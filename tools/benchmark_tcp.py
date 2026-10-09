"""Local TCP throughput/CPU benchmark with isolated relay and traffic processes.

Run: uv run python tools/benchmark_tcp.py --output-dir PATH
Only loopback is used. No production defaults or runtime dependencies are changed.
"""

import argparse
import asyncio
import json
import math
import os
import platform
import random
import resource
import socket
import statistics
import struct
import sys
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from socks5_kit import ServerOptions, Socks5Client, Socks5RewriteServer, Target
from socks5_kit._io import negotiate_server, read_exact, read_request
from socks5_kit.protocol import encode_reply

HEADER = struct.Struct("!ddB")
TRAILER = struct.Struct("!QQ")
MODES = {"upload": 0, "download": 1, "duplex": 2}
BLOCK_SIZE = 65536
UPLOAD = b"U" * BLOCK_SIZE
DOWNLOAD = b"D" * BLOCK_SIZE
SCRIPT_PATH = str(Path(__file__).resolve())


def usage():
    stats = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "user_seconds": stats.ru_utime,
        "system_seconds": stats.ru_stime,
        "voluntary_switches": stats.ru_nvcsw,
        "involuntary_switches": stats.ru_nivcsw,
        "max_rss_kib": stats.ru_maxrss,
        "fds": len(os.listdir("/proc/self/fd")),
    }


def cpu_delta(end, start):
    return (
        end["user_seconds"]
        - start["user_seconds"]
        + end["system_seconds"]
        - start["system_seconds"]
    )


def emit(value):
    print(json.dumps(value), flush=True)


class LagMonitor:
    def __init__(self, loop, period=0.005):
        self.loop = loop
        self.period = period
        self.samples = []
        self.handle = None

    def start(self):
        self.schedule(self.loop.time() + self.period)

    def schedule(self, deadline):
        self.handle = self.loop.call_at(deadline, self.tick, deadline)

    def tick(self, deadline):
        now = self.loop.time()
        lag = max(0, now - deadline)
        self.samples.append(lag * 1000)
        skipped = math.floor(lag / self.period)
        self.schedule(deadline + (skipped + 1) * self.period)

    def stop(self):
        if self.handle is not None:
            self.handle.cancel()
        values = sorted(self.samples)
        return {
            "lag_samples": len(values),
            "lag_p50_ms": statistics.median(values) if values else None,
            "lag_p99_ms": values[
                min(len(values) - 1, math.ceil(len(values) * 0.99) - 1)
            ]
            if values
            else None,
            "lag_max_ms": max(values) if values else None,
        }


class CopyRelay:
    """Same raw sockets/lifecycle, with recv/sendall and 64 KiB Python buffers."""

    def __init__(self, left, right, *, byte_budget, call_budget):
        self.left, self.right = left, right
        self.loop = asyncio.get_running_loop()
        self.byte_budget = byte_budget
        self.call_budget = call_budget

    async def run(self):
        async def copy(source, sink):
            moved = calls = 0
            while data := await self.loop.sock_recv(source, BLOCK_SIZE):
                await self.loop.sock_sendall(sink, data)
                moved += 2 * len(data)
                calls += 2
                if moved >= self.byte_budget or calls >= self.call_budget:
                    moved = calls = 0
                    await asyncio.sleep(0)
            sink.shutdown(socket.SHUT_WR)

        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(copy(self.left, self.right))
            tasks.create_task(copy(self.right, self.left))

    def close(self):
        pass  # The server owns sockets; TaskGroup owns both copy coroutines.


class Peer:
    """A controlled no-auth SOCKS upstream producing/consuming benchmark bytes."""

    def __init__(self):
        self.loop = asyncio.get_running_loop()
        self.tasks = set()
        self.errors = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.setblocking(False)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(256)
        self.port = self.listener.getsockname()[1]
        self.accept_task = self.loop.create_task(self.accept())

    async def accept(self):
        while True:
            sock, _peer = await self.loop.sock_accept(self.listener)
            sock.setblocking(False)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            task = self.loop.create_task(self.handle(sock))
            self.tasks.add(task)
            task.add_done_callback(
                lambda done, accepted=sock: self.done(done, accepted)
            )

    def done(self, task, sock):
        sock.close()
        self.tasks.discard(task)
        if not task.cancelled() and (error := task.exception()) is not None:
            self.errors.append(repr(error))

    async def handle(self, sock):
        try:
            if not await negotiate_server(sock):
                return
            command, _target = await read_request(sock)
            assert command == 1
            await self.loop.sock_sendall(sock, encode_reply(0))
            start, deadline, mode = HEADER.unpack(await read_exact(sock, HEADER.size))
            await asyncio.sleep(max(0, start - time.monotonic()))

            async def source():
                total = 0
                if mode != MODES["upload"]:
                    while time.monotonic() < deadline:
                        await self.loop.sock_sendall(sock, DOWNLOAD)
                        total += len(DOWNLOAD)
                        if total % (1024 * 1024) == 0:
                            await asyncio.sleep(0)
                return total

            async def sink():
                total = 0
                while data := await self.loop.sock_recv(sock, 262144):
                    assert data[:64] == b"U" * min(64, len(data))
                    assert data[-64:] == b"U" * min(64, len(data))
                    total += len(data)
                    if total % (1024 * 1024) < len(data):
                        await asyncio.sleep(0)
                return total

            async with asyncio.TaskGroup() as tasks:
                sending = tasks.create_task(source())
                receiving = tasks.create_task(sink())
            await self.loop.sock_sendall(
                sock, TRAILER.pack(receiving.result(), sending.result())
            )
            sock.shutdown(socket.SHUT_WR)
        finally:
            sock.close()

    async def idle(self):
        if self.tasks:
            await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
        await asyncio.sleep(0)
        if self.errors:
            raise RuntimeError(self.errors)

    async def close(self):
        self.accept_task.cancel()
        await asyncio.gather(self.accept_task, return_exceptions=True)
        self.listener.close()
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)


async def service(arguments):
    if arguments.cpu is not None:
        os.sched_setaffinity(0, {arguments.cpu})
    loop = asyncio.get_running_loop()
    monitor = None
    begin = None
    baseline = None
    started = None
    armed = None
    owner = None

    if arguments.role == "peer":
        owner = Peer()
        port = owner.port
    else:
        if arguments.backend == "copy":
            import socks5_kit.server as server_module

            server_module.SpliceRelay = CopyRelay
        owner = Socks5RewriteServer(
            lambda _t, _c: Target("benchmark.invalid", 1),
            "127.0.0.1",
            arguments.upstream_port,
            options=ServerOptions(max_connections=256),
        )
        await owner.start(port=0)
        port = owner.address[1]
    emit({"port": port, "pid": os.getpid(), "cpu": arguments.cpu})

    def begin_measurement():
        nonlocal begin, baseline, started, monitor
        baseline = usage()
        started = time.monotonic()
        monitor = LagMonitor(loop)
        monitor.start()
        begin.set()

    try:
        while line := await asyncio.to_thread(sys.stdin.readline):
            request = json.loads(line)
            match request["command"]:
                case "snapshot":
                    emit(usage())
                case "arm":
                    begin = asyncio.Event()
                    armed = loop.call_later(
                        max(0, request["start"] - time.monotonic()), begin_measurement
                    )
                    emit({"armed": True})
                case "end":
                    await begin.wait()
                    await asyncio.gather(
                        *tuple(owner._sessions), return_exceptions=True
                    )
                    await asyncio.sleep(0)
                    ended = usage()
                    result = {
                        "wall_seconds": time.monotonic() - started,
                        "cpu_seconds": cpu_delta(ended, baseline),
                        "user_seconds": ended["user_seconds"]
                        - baseline["user_seconds"],
                        "system_seconds": ended["system_seconds"]
                        - baseline["system_seconds"],
                        "voluntary_switches": ended["voluntary_switches"]
                        - baseline["voluntary_switches"],
                        "involuntary_switches": ended["involuntary_switches"]
                        - baseline["involuntary_switches"],
                        "max_rss_kib": ended["max_rss_kib"],
                        "active_sessions_after": owner.active_connections,
                        "fds_after": ended["fds"],
                        **monitor.stop(),
                    }
                    emit(result)
                case "idle":
                    await owner.idle()
                    emit({"idle": True})
                case "stop":
                    emit({"stopping": True})
                    break
    finally:
        if armed is not None:
            armed.cancel()
        if monitor is not None:
            monitor.stop()
        if arguments.role == "peer":
            await owner.close()
        else:
            await owner.aclose()


class Child:
    def __init__(self, process, ready):
        self.process, self.ready = process, ready

    @classmethod
    async def start(cls, arguments, log_path):
        with log_path.open("wb") as log:
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-u",
                SCRIPT_PATH,
                *arguments,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=log,
            )
        child = cls(process, None)
        try:
            async with asyncio.timeout(10):
                line = await process.stdout.readline()
                if not line:
                    raise RuntimeError(f"child failed; inspect {log_path}")
                child.ready = json.loads(line)
            return child
        except BaseException:
            await child.close()
            raise

    async def command(self, name, **values):
        self.process.stdin.write(
            (json.dumps({"command": name, **values}) + "\n").encode()
        )
        await self.process.stdin.drain()
        line = await self.process.stdout.readline()
        if not line:
            raise RuntimeError("benchmark child exited unexpectedly")
        return json.loads(line)

    async def close(self):
        if self.process.returncode is not None:
            return
        self.process.stdin.close()
        try:
            async with asyncio.timeout(5):
                await self.process.wait()
        except TimeoutError:
            self.process.kill()
            await self.process.wait()


async def flow(tunnel, start, deadline, mode):
    loop = asyncio.get_running_loop()
    sock = tunnel.socket
    await loop.sock_sendall(sock, HEADER.pack(start, deadline, mode))
    await asyncio.sleep(max(0, start - time.monotonic()))

    async def send():
        total = 0
        if mode != MODES["download"]:
            while time.monotonic() < deadline:
                await loop.sock_sendall(sock, UPLOAD)
                total += len(UPLOAD)
                if total % (1024 * 1024) == 0:
                    await asyncio.sleep(0)
        sock.shutdown(socket.SHUT_WR)
        return total

    async def receive():
        total = 0
        tail = b""
        while data := await loop.sock_recv(sock, 262144):
            combined = tail + data
            if len(combined) > TRAILER.size:
                payload, tail = combined[: -TRAILER.size], combined[-TRAILER.size :]
                assert payload[:64] == b"D" * min(64, len(payload))
                assert payload[-64:] == b"D" * min(64, len(payload))
                total += len(payload)
                if total % (1024 * 1024) < len(payload):
                    await asyncio.sleep(0)
            else:
                tail = combined
        assert len(tail) == TRAILER.size, "missing upstream counters"
        uploaded, downloaded = TRAILER.unpack(tail)
        assert downloaded == total
        return uploaded, downloaded

    try:
        async with asyncio.TaskGroup() as tasks:
            sending = tasks.create_task(send())
            receiving = tasks.create_task(receive())
        uploaded, downloaded = receiving.result()
        assert uploaded == sending.result()
        return uploaded, downloaded
    finally:
        tunnel.close()


async def transfer(endpoint, connections, seconds, direction, worker=None):
    client = Socks5Client("127.0.0.1", endpoint)
    tunnels = []
    try:
        tunnels = await asyncio.gather(
            *(client.connect(Target("original.invalid", 1)) for _ in range(connections))
        )
        start = time.monotonic() + 0.15
        deadline = start + seconds
        jobs = [
            asyncio.create_task(flow(t, start, deadline, MODES[direction]))
            for t in tunnels
        ]
        if worker is not None:
            await worker.command("arm", start=start)
        driver_before = usage()
        amounts = await asyncio.gather(*jobs)
        ended = time.monotonic()
        driver_after = usage()
        metrics = (
            await worker.command("end")
            if worker
            else {
                "wall_seconds": ended - start,
                "cpu_seconds": 0,
            }
        )
        metrics.update(
            upload_bytes=sum(x[0] for x in amounts),
            download_bytes=sum(x[1] for x in amounts),
            driver_cpu_seconds=cpu_delta(driver_after, driver_before),
        )
        return metrics
    finally:
        for tunnel in tunnels:
            tunnel.close()


def environment(affinity):
    cpu_model = next(
        (
            line.split(":", 1)[1].strip()
            for line in Path("/proc/cpuinfo").read_text().splitlines()
            if line.startswith("model name")
        ),
        "unknown",
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        buffers = {
            "send": sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
            "receive": sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
        }
    read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        import fcntl

        pipe_capacity = fcntl.fcntl(read_fd, fcntl.F_GETPIPE_SZ)
    finally:
        os.close(read_fd)
        os.close(write_fd)
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "cpu": cpu_model,
        "available_cpus": affinity,
        "loop": type(asyncio.get_running_loop()).__name__,
        "copy_block_bytes": BLOCK_SIZE,
        "pipe_capacity_bytes": pipe_capacity,
        "default_socket_buffers_bytes": buffers,
        "splice_byte_budget": 262144,
        "splice_call_budget": 8,
        "lag_timer_ms": 5,
        "payload_validation": (
            "byte counters plus first/last 64 bytes per received chunk"
        ),
        "baseline_fairness": "same byte/call budgets; 64 KiB recv/sendall",
        "started_at": datetime.now(ZoneInfo("America/Chicago")).isoformat(),
        "loadavg_before": os.getloadavg(),
    }


async def benchmark(arguments):
    affinity = sorted(os.sched_getaffinity(0))
    env = environment(affinity)
    worker_cpu, peer_cpu, driver_cpu = (affinity + affinity * 2)[:3]
    env["cpu_assignments"] = {
        "relay": worker_cpu,
        "peer": peer_cpu,
        "driver": driver_cpu,
    }
    os.sched_setaffinity(0, {driver_cpu})
    output = arguments.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    config = {
        "seconds": arguments.seconds,
        "warmup_seconds": 0.25,
        "repeats": arguments.repeats,
        "concurrency": arguments.concurrency,
        "directions": arguments.directions,
        "seed": 20261007,
    }
    results = []
    peer = await Child.start(
        ["--role", "peer", "--cpu", str(peer_cpu)], output / "peer.log"
    )
    plan = [
        (backend, direction, connections, repetition)
        for repetition in range(arguments.repeats)
        for direction in arguments.directions
        for connections in arguments.concurrency
        for backend in ["direct", "splice", "copy"]
    ]
    random.Random(config["seed"]).shuffle(plan)
    try:
        for index, (backend, direction, connections, repetition) in enumerate(plan):
            worker = None
            endpoint = peer.ready["port"]
            if backend != "direct":
                worker = await Child.start(
                    [
                        "--role",
                        "relay",
                        "--backend",
                        backend,
                        "--cpu",
                        str(worker_cpu),
                        "--upstream-port",
                        str(endpoint),
                    ],
                    output / f"relay-{index}.log",
                )
                endpoint = worker.ready["port"]
            try:
                async with asyncio.timeout(max(30, arguments.seconds * 4)):
                    await transfer(endpoint, connections, 0.25, direction, worker)
                    await peer.command("idle")
                    peer_before = await peer.command("snapshot")
                    row = await transfer(
                        endpoint, connections, arguments.seconds, direction, worker
                    )
                    await peer.command("idle")
                    peer_after = await peer.command("snapshot")
                    row.update(
                        backend=backend,
                        direction=direction,
                        connections=connections,
                        repetition=repetition,
                        peer_cpu_seconds=cpu_delta(peer_after, peer_before),
                    )
                    total = row["upload_bytes"] + row["download_bytes"]
                    row["gbit_per_second"] = total * 8 / row["wall_seconds"] / 1e9
                    row["mib_per_second"] = total / row["wall_seconds"] / 1048576
                    row["relay_cpu_percent"] = (
                        row["cpu_seconds"] / row["wall_seconds"] * 100
                    )
                    row["relay_cpu_seconds_per_gib"] = row["cpu_seconds"] / (
                        total / 1073741824
                    )
                    results.append(row)
                    (output / "results.json").write_text(
                        json.dumps(
                            {"environment": env, "config": config, "samples": results},
                            indent=2,
                        )
                        + "\n"
                    )
                    emit({"progress": f"{index + 1}/{len(plan)}", **row})
            finally:
                if worker:
                    await worker.close()
    finally:
        await peer.close()
        os.sched_setaffinity(0, affinity)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--seconds", type=float, default=2)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 8, 32])
    parser.add_argument(
        "--directions", choices=list(MODES), nargs="+", default=list(MODES)
    )
    parser.add_argument("--role", choices=["relay", "peer"])
    parser.add_argument("--backend", choices=["splice", "copy"])
    parser.add_argument("--upstream-port", type=int)
    parser.add_argument("--cpu", type=int)
    arguments = parser.parse_args()
    if arguments.role:
        asyncio.run(service(arguments))
    else:
        if arguments.output_dir is None:
            parser.error("--output-dir is required")
        if (
            not math.isfinite(arguments.seconds)
            or arguments.seconds <= 0
            or arguments.repeats <= 0
            or any(c <= 0 or c > 128 for c in arguments.concurrency)
        ):
            parser.error("positive duration/repeats and concurrency in 1..128 required")
        asyncio.run(benchmark(arguments))
