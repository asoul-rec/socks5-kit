"""Run local TCP integration with independently supplied official proxy binaries.

Usage: uv run python tools/check_interop.py --bin-dir PATH --output-dir PATH
No binaries are downloaded by this tool. All test traffic stays on loopback.
"""

import argparse
import asyncio
import json
import socket
from contextlib import asynccontextmanager, suppress
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from socks5_kit import Socks5Client, Socks5RewriteServer, Target


def unused_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def wait_ready(process, port):
    async with asyncio.timeout(10):
        while True:
            if process.returncode is not None:
                raise RuntimeError(
                    f"proxy exited before listening: {process.returncode}"
                )
            try:
                _reader, writer = await asyncio.open_connection("127.0.0.1", port)
            except ConnectionRefusedError:
                await asyncio.sleep(0.025)
            else:
                writer.close()
                await writer.wait_closed()
                return


@asynccontextmanager
async def proxy(name, binaries, output):
    port = unused_port()
    processes = []

    async def launch(binary, arguments, listen_port):
        log_path = output / f"{binary}.log"
        with log_path.open("wb") as log:
            process = await asyncio.create_subprocess_exec(
                str(binaries / binary),
                *arguments,
                stdout=log,
                stderr=asyncio.subprocess.STDOUT,
            )
        processes.append(process)
        try:
            await wait_ready(process, listen_port)
        except Exception as exc:
            raise RuntimeError(f"{binary} startup failed; inspect {log_path}") from exc

    try:
        if name in ("xray", "v2ray"):
            config = {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {
                        "listen": "127.0.0.1",
                        "port": port,
                        "protocol": "socks",
                        "settings": {"auth": "noauth", "udp": False},
                    }
                ],
                "outbounds": [{"protocol": "freedom", "settings": {}}],
            }
            config_path = output / f"{name}.json"
            config_path.write_text(json.dumps(config, indent=2) + "\n")
            await launch(name, ["run", "-c", str(config_path)], port)
        else:
            encrypted_port = unused_port()
            common = [
                "-s",
                f"127.0.0.1:{encrypted_port}",
                "-k",
                "local-interop-test-password",
                "-m",
                "chacha20-ietf-poly1305",
            ]
            await launch("ssserver", common, encrypted_port)
            await launch("sslocal", [*common, "-b", f"127.0.0.1:{port}"], port)
        yield port
    finally:
        for process in processes:
            if process.returncode is None:
                process.terminate()
        try:
            async with asyncio.timeout(5):
                await asyncio.gather(*(process.wait() for process in processes))
        except TimeoutError:
            for process in processes:
                if process.returncode is None:
                    process.kill()
            await asyncio.gather(*(process.wait() for process in processes))


@asynccontextmanager
async def echo_server():
    tasks, writers, errors = set(), set(), []

    async def handle(reader, writer):
        try:
            header = await reader.readexactly(5)
            half_close = bool(header[0])
            size = int.from_bytes(header[1:])
            assert size <= 4 * 1024 * 1024
            data = await reader.readexactly(size)
            if half_close:
                assert await reader.read() == b""
            writer.write(data)
            await writer.drain()
        except asyncio.IncompleteReadError, ConnectionError:
            pass
        except Exception as exc:
            errors.append(repr(exc))
        finally:
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()
            writers.discard(writer)

    def accept(reader, writer):
        writers.add(writer)
        task = asyncio.create_task(handle(reader, writer))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        listener.setblocking(False)
        listener.bind(("::", 0))
        listener.listen(128)
        server = await asyncio.start_server(accept, sock=listener)
    except BaseException:
        listener.close()
        raise
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()
        for writer in tuple(writers):
            writer.close()
        for task in tuple(tasks):
            task.cancel()
        await asyncio.gather(*tuple(tasks), return_exceptions=True)
    assert not errors, errors


async def check_case(endpoint, target, *, half_close):
    payload = bytes(range(256)) * 4096
    async with asyncio.timeout(5):
        async with await Socks5Client(*endpoint).connect(target) as tunnel:
            await tunnel.sendall(
                bytes([half_close]) + len(payload).to_bytes(4) + payload
            )
            if half_close:
                tunnel.shutdown_write()
            received = bytearray()
            while data := await tunnel.recv():
                received.extend(data)
            assert received == payload, (len(received), len(payload))
            bound = tunnel.bound_address
            return {
                "type": bound.kind.name,
                "host": str(bound.host),
                "port": bound.port,
            }


async def main(binaries, output):
    output.mkdir(parents=True, exist_ok=True)
    for name in ("xray", "v2ray", "sslocal", "ssserver"):
        if not (binaries / name).is_file():
            raise FileNotFoundError(binaries / name)
    results = []
    originals = [
        Target(IPv4Address("192.0.2.10"), 9000),
        Target(IPv6Address("2001:db8::10"), 9000),
        Target("original.example", 9000),
    ]
    async with echo_server() as echo_port:
        for name in ("xray", "v2ray", "shadowsocks-rust"):
            async with proxy(name, binaries, output) as upstream_port:
                # Check EOF-triggered responses directly as well as through M.
                baseline = {
                    "proxy": name,
                    "path": "direct",
                    "original_type": "DOMAIN",
                    "half_close": True,
                    "payload_bytes": 1048576,
                }
                try:
                    baseline["bound"] = await check_case(
                        ("127.0.0.1", upstream_port),
                        Target("localhost", echo_port),
                        half_close=True,
                    )
                except Exception as exc:
                    baseline.update(status="FAIL", error=repr(exc))
                else:
                    baseline["status"] = "PASS"
                results.append(baseline)
                print(json.dumps(baseline), flush=True)
                callbacks = []

                def rewrite(target, context, *, calls=callbacks):
                    calls.append((target, context))
                    return Target("localhost", echo_port)

                async with Socks5RewriteServer(
                    rewrite, "127.0.0.1", upstream_port
                ) as server:
                    await server.start(port=0)
                    for half_close in (False, True):
                        for target in originals:
                            result = {
                                "proxy": name,
                                "path": "relay",
                                "original_type": target.kind.name,
                                "half_close": half_close,
                                "payload_bytes": 1048576,
                            }
                            try:
                                result["bound"] = await check_case(
                                    server.address, target, half_close=half_close
                                )
                            except Exception as exc:
                                result.update(status="FAIL", error=repr(exc))
                                if half_close and baseline["status"] == "FAIL":
                                    result["direct_baseline"] = "FAIL"
                            else:
                                result["status"] = "PASS"
                            results.append(result)
                            print(json.dumps(result), flush=True)
                    assert len(callbacks) == 6
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    if any(result["status"] != "PASS" for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()
    asyncio.run(main(arguments.bin_dir.resolve(), arguments.output_dir.resolve()))
