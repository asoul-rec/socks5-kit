"""Real Linux socketpair -> pipe -> socketpair I/O; simulated write EOF.

Real TCP half-close is covered separately by the loopback integration tests.
"""

import asyncio
import errno
import os
import socket

import pytest

from socks5_kit._linux.splice import SpliceRelay

from .local_io import local_pair, recv, run, sendall


def test_real_splice_partial_io_eagain_and_delayed_reverse(monkeypatch):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        with local_pair() as (left, sender), local_pair() as (right, responder):
            forward = b"forward\x00\xff" * 65536
            reverse = b"reverse\x00\xff" * 65536
            expected = {left.fileno(): len(forward), right.fileno(): len(reverse)}
            read_counts = dict.fromkeys(expected, 0)
            write_counts = dict.fromkeys(expected, 0)
            original_splice = os.splice
            injected = set()
            calls = 0

            def partial_splice(src, dst, count, **kwargs):
                nonlocal calls
                calls += 1
                reading = src in expected
                phase = "read" if reading else "write"
                if phase not in injected:
                    injected.add(phase)
                    raise BlockingIOError(errno.EAGAIN, "injected readiness race")
                if reading and read_counts[src] == expected[src]:
                    return 0  # Deterministic peer write EOF, without shutdown syscall.
                result = original_splice(src, dst, min(count, 257), **kwargs)
                counts, fd = (read_counts, src) if reading else (write_counts, dst)
                counts[fd] += result
                return result

            class Endpoint:
                def __init__(self, sock, total):
                    self.sock = sock
                    self.total = total
                    self.eof = asyncio.Event()
                    self.shutdown_calls = 0

                def fileno(self):
                    return self.sock.fileno()

                def shutdown(self, how):
                    assert how == socket.SHUT_WR
                    assert write_counts[self.fileno()] == self.total
                    self.shutdown_calls += 1
                    self.eof.set()

            left_endpoint = Endpoint(left, len(reverse))
            right_endpoint = Endpoint(right, len(forward))
            monkeypatch.setattr(os, "splice", partial_splice)

            async def receive(sock, count, *, slow=False):
                data = bytearray()
                while len(data) < count:
                    chunk = await recv(sock, min(4096, count - len(data)))
                    assert chunk
                    data.extend(chunk)
                    if slow:
                        await asyncio.sleep(0.0001)
                return bytes(data)

            async def client_side():
                await sendall(sender, forward)
                assert await receive(sender, len(reverse)) == reverse
                await left_endpoint.eof.wait()

            async def remote_side():
                assert await receive(responder, len(forward), slow=True) == forward
                await right_endpoint.eof.wait()
                await sendall(responder, reverse)

            relay = SpliceRelay(
                left_endpoint, right_endpoint, byte_budget=4096, call_budget=3
            )
            try:
                async with asyncio.TaskGroup() as group:
                    group.create_task(relay.run())
                    group.create_task(client_side())
                    group.create_task(remote_side())
                assert injected == {"read", "write"} and calls > 100
                assert (
                    left_endpoint.shutdown_calls == right_endpoint.shutdown_calls == 1
                )
            finally:
                relay.close()
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


@pytest.mark.parametrize("failure", ["cancel", "splice", "second_pipe"])
def test_splice_cleanup_on_cancellation_and_failure(monkeypatch, failure):
    async def scenario():
        baseline = len(os.listdir("/proc/self/fd"))
        with local_pair() as (left, _sender), local_pair() as (right, _responder):
            if failure == "second_pipe":
                original = os.pipe2
                calls = 0

                def allocate(flags):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise OSError(errno.EMFILE, "injected pipe failure")
                    return original(flags)

                monkeypatch.setattr(os, "pipe2", allocate)
                with pytest.raises(OSError, match="injected pipe failure"):
                    SpliceRelay(left, right)
            else:
                if failure == "splice":

                    def broken(*_args, **_kwargs):
                        raise OSError(errno.EIO, "injected splice failure")

                    monkeypatch.setattr(os, "splice", broken)
                relay = SpliceRelay(left, right)
                task = asyncio.create_task(relay.run())
                try:
                    if failure == "cancel":
                        await asyncio.sleep(0)
                        await asyncio.sleep(0)  # Let both reader watchers register.
                        task.cancel()
                        with pytest.raises(asyncio.CancelledError):
                            await task
                    else:
                        with pytest.raises(OSError, match="injected splice failure"):
                            await task
                    assert all(d.closed for d in relay._directions)
                    assert not any(d._reading or d._writing for d in relay._directions)
                finally:
                    relay.close()
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)


@pytest.mark.tcp_loopback
def test_real_kernel_eof_half_close_and_backpressure(monkeypatch):
    async def scenario():
        loop = asyncio.get_running_loop()
        baseline = len(os.listdir("/proc/self/fd"))
        with local_pair() as (left, sender), local_pair() as (right, responder):
            for sock in (left, sender, right, responder):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            source_fds = {left.fileno(), right.fileno()}
            original = os.splice
            injected = set()
            natural_eagain = set()
            eof_fds = set()
            counts = {"read": 0, "write": 0}

            def partial(src, dst, count, **kwargs):
                phase = "read" if src in source_fds else "write"
                if phase not in injected:
                    injected.add(phase)
                    raise BlockingIOError(errno.EAGAIN, "injected readiness race")
                try:
                    result = original(src, dst, min(count, 257), **kwargs)
                except BlockingIOError:
                    natural_eagain.add(phase)
                    raise
                counts[phase] += result
                if src in source_fds and result == 0:
                    eof_fds.add(src)
                return result

            monkeypatch.setattr(os, "splice", partial)
            forward = bytes(range(256)) * 4096
            reverse = b"reply after receiving real EOF\x00\xff" * 16384

            async def receive(sock, *, slow=False):
                result = bytearray()
                while data := await loop.sock_recv(sock, 4096):
                    result.extend(data)
                    if slow:
                        await asyncio.sleep(0.001)
                return bytes(result)

            async def client_side():
                await loop.sock_sendall(sender, forward)
                sender.shutdown(socket.SHUT_WR)
                assert await receive(sender) == reverse

            async def remote_side():
                # A slow reader and tiny socket buffers produce real write EAGAIN.
                assert await receive(responder, slow=True) == forward
                await loop.sock_sendall(responder, reverse)
                responder.shutdown(socket.SHUT_WR)

            relay = SpliceRelay(left, right, byte_budget=4096, call_budget=3)
            try:
                async with asyncio.TaskGroup() as group:
                    group.create_task(relay.run())
                    group.create_task(client_side())
                    group.create_task(remote_side())
                assert injected == natural_eagain == {"read", "write"}
                assert eof_fds == source_fds
                assert counts["read"] == counts["write"] == len(forward) + len(reverse)
            finally:
                relay.close()
        assert len(os.listdir("/proc/self/fd")) == baseline

    run(scenario)
