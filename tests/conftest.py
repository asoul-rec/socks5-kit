"""Keep loopback checks runnable while reporting restricted hosts explicitly."""

import errno
import socket

import pytest


@pytest.fixture(autouse=True)
def require_tcp_when_marked(request):
    if request.node.get_closest_marker("tcp_loopback") is None:
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            probe.bind(("127.0.0.1", 0))
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES):
            raise
        pytest.skip(f"environment forbids TCP socket operations: {exc}")
