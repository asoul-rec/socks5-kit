"""Exercise reverse TCP through independently supplied Xray and V2Fly binaries.

Usage: uv run python tools/check_reverse_interop.py --bin-dir PATH --output-dir PATH
No downloads or dependencies; all listeners and destinations stay on loopback.
The default carrier is encrypted VLESS/TLS with an embedded test-only identity
trusted explicitly by each local client; no external certificate tool is needed.
--carrier vmess, vless, or shadowsocks reproduces alternative carrier checks.
--default-policy leaves both proxies' timeout policy at their built-in defaults.
The optional half-close probe records a limitation without failing ordinary tests.
"""

import argparse
import asyncio
import json
import logging
import socket
import sys
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from socks5_kit import BoundAddress, Socks5Client, Target, TcpTunnel
from socks5_kit._io import read_exact, read_reply
from socks5_kit.protocol import encode_connect
from socks5_kit.reverse import (
    DEFAULT_REVERSE_DOMAIN,
    ReverseAgent,
    ReverseAgentOptions,
    ReverseServer,
)
from socks5_kit.reverse._common import REGISTRATION_ACK, REGISTRATION_HELLO

USERNAME = b"reverse-test"
VMESS_ID = "ee55aa11-1234-4cde-8abc-9876543210ab"
PAYLOAD = bytes(range(256)) * 4096
RESPONSE = PAYLOAD[::-1]
GREETING = b"reverse-interop: target speaks first\x00\xff"
POLICY = {
    "levels": {
        "0": {"handshake": 10, "connIdle": 300, "uplinkOnly": 10, "downlinkOnly": 10}
    }
}
CARRIERS = {
    "vmess": "VMess AES-128-GCM over TCP, no multiplexing",
    "vless": "VLESS over plain TCP, encryption/decryption none, no multiplexing",
    "vless-tls": "VLESS over TLS with a test-only self-signed certificate",
    "shadowsocks": "Shadowsocks chacha20-ietf-poly1305 over TCP",
}


# Public test-only identity. Never use this private key for an actual service.
TEST_TLS_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUc5jQszzpMzMp78GQ7eL10aNLvGUwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAxMTE4NDg0MloXDTM2MTAw
ODE4NDg0MlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAjig47GwnOFcv4QA+oP+9i6frlUIWX3FNglaKpCUbYgEY
DH6ZaIEjfbX1vDGTr5ARCBOk1Fn2LiZ3EwnStPcyZN7tYW/SWSFJvkUflOHa+qlW
w1cM16mWvSK5NdCoomG2h9cfD2w/FzC2NVS5r8ikfVaXaVTgA0CzBYiUwYL//Vhw
9Fm/JGtlG+a5OjcAXdaJ3LaWRzGeYdBHcKwpwx9MptwlG9nPaXwixcOvEG3rTO55
j/SoUA/KPwYqZhz/3arZVyCBEetwZu9qIDSG7+3qa2VFXHRan2/LF7K0mItesa5Q
Amiaxog9uiS0FXDjpcWR8/UBCEu8ta0IrJGQaYBACwIDAQABo28wbTAdBgNVHQ4E
FgQU86mjyJAfzRqyHX11rQhQd0fcnA8wHwYDVR0jBBgwFoAU86mjyJAfzRqyHX11
rQhQd0fcnA8wDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAHUmI6BrVfKxODCITIrOEJRFhImlB/BE
SBgavMQI/t+XasAmudPiwWTT63fa8MoNEJHXwW3kMgtsPCLfwPLLojZ5qcp+6NQg
T0CxO1v6R4Ag1J5E6yai/QEkEyxcW3jdi7SWkQU9fm75/9oJ5Fpb4g1acgGXyfSg
P3iEt7S1TaXMgBR47UrD8Uf2mgZ9bcUmKm5rav/lfZVwAhJi/yvB00tEiS2Ww9Yt
DgqI0sfeQr/Ny5ejyiGI7flcsiPCnDkOpmEoU3wK00D2oWr7QTWGC+2y6tR1jY1q
A7Aki8G1lluB6O/tmyVRlrNCdwkRz4kZ1T5sdosnMcrvh8bkfdoAcxA=
-----END CERTIFICATE-----
"""
TEST_TLS_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCOKDjsbCc4Vy/h
AD6g/72Lp+uVQhZfcU2CVoqkJRtiARgMfplogSN9tfW8MZOvkBEIE6TUWfYuJncT
CdK09zJk3u1hb9JZIUm+RR+U4dr6qVbDVwzXqZa9Irk10KiiYbaH1x8PbD8XMLY1
VLmvyKR9VpdpVOADQLMFiJTBgv/9WHD0Wb8ka2Ub5rk6NwBd1onctpZHMZ5h0Edw
rCnDH0ym3CUb2c9pfCLFw68QbetM7nmP9KhQD8o/BipmHP/dqtlXIIER63Bm72og
NIbv7eprZUVcdFqfb8sXsrSYi16xrlACaJrGiD26JLQVcOOlxZHz9QEIS7y1rQis
kZBpgEALAgMBAAECggEAA5Qj+WEFobz20cQRpOLwm3NC59Mt61bXsS11jbP4xar/
tyd5ZttCu0zuiT95l3oEe768L7OuEgkE3Aqrbm5/VcZo6m2IDuywGw/0FL7qJipH
gAu7y91ok+KrupzsnzM03E7q6MFRsJyY0ayML3kubuX+/MysBljwHiELQaMxx5Jo
oOGZRyP2bWMSdUh0pInDTiR3/9XXnGxlzcAA3YfguX072Faq+yXf7AgBTWHBFS3G
WaOCkA4zclbpWF/Q7j6fP0j0R1QFfb7c4FM6sFfSNIXvWjOMFRSPdkv0ilW50Lud
Boz0Exm0b+FRoE2q7NrL1xJMSbzqcpqbVSGaslsQkQKBgQDChXEjRZoO9okyAYOe
oewu0Zs4Jk/aVlRqyE2tecn7jKLb2Zonmh8RyZXT6Db/mNg/WBeIv+/e+hpo6EqX
zS9LfQF+2uLG85jLLpzBo2hax3rJZE2PvWCl4y00+FP3woZqhpvfppMlkqluD+Kh
BMPLvBImPaqABBuc2XCN/M+RUQKBgQC7FgpIBGHxGo4yeJC9Qf6aeEAYLa6RpuHm
ngC4gwsos7dpPOS0LKQzHE9fRgyx42IZhGijmaBlqfuN4UJP88tc7+QPpRQRoTaC
Gu20jjUmsaBip+t5gQF76gCY5iEwmzISTSzdC98h5AWNZ877MmPch/uS6uy5FTqJ
lHOB7S4EmwKBgAsbT3ByIu/Dx+WhDIDcQf4SXciA94JB96P5N+Y11ACW8R2YeSLV
u/xqBDILSkih04caYo2eV/XlVeizir7MKm0nABTcLqKpegnv6WdtCyJTzYD+Rydz
6rbOF+C0ZSb6Zm5irTfB7RjyHNZ59bi36u4RGQAx+TBCC8mS6MhSrQ9hAoGANg2V
JN+XSKjqgqyQ7Q1/OTQbGKFCObTkudPW03iRJc5e5JoCXggz3MyGJjm/+zl+I289
KF9/lz/4fTKjDSScEhsBYn/If5t7ezW6jhs0Qhy6AScRAscCHcIrMAH1fuyoF9+S
Yb9HVaxi6kse4zbY4WOsjPMxN/xpMEzi3pwfWpcCgYAqK8333Q0QLb5CfRCw7pXo
ojMav+00+hTEbbu9xsJ+BBd53QS5FziLYzrH8pT9Vd/Ou86/62kDKrGxYVHlyr3k
efWqCbFbmZ+Qy0yuoBaAMET+cEykJmzogGB+QEIV1vWbZxLaNu0uqqcMG3fBGt5b
/IyeR40MgfqaKw1shiuTIw==
-----END PRIVATE KEY-----
"""


def address_record(address):
    return {
        "type": address.kind.name,
        "host": str(address.host),
        "port": address.port,
    }


def unused_ports(count):
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(sock)
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


async def wait_ready(process, port):
    async with asyncio.timeout(10):
        while True:
            if process.returncode is not None:
                raise RuntimeError(f"proxy exited: {process.returncode}")
            try:
                _reader, writer = await asyncio.open_connection("127.0.0.1", port)
            except ConnectionRefusedError:
                await asyncio.sleep(0.025)
            else:
                writer.close()
                await writer.wait_closed()
                return


async def wait_pool(server, agent, count=2):
    started = asyncio.get_running_loop().time()
    async with asyncio.timeout(10):
        while True:
            if server.idle_count(USERNAME) >= count and agent.idle_connections >= count:
                return asyncio.get_running_loop().time() - started
            await asyncio.sleep(0.01)


def socks_inbound(port, tag):
    return {
        "tag": tag,
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    }


@asynccontextmanager
async def proxies(
    name,
    binaries,
    output,
    reverse_address,
    *,
    debug=False,
    carrier="vmess",
    default_policy=False,
):
    """P_C uses the chosen carrier for registrations and Freedom for targets.

    P_S sends both carrier registrations and ordinary SOCKS business requests
    to ReverseServer using the same raw SOCKS username.
    """
    client_port, carrier_port, business_port = unused_ports(3)
    client_config = {
        "log": {"loglevel": "debug" if debug else "warning"},
        "policy": POLICY,
        "inbounds": [socks_inbound(client_port, "agent-in")],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {
                "tag": "carrier",
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": "127.0.0.1",
                            "port": carrier_port,
                            "users": [
                                {
                                    "id": VMESS_ID,
                                    "alterId": 0,
                                    "security": "aes-128-gcm",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {"network": "tcp"},
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "domain": [f"full:{DEFAULT_REVERSE_DOMAIN}"],
                    "outboundTag": "carrier",
                }
            ],
        },
    }
    server_config = {
        "log": {"loglevel": "debug" if debug else "warning"},
        "policy": POLICY,
        "inbounds": [
            {
                "tag": "carrier-in",
                "listen": "127.0.0.1",
                "port": carrier_port,
                "protocol": "vmess",
                "settings": {"clients": [{"id": VMESS_ID, "alterId": 0}]},
                "streamSettings": {"network": "tcp"},
            },
            socks_inbound(business_port, "business-in"),
        ],
        "outbounds": [
            {
                "tag": "reverse",
                "protocol": "socks",
                "settings": {
                    "servers": [
                        {
                            "address": reverse_address[0],
                            "port": reverse_address[1],
                            "users": [{"user": USERNAME.decode(), "pass": "dummy"}],
                        }
                    ]
                },
            }
        ],
    }
    if carrier in ("vless", "vless-tls"):
        client_config["outbounds"][1]["protocol"] = "vless"
        client_config["outbounds"][1]["settings"]["vnext"][0]["users"] = [
            {"id": VMESS_ID, "encryption": "none"}
        ]
        server_config["inbounds"][0]["protocol"] = "vless"
        server_config["inbounds"][0]["settings"] = {
            "decryption": "none",
            "clients": [{"id": VMESS_ID}],
        }
        if carrier == "vless-tls":
            certificate = output / "test-tls-certificate.pem"
            private_key = output / "test-tls-key.pem"
            certificate.write_text(TEST_TLS_CERTIFICATE)
            private_key.write_text(TEST_TLS_PRIVATE_KEY)
            client_config["outbounds"][1]["streamSettings"] = {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "disableSystemRoot": True,
                    "certificates": [
                        {
                            "certificateFile": str(certificate),
                            "usage": "verify",
                            "oneTimeLoading": True,
                        }
                    ],
                },
            }
            server_config["inbounds"][0]["streamSettings"] = {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": str(certificate),
                            "keyFile": str(private_key),
                            "oneTimeLoading": True,
                        }
                    ]
                },
            }
    elif carrier == "shadowsocks":
        encryption = {
            "method": "chacha20-ietf-poly1305",
            "password": "reverse-interop-encrypted-carrier",
        }
        client_config["outbounds"][1]["protocol"] = "shadowsocks"
        client_config["outbounds"][1]["settings"] = {
            "servers": [{"address": "127.0.0.1", "port": carrier_port, **encryption}]
        }
        server_config["inbounds"][0]["protocol"] = "shadowsocks"
        server_config["inbounds"][0]["settings"] = {"network": "tcp", **encryption}
    if default_policy:
        client_config.pop("policy")
        server_config.pop("policy")
    processes = []

    async def launch(role, config, ports):
        config_path = output / f"{name}-{role}.json"
        log_path = output / f"{name}-{role}.log"
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        with log_path.open("wb") as log:
            process = await asyncio.create_subprocess_exec(
                str(binaries / name),
                "run",
                "-c",
                str(config_path),
                stdout=log,
                stderr=asyncio.subprocess.STDOUT,
            )
        processes.append(process)
        try:
            for port in ports:
                await wait_ready(process, port)
        except Exception as exc:
            raise RuntimeError(
                f"{name} {role} startup failed; inspect {log_path}"
            ) from exc

    try:
        await launch("server", server_config, [carrier_port, business_port])
        await launch("client", client_config, [client_port])
        yield ("127.0.0.1", client_port), ("127.0.0.1", business_port)
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


class RecordingClient(Socks5Client):
    """Observe the precise request the agent passes to its real local proxy."""

    def __init__(self, *endpoint):
        super().__init__(*endpoint)
        self.targets = []
        self.initial_payloads = []

    async def connect(self, target, *, initial_data=b"", credentials=None):
        self.targets.append(target)
        self.initial_payloads.append(initial_data)
        return await super().connect(
            target, initial_data=initial_data, credentials=credentials
        )

    async def _connect_pipelined(
        self, target, source, *, credentials=None, byte_budget, call_budget
    ):
        self.targets.append(target)
        return await super()._connect_pipelined(
            target,
            source,
            credentials=credentials,
            byte_budget=byte_budget,
            call_budget=call_budget,
        )


@asynccontextmanager
async def target_server():
    tasks, writers, errors = set(), set(), []

    async def handle(reader, writer):
        try:
            writer.write(GREETING)
            await writer.drain()
            header = await reader.readexactly(5)
            half_close = bool(header[0])
            size = int.from_bytes(header[1:])
            assert size == len(PAYLOAD), size

            async def receive():
                assert await reader.readexactly(size) == PAYLOAD
                if half_close:
                    assert await reader.read() == b""

            async def send():
                writer.write(RESPONSE)
                await writer.drain()

            if half_close:
                await receive()
                await send()
            else:
                # Both sides exchange a full MiB concurrently, without EOF.
                async with asyncio.TaskGroup() as group:
                    group.create_task(receive())
                    group.create_task(send())
        except asyncio.IncompleteReadError, ConnectionError:
            # Disconnects also occur during the optional unsupported EOF probe.
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

    listeners, servers = [], []
    try:
        port = 0
        for family, host in ((socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")):
            listener = socket.socket(family, socket.SOCK_STREAM)
            listeners.append(listener)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.setblocking(False)
            listener.bind((host, port))
            port = listener.getsockname()[1]
            listener.listen(128)
            servers.append(await asyncio.start_server(accept, sock=listener))
        yield port, errors
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))
        for listener in listeners:
            listener.close()
        for writer in tuple(writers):
            writer.close()
        for task in tuple(tasks):
            task.cancel()
        await asyncio.gather(*tuple(tasks), return_exceptions=True)


async def receive_exact(tunnel, size):
    received = bytearray()
    while len(received) < size:
        data = await tunnel.recv(size - len(received))
        if not data:
            raise AssertionError(f"early EOF: {len(received)} of {size} bytes")
        received.extend(data)
    return bytes(received)


async def check_case(endpoint, target, *, half_close=False, wait_for_greeting=False):
    async with asyncio.timeout(10):
        async with await Socks5Client(*endpoint).connect(target) as tunnel:
            if wait_for_greeting or half_close:
                assert await receive_exact(tunnel, len(GREETING)) == GREETING

            async def send():
                await tunnel.sendall(
                    bytes([half_close]) + len(PAYLOAD).to_bytes(4) + PAYLOAD
                )
                if half_close:
                    tunnel.shutdown_write()

            async def receive():
                if not (wait_for_greeting or half_close):
                    assert await receive_exact(tunnel, len(GREETING)) == GREETING
                assert await receive_exact(tunnel, len(RESPONSE)) == RESPONSE

            async with asyncio.TaskGroup() as group:
                group.create_task(send())
                group.create_task(receive())
            return address_record(tunnel.bound_address)


async def connect_reverse_authenticated(endpoint, target):
    """Inspect ReverseServer's own REP, before another SOCKS proxy replaces BND."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, endpoint)
        await loop.sock_sendall(sock, b"\x05\x01\x02")
        assert await read_exact(sock, 2) == b"\x05\x02"
        await loop.sock_sendall(
            sock, b"\x01" + bytes([len(USERNAME)]) + USERNAME + b"\x05dummy"
        )
        assert await read_exact(sock, 2) == b"\x01\x00"
        await loop.sock_sendall(sock, encode_connect(target))
        bound = await read_reply(sock)
        assert bound == BoundAddress(IPv4Address("0.0.0.0"), 0), bound
        return TcpTunnel(sock, bound, loop)
    except BaseException:
        sock.close()
        raise


async def check_direct_reverse_reply(endpoint, target, *, failure=False):
    async with asyncio.timeout(10):
        async with await connect_reverse_authenticated(endpoint, target) as tunnel:
            if failure:
                assert await tunnel.recv() == b"", (
                    "post-success failure sent a second REP"
                )
            else:
                assert await receive_exact(tunnel, len(GREETING)) == GREETING

                async def send():
                    await tunnel.sendall(b"\x00" + len(PAYLOAD).to_bytes(4) + PAYLOAD)

                async def receive():
                    assert await receive_exact(tunnel, len(RESPONSE)) == RESPONSE

                async with asyncio.TaskGroup() as group:
                    group.create_task(send())
                    group.create_task(receive())
            return address_record(tunnel.bound_address)


async def binary_version(binary):
    process = await asyncio.create_subprocess_exec(
        str(binary),
        "version",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    async with asyncio.timeout(5):
        stdout, _stderr = await process.communicate()
    if process.returncode:
        raise RuntimeError(f"version command failed: {binary}")
    return stdout.decode().splitlines()[0]


async def main(
    binaries,
    output,
    *,
    probe_half_close,
    debug=False,
    carrier="vless-tls",
    default_policy=False,
):
    output.mkdir(parents=True, exist_ok=True)
    versions = {}
    for name in ("xray", "v2ray"):
        binary = binaries / name
        if not binary.is_file():
            raise FileNotFoundError(binary)
        versions[name] = await binary_version(binary)
    results = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "python": sys.version.split()[0],
        "binaries": versions,
        "carrier": CARRIERS[carrier],
        "proxy_policy": "binary defaults" if default_policy else POLICY,
        "registration_protocol": {
            "hello_hex": REGISTRATION_HELLO.hex(),
            "ack_hex": REGISTRATION_ACK.hex(),
            "hello_bytes": len(REGISTRATION_HELLO),
            "ack_bytes": len(REGISTRATION_ACK),
            "agent_idle_requires_ack": True,
        },
        "username": USERNAME.decode(),
        "network": "loopback only",
        "checks": [],
    }

    def record(result):
        results["checks"].append(result)
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps(result), flush=True)

    async with target_server() as (target_port, target_errors):
        targets = [
            Target(IPv4Address("127.0.0.1"), target_port),
            Target(IPv6Address("::1"), target_port),
            Target("localhost", target_port),
        ]
        for name in ("xray", "v2ray"):
            try:
                async with ReverseServer() as server:
                    await server.start(port=0)
                    async with proxies(
                        name,
                        binaries,
                        output,
                        server.address,
                        debug=debug,
                        carrier=carrier,
                        default_policy=default_policy,
                    ) as (
                        agent_endpoint,
                        business_endpoint,
                    ):
                        egress = RecordingClient(*agent_endpoint)
                        registration = RecordingClient(*agent_endpoint)
                        async with ReverseAgent(
                            Target(DEFAULT_REVERSE_DOMAIN, 443),
                            registration,
                            egress_proxy=egress,
                            options=ReverseAgentOptions(
                                idle_connections=2, max_connections=8
                            ),
                        ) as agent:
                            await agent.start()
                            prewarm = {
                                "proxy": name,
                                "case": "prewarm_without_application_payload",
                                "required": True,
                                "application_payload_bytes": 0,
                                "idle_stability_seconds": 2,
                            }
                            try:
                                prewarm["elapsed_seconds"] = round(
                                    await wait_pool(server, agent), 4
                                )
                                assert not egress.targets
                                assert server.idle_count() == 0
                                registered = len(registration.targets)
                                assert registration.initial_payloads == [
                                    REGISTRATION_HELLO,
                                    REGISTRATION_HELLO,
                                ], registration.initial_payloads
                                prewarm["agent_ack_confirmed_idle_before_hold"] = (
                                    agent.idle_connections
                                )
                                prewarm["server_same_username_idle_before_hold"] = (
                                    server.idle_count(USERNAME)
                                )
                                await asyncio.sleep(2)
                                assert len(registration.targets) == registered == 2, (
                                    "idle registrations were replaced",
                                    registered,
                                    len(registration.targets),
                                )
                                assert server.idle_count(USERNAME) == 2
                                assert agent.idle_connections == 2
                            except Exception as exc:
                                prewarm.update(status="FAIL", error=repr(exc))
                                record(prewarm)
                                continue
                            prewarm.update(
                                status="PASS",
                                idle_for_username=server.idle_count(USERNAME),
                                idle_for_noauth=server.idle_count(),
                                agent_ack_confirmed_idle_after_hold=(
                                    agent.idle_connections
                                ),
                                registration_hello_bytes_sent=(
                                    sum(map(len, registration.initial_payloads))
                                ),
                                registration_attempts=registered,
                            )
                            record(prewarm)
                            for case, target, failure in (
                                ("direct_optimistic_reply", targets[-1], False),
                                (
                                    "direct_post_success_failure_no_second_reply",
                                    Target(
                                        IPv4Address("127.0.0.1"), unused_ports(1)[0]
                                    ),
                                    True,
                                ),
                            ):
                                result = {
                                    "proxy": name,
                                    "case": case,
                                    "required": True,
                                    "target": address_record(target),
                                    "reply_endpoint": (
                                        "ReverseServer authenticated business listener"
                                    ),
                                }
                                before = len(egress.targets)
                                try:
                                    await wait_pool(server, agent)
                                    result["bound"] = await check_direct_reverse_reply(
                                        server.address, target, failure=failure
                                    )
                                    assert egress.targets[before:] == [target]
                                    result["refill_seconds"] = round(
                                        await wait_pool(server, agent), 4
                                    )
                                except Exception as exc:
                                    result.update(status="FAIL", error=repr(exc))
                                else:
                                    result["status"] = "PASS"
                                record(result)
                            for target in targets:
                                result = {
                                    "proxy": name,
                                    "case": "bidirectional_tcp",
                                    "required": True,
                                    "target": address_record(target),
                                    "client_to_target_bytes": len(PAYLOAD),
                                    "target_to_client_bytes": len(RESPONSE),
                                    "server_first_bytes": len(GREETING),
                                    "client_waits_for_greeting": True,
                                }
                                before = len(egress.targets)
                                try:
                                    await wait_pool(server, agent)
                                    result["bound"] = await check_case(
                                        business_endpoint,
                                        target,
                                        wait_for_greeting=True,
                                    )
                                    observed = egress.targets[before:]
                                    assert observed == [target], observed
                                    assert not target_errors, target_errors
                                    result["agent_target"] = address_record(observed[0])
                                    result["refill_seconds"] = round(
                                        await wait_pool(server, agent), 4
                                    )
                                    result["agent_ack_confirmed_idle_after_refill"] = (
                                        agent.idle_connections
                                    )
                                    result["server_same_username_idle_after_refill"] = (
                                        server.idle_count(USERNAME)
                                    )
                                except Exception as exc:
                                    result.update(status="FAIL", error=repr(exc))
                                else:
                                    result["status"] = "PASS"
                                record(result)
                            if probe_half_close:
                                target = targets[-1]
                                for path, endpoint in (
                                    ("direct_P_C", agent_endpoint),
                                    ("reverse", business_endpoint),
                                ):
                                    result = {
                                        "proxy": name,
                                        "case": "EOF_triggered_response",
                                        "path": path,
                                        "required": False,
                                        "target": address_record(target),
                                        "payload_bytes": len(PAYLOAD),
                                    }
                                    try:
                                        await wait_pool(server, agent)
                                        result["bound"] = await check_case(
                                            endpoint, target, half_close=True
                                        )
                                    except Exception as exc:
                                        result.update(
                                            status="LIMITATION", error=repr(exc)
                                        )
                                    else:
                                        result["status"] = "PASS"
                                    record(result)
            except Exception as exc:
                record(
                    {
                        "proxy": name,
                        "case": "proxy_lifecycle",
                        "required": True,
                        "status": "FAIL",
                        "error": repr(exc),
                    }
                )
    if any(
        result["required"] and result["status"] != "PASS"
        for result in results["checks"]
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--probe-half-close", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--carrier", choices=CARRIERS, default="vless-tls")
    parser.add_argument("--default-policy", action="store_true")
    arguments = parser.parse_args()
    if arguments.debug:
        logging.basicConfig(level=logging.DEBUG)
    asyncio.run(
        main(
            arguments.bin_dir.resolve(),
            arguments.output_dir.resolve(),
            probe_half_close=arguments.probe_half_close,
            debug=arguments.debug,
            carrier=arguments.carrier,
            default_policy=arguments.default_policy,
        )
    )
