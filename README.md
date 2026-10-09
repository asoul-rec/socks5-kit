# socks5-kit

可嵌入其他网络项目的 SOCKS5 目标改写中继，使用 uv 管理，Python 3.14，Linux 运行。
运行时无第三方依赖。

已实现 TCP CONNECT：接收 IPv4、IPv6 或域名目标，调用同步或异步 callback，
用返回的域名目标连接指定上游 SOCKS5，随后通过双向 Linux `splice` / pipe 透传 payload。
每个 CONNECT 使用独立上游连接；不直接连接目标，不在失败时直连。
入站优先选择用户名/密码方法 `0x02`，其次为无认证 `0x00`；凭据交给 callback 决策。

另提供独立的 [callback DNS 服务器](docs/dns.md)，支持 A、AAAA 和 CNAME，
通过 `resolve(domain, qtype)` 回复，支持 UDP/TCP；与 SOCKS 对象互不依赖。

UDP 暂未实现，UDP ASSOCIATE 和 BIND 均回复 `REP=0x07`。
[架构文档](docs/architecture.md) 记录当前 API、TCP 数据面和后续 UDP 契约；
[UDP 调查](docs/udp-interop.md) 保留 Xray、V2Fly、Shadowsocks 源码对照。

## 启动中继

```python
import asyncio
from ipaddress import IPv4Address

from socks5_kit import RewriteContext, Socks5RewriteServer, Target


def rewrite(target: Target, context: RewriteContext) -> Target | None:
    if target == Target(IPv4Address("192.0.2.10"), 9000):
        return Target("relay-target.example", 9000)
    return None


async def main() -> None:
    async with Socks5RewriteServer(
        rewrite,
        upstream_ip="127.0.0.1",
        upstream_port=1081,
    ) as server:
        await server.start(host="127.0.0.1", port=1080)
        await server.serve_forever()


asyncio.run(main())
```

示例中的映射域名和上游地址需要换成实际配置。域名由上游代理解析。
构造对象不执行 I/O；`start()` 才开始监听。服务使用调用方的 asyncio 事件循环，
无需创建后台线程。`start(port=0)` 可申请临时端口，通过 `server.address` 读取。

`Target(host, port)` 直接构造，`host` 为 `IPv4Address`、`IPv6Address` 或域名字符串。
`target.host` 保留该类型，`target.kind` 按类型推导 `AddressType`；字符串不猜测为 IP。
callback 成功须返回 `Target("域名", port)`，可同时改端口；返回 `None` 或抛出
`RejectTarget` 会以 `REP=0x02` 拒绝，并且不连接上游。返回 IP 或非法值则回复一般失败。
快速同步函数和异步函数都可用；同步函数应避免阻塞事件循环。

入站方法列表包含 `0x02` 就选择它，否则有 `0x00` 就选择无认证，两者都没有则回复 `0xFF`
并关闭。用户名/密码帧完整且版本正确时，无论凭据内容如何都先回复 `01 00`。
随后 `rewrite(target, context)` 可通过 `context.username`、`context.password` 判断策略：
两者均为原始 `bytes`，无认证时均为 `None`；空值保留 `b""`，不会尝试 UTF-8 解码。

```python
def rewrite(target: Target, context: RewriteContext) -> Target | None:
    if (context.username, context.password) != (b"demo-user", b"demo-password"):
        return None
    return Target("relay-target.example", target.port)
```

示例凭据仅展示 callback 写法，应替换为实际策略。拒绝发生在 CONNECT 阶段，回复 `REP=0x02`，
不连接上游。用户名/密码不会转发给上游；`Socks5Client` 仍向上游协商 `0x00`。
凭据不出现在 `RewriteContext` 的默认 repr 中。

`ServerOptions` 可配置握手、callback、上游建立和回复超时，以及连接上限、监听队列、
IPv6 单栈/双栈和 splice 调度预算。默认下游握手/callback/上游建立与握手各 10 秒，
回复 5 秒，最多 1024 个会话；已建立的数据流没有空闲超时。
`await server.aclose(grace_period=5)` 停止接受连接，等待已有会话，期限后取消并回收资源。
异步上下文退出立即关闭；关闭后不能重启同一对象。

## 独立 SOCKS5 客户端

```python
from socks5_kit import Socks5Client, Target


async def fetch() -> bytes:
    client = Socks5Client("127.0.0.1", 1081)
    async with await client.connect(Target("example.com", 80)) as tunnel:
        await tunnel.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        chunks = []
        while data := await tunnel.recv():
            chunks.append(data)
        return b"".join(chunks)
```

独立客户端的 `connect()` 接受三种地址类型，返回拥有 socket 的 `TcpTunnel`，
包含上游返回的 `bound_address`。握手使用精确读取，应用数据保留在 socket 接收队列。
隧道提供 `sendall()`、`recv()`、`shutdown_write()` 和关闭接口；调用方也可直接接管
`tunnel.socket`，同一 socket 的 I/O 应由一个组件统一管理。

## callback DNS

```python
from ipaddress import IPv4Address, IPv6Address

from socks5_kit.dns import DnsRecordType, DnsServer


def resolve(
    domain: str, qtype: DnsRecordType
) -> IPv4Address | IPv6Address | str | None:
    if domain == "alias.example":
        return "service.example"
    if domain != "service.example":
        return None
    if qtype == DnsRecordType.AAAA:
        return IPv6Address("2001:db8::10")
    return IPv4Address("192.0.2.10")


async def serve_dns() -> None:
    async with DnsServer(resolve) as server:
        await server.start("127.0.0.1", 15353)  # UDP/TCP 同端口
        await server.serve_forever()
```

同步/异步 callback 均可；域名使用小写 ASCII/A-label，无末尾点。
`None` 返回 NXDOMAIN，异常/超时返回 SERVFAIL；IP 按对应地址族生成一条 A 或 AAAA。
字符串只表示域名，默认生成一条 CNAME；IP 必须使用 `ipaddress` 对象，
例如返回 `"127.0.0.1"` 仍是 CNAME。callback 固定传入域名和查询类型两个参数。
其他查询类型回复空答案、不调用 callback。
可选 `DnsServer(resolve, upstream_dns=("127.0.0.1", 1053))`：A/AAAA 的 callback 返回域名时，
向上游补查一次。拿到对应地址则回复 A/AAAA，否则保留原 CNAME；不继续追踪上游别名。
内部不缓存；`DnsOptions(ttl=30)` 仅设置客户端缓存 TTL。
完整 API、EDNS 行为及生命周期见 [DNS 文档](docs/dns.md)。

## 安装和开发

在其他 uv 项目中添加本地包：

```bash
uv add --editable /absolute/path/to/socks5-kit
```

本项目使用 src 布局、`.python-version` 和锁文件；开发与构建：

```bash
uv sync --locked
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv build
```

`dist/` 包含 wheel 和源码发行包，尚未发布到 PyPI。
Linux 支持 `os.splice`、`os.pipe2`，事件循环须支持 FD reader/writer；不提供复制转发回退。

测试包含协议检查、真实 Linux splice、部分 I/O/EAGAIN、FD 回收和 TCP 回环集成。
2026-10-07 在 Python 3.14.8/Linux 上运行 **69 项全部通过，无跳过**，并在 asyncio debug
和 warnings-as-errors 下通过；验证了真实半关闭、IPv6/双栈、32 路并发和连接重置。

2026-10-08，加入入站用户名/密码收集后，全量 **458 项通过，无跳过**，
使用 asyncio debug、Python dev 模式和 warnings-as-errors；DNS 的 265 项测试包含真实
UDP/TCP 同端口、IPv6、多查询、限流、超长 CNAME 的 UDP TC/TCP 完整回答，
以及启动失败/取消、关闭取消与 callback 内关闭自身的清理检查。
上游补查覆盖 A/AAAA 成功、CNAME/错误/超时等失败回退、IPv6 上游及出站 socket 回收。
另有 79 项模型验证，覆盖对象类型、域名 IDNA、端口和旧工厂接口删除。
认证增加 31 项协议和 13 项真实 TCP 检查，覆盖方法优先级、原始/空凭据、callback 拒绝、
并发隔离、认证/CONNECT/payload 拼包、分片、半关闭、超时与资源回收。

Xray 26.9.9、V2Fly 5.53.0、Shadowsocks Rust 1.25.0 的普通 TCP 转发均已联调通过。
“客户端先关闭写方向、目标收到 EOF 后才回复”的场景中，Xray/V2Fly 返回空响应，
移除本模块直接连接它们也复现；Shadowsocks Rust 通过。
详见 [验证记录与复现方式](docs/validation.md)。受限环境禁止 TCP 时，回环测试会明确跳过。
已完成 [TCP 吞吐/CPU benchmark](docs/benchmark.md)，包含 recv/send 对照、原始数据与复现工具。
UDP 尚未联调。
