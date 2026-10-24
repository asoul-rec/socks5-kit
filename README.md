# socks5-kit

可嵌入其他网络项目的 Python 网络模块，使用 uv 管理，要求 Python 3.14 和 Linux。
运行时无第三方依赖，使用调用方的 asyncio 事件循环。

## 功能

- **SOCKS5 目标改写中继**：接收 IPv4、IPv6 或域名目标，由同步或异步 callback 改写为域名，
  经指定上游 SOCKS5 建连，随后通过双向 Linux `splice` / pipe 透传。入站用户名和密码交给 callback 决策。
- **SOCKS5 客户端**：独立建立 TCP 隧道，支持三种地址类型、可选用户名/密码认证、写半关闭，
  以及随 CONNECT 发送首段数据。
- **callback DNS 服务器**：支持 UDP/TCP 上的 A、AAAA 和 CNAME；可选上游 DNS 补查 CNAME 对应地址。
- **reverse addon**：Agent 经现有代理预建反向 TCP 连接，Server 按 SOCKS5 username 分组、
  随机领取空闲资源，空池请求可有界排队并设置超时。HELLO/ACK 确认公网注册，
  预注册和业务请求共享 user slot 配额，每条连接使用一次，并在后台补池。
  单个 Agent 可共用代理和目标配置，为多组本机 SOCKS 账户分别补池，并设置全局连接上限。
  取得资源后提前回复成功，流水发送 CONNECT 和业务数据，连接失败时关闭流。

SOCKS5 目前仅支持 TCP CONNECT，不支持 BIND 和 UDP ASSOCIATE。
目标改写中继和 reverse addon 均经代理访问目标，不直接连接业务目标。

## 安装

在其他 uv 项目中添加本地包：

```bash
uv add --editable /absolute/path/to/socks5-kit
```

## 中继示例

```python
import asyncio

from socks5_kit import RewriteContext, Socks5RewriteServer, Target


def rewrite(target: Target, context: RewriteContext) -> Target | None:
    if target.host == "service.example":
        return Target("mapped.example", target.port)
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

将示例域名、上游地址和改写规则换成实际配置。callback 返回 `None` 表示拒绝。
`Target(host, port)` 的字符串始终表示域名；IP 使用 `ipaddress.IPv4Address` 或 `IPv6Address` 对象。

## 文档

- [SOCKS5 架构与 API](docs/architecture.md)
- [DNS API](docs/dns.md)
- [reverse 协议与使用示例](docs/reverse.md)
- [测试与代理兼容性](docs/validation.md)
- [访问日志与 reverse 排队诊断](docs/logging.md)
- [吞吐与 CPU benchmark](docs/benchmark.md)
- [SOCKS5 UDP 实现调查](docs/udp-interop.md)

## 开发

```bash
uv sync --locked
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv build
```
