# callback DNS 服务器

`socks5_kit.dns` 是同一发行包里的独立模块，不依赖 SOCKS 对象，运行时无第三方依赖。
调用方提供 `resolve(domain, qtype) -> IPv4Address | IPv6Address | str | None`，
服务器负责 A、AAAA 和 CNAME 的报文及 UDP/TCP 监听。
可选把 callback 的 CNAME 目标交给上游 DNS 查询一次 A/AAAA；
不实现自行迭代递归、多地址答案或 DNSSEC。callback 仍决定哪些名字可以处理。

## 使用

```python
import asyncio
from ipaddress import IPv4Address, IPv6Address

from socks5_kit.dns import DnsOptions, DnsRecordType, DnsServer


def resolve(
    domain: str, qtype: DnsRecordType
) -> IPv4Address | IPv6Address | str | None:
    if domain == "alias.example":
        return "service.example"
    if domain != "service.example":
        return None
    if qtype == DnsRecordType.AAAA:
        return IPv6Address("2001:db8::10")
    # A 得到地址；CNAME 查询得到空答案，表示名字存在但没有别名。
    return IPv4Address("192.0.2.10")


async def main() -> None:
    async with DnsServer(resolve, options=DnsOptions(ttl=30)) as server:
        await server.start(host="127.0.0.1", port=15353)
        await server.serve_forever()


asyncio.run(main())
```

callback 必须返回 `IPv4Address`、`IPv6Address`、域名 `str` 或 `None`，可定义为 `async def`。
`qtype` 为 `DnsRecordType.A`、`.AAAA` 或 `.CNAME`；可与对应数字 1、28、5 比较。
每次固定传入域名和查询类型两个位置参数，无签名推断或单参数回退。
第二参数可带默认值，但服务器总是显式传入实际查询类型。
签名不匹配或内部抛出 TypeError 按其他 callback 异常处理，不重试调用。
同步 callback 应快速返回，避免阻塞 asyncio 事件循环。
callback 超时只约束可等待的异步工作，无法中断阻塞的同步函数。
示例地址须换成实际配置；可用 `dig @127.0.0.1 -p 15353 service.example AAAA +norecurse`
或查询 `alias.example A`、`alias.example CNAME`。

名称转为 ASCII 小写，去掉末尾根点；IDNA 域名保持 `xn--...` 的 A-label，根名为 `"."`。
合法二进制标签也能接受：标签内的点、反斜线和非打印/非 ASCII 字节表示为 `\DDD`
十进制转义，避免与标签分隔符混淆。回复中的问题名称保留查询的原始大小写。

字符串始终表示 CNAME 目标：返回 `"canonical.example"` 即回复一条别名记录；
`"127.0.0.1"` 也表示字面域名，不自动转成 A。要回复 IP，必须构造标准库 IP 对象。
别名目标接受 Unicode IDNA 和可选末尾点，规范化为小写 ASCII/A-label；
空标签、控制字符和过长名称会令此次查询回复 SERVFAIL。
目标 `"."` 表示根名，其他目标必须是完整名称，不使用系统搜索后缀；
此接口不接受查询名称里的 `\DDD` 二进制标签转义。
DNS 返回值不使用带端口的 `Target` / `BoundAddress`，两者会作为非法值处理；
SOCKS 使用相同的 IP 对象/域名字符串约定，另在 `Target(host, port)` 中携带端口。

## 查询行为

| 输入 / callback 结果 | 回复 |
| --- | --- |
| IN/A，返回 `IPv4Address` | NOERROR，一条 A，TTL 使用选项值 |
| IN/AAAA，返回 `IPv6Address` | NOERROR，一条 AAAA |
| IN/A、AAAA 或 CNAME，返回域名字符串 | NOERROR，一条 CNAME |
| 支持的查询，返回 IP 但与查询类型不匹配 | NOERROR，空答案（NODATA）；CNAME 查询收到 IP 也为空答案 |
| 支持的查询，返回 `None` | NXDOMAIN，空答案，表示名字不存在 |
| IN/其他类型，包括 MX、TXT、ANY | NOERROR，空答案，不调用 callback |
| callback 异常、超时或其他非法值（含带 scope ID 的 IPv6） | SERVFAIL |
| 非 QUERY opcode / 非 IN class | NOTIMP / REFUSED，不调用 callback |
| 完整头但格式错误、多问题查询、压缩循环等 | FORMERR，不调用 callback |
| 不足 12 字节或已经是回复的包 | 忽略 |

只对标准 QUERY/IN 的 A、AAAA、CNAME 调用 callback，一次查询只调用一次。
同一名称可通过 `qtype` 返回不同地址族。`None` 始终表示名字不存在；
存在但缺少请求类型时，可返回该名字的另一种 IP，使服务器回复 NODATA。
CNAME 默认只返回别名记录。配置 `upstream_dns` 后，A/AAAA 查询可进行下面的单次补查；
直接 CNAME 查询仍只返回别名，不再次调用 callback。服务器内部不缓存、
不合并并发查询；设置 TTL 也不会减少 callback 次数。客户端可按 TTL 缓存答案。
默认 TTL 为 0。NXDOMAIN/NODATA 不包含 SOA，服务器不指定负缓存期限。

解析支持压缩名称及普通 EDNS(0)；未使用的记录、未知 EDNS 选项和报文末尾多余字节
安全跳过。重复 OPT、非法标签、越界/循环指针和截断报文按格式错误处理。
非零 EDNS 版本回复 BADVERS。带 OPT 的回复广告 512 字节。
极长问题名与 CNAME 目标可让回复超过 512 字节：UDP 保留问题/OPT、去掉整条答案并设置 TC，
客户端可用同端口 TCP 获取完整 CNAME；不会发送截断的记录。TCP 不受 512 字节限制。
成功及 NXDOMAIN 设置 AA，保留请求 ID/RD/CD/opcode；RA/AD 为 0，普通回复 TC 为 0。
RD 不改变 callback 或补查规则；只有配置上游且 A/AAAA 返回域名才触发补查。
DO 不使服务器提供 DNSSEC 数据。

## 可选上游补查

```python
server = DnsServer(
    resolve,
    upstream_dns=("127.0.0.1", 1053),
    options=DnsOptions(ttl=30, upstream_timeout=2),
)
await server.start("127.0.0.1", 15353)
```

`upstream_dns` 默认 `None`；配置为 `(数字 IPv4/IPv6 字符串, 端口)`，
端口为 1..65535，不接受域名或 IPv6 scope ID。示例需换成实际上游监听地址。
构造只验证并保存配置，不执行网络 I/O；`server.upstream_dns` 为规范化后的只读配置。

下游查询 A/AAAA，callback 返回域名字符串时，先验证/规范化这个别名，再向上游发送一次
同类型的 IN 查询，RD=1。每次使用独立的 UDP socket，接收来源由连接的上游 IP/端口限制；
事务 ID 和问题须匹配。仅取 ANSWER 中第一条对应类型、正确长度的 IN 地址记录，
上游同时包含 CNAME 和对应地址也可接受，authority/additional 的地址不作为答案。

成功时，为下游的原问题构造一条 A/AAAA，保留原 ID/问题名，TTL 使用本机 `DnsOptions.ttl`；
不转发上游原始包，也不附带 CNAME 链。未成功时仍回复 callback 给出的原始 CNAME，
包括超时、网络错误、无地址、错误响应、TC、错误/损坏报文、仅有 CNAME 等情况。
上游 NXDOMAIN 不覆盖 callback 已存在的别名；补查失败不会变成 SERVFAIL。
callback 本身异常或别名非法仍按原规则返回 SERVFAIL。

这一步不再次调用 callback、不查询上游的其他 CNAME，不重试、不进行上游 TCP 回退，
也不使用系统 DNS。直接 CNAME 查询、callback 直接返回 IP/None、其他类型查询不会补查。
超时独立于 callback 超时，补查期间占用原查询额度；关闭/取消会回收上游 UDP socket。
不缓存上游答案，每次符合条件的查询都会补查一次。

## 嵌入与生命周期

构造对象不执行 I/O。`await start(host="127.0.0.1", port=53)` 同时启动 UDP 和 TCP，
两者绑定同一地址、同一端口。`port=0` 先选择临时端口再绑定另一种传输；
`server.address` 返回 `(host, port)`，未监听或关闭时为 `None`。
IPv4/IPv6 均可作为监听地址，返回的记录类型与监听地址族互不影响。

TCP 使用两字节长度前缀，允许同一连接发送多个查询和 pipeline；同一连接顺序处理、
按序回复，不必每次查询重新连接。UDP 查询各自处理，可并发等待异步 callback。
服务使用调用方当前 asyncio 事件循环，不创建线程；启动和关闭须在同一循环中进行。
启动失败会回收已创建的监听，可重试；成功启动后不能重复启动，关闭后不能重启。

`await aclose()` 停止双监听，取消正在处理的查询，立即关闭现存 TCP 连接并等待资源回收。
关闭不保证送达尚未发送的答案；重复关闭安全。取消关闭等待仍会完成清理。
异步上下文退出或取消 `serve_forever()` 也会关闭。
`active_queries` 和 `active_connections` 可用于观察待处理查询与 TCP 连接数。

| `DnsOptions` | 默认值与含义 |
| --- | --- |
| `ttl` | 0；A、AAAA、CNAME 的 TTL，整数 0..2147483647 秒 |
| `callback_timeout` | 10 秒，单次 callback |
| `upstream_timeout` | 2 秒，整个上游 UDP 补查；失败保留 CNAME |
| `tcp_idle_timeout` | 10 秒，完整请求读取、回复写入及连接关闭的等待上限 |
| `max_pending_queries` | 256，UDP/TCP 合计；达到上限后 UDP 丢包，TCP 查询回复 SERVFAIL |
| `max_tcp_connections` | 128；超过时直接关闭新连接 |
| `backlog` | 128，TCP 监听队列 |
| `ipv6_only` | True；IPv6 监听设为 False 时可接受 IPv4 双栈连接 |

超时须有限且大于 0，容量须为正整数。单次 TCP 读包受 DNS 的 16 位长度限制；
报文解析和答复很小，使用常规 asyncio I/O，无需 splice。

## 协议依据与测试

实现参考 [RFC 1034：CNAME](https://www.rfc-editor.org/rfc/rfc1034.html#section-3.6.2)、
[RFC 1035：报文与压缩](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1)、
[RFC 7766：DNS over TCP](https://www.rfc-editor.org/rfc/rfc7766.html#section-6)、
[RFC 6891：EDNS](https://www.rfc-editor.org/rfc/rfc6891.html#section-6)、
[RFC 2308：NODATA 与负缓存](https://www.rfc-editor.org/rfc/rfc2308.html#section-2.2)、
[RFC 4343：名称大小写](https://www.rfc-editor.org/rfc/rfc4343.html#section-2) 和
[RFC 9619：单问题查询](https://www.rfc-editor.org/rfc/rfc9619.html#section-3)。

协议测试独立检查 wire 格式、压缩/截断、二进制名字、flags 和 EDNS；
服务器测试检查 callback、拒绝/失败、真实 UDP/TCP 同端口收发、多查询、IPv6、限流与关闭。
这些 DNS 测试不涉及尚未实现的 SOCKS5 UDP ASSOCIATE。

2026-10-08，Python 3.14.8/Linux：133 项 DNS 协议测试、83 项 DNS 服务器测试及
49 项上游补查测试全部通过。
包含 A/AAAA/CNAME、严格双参数 callback、字符串只作 CNAME、IP 对象、非法值拒绝、
其他类型零调用、IDNA、UDP TC/TCP 完整回答，
以及 startup 失败/取消后重试、callback 内关闭自身、取消关闭等待、TCP 背压回收。
补查测试使用本机模拟上游，覆盖成功、失败保留 CNAME、IPv6、错 ID、无缓存、
UDP/TCP 下游入口，以及关闭时回收出站 socket；未发送公网 DNS 请求。
包含后续 SOCKS 认证检查，全包 458 项测试无跳过，
在 `PYTHONASYNCIODEBUG=1`、`python -X dev` 和 `-W error` 下通过。
