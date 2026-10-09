# TCP 验证记录

日期：2026-10-07。Python 3.14.8，Linux x86_64，默认 asyncio 事件循环。
验证使用本机回环网络，没有向公网目标发送测试 payload。

## 自动化检查

```bash
PYTHONASYNCIODEBUG=1 uv run --locked pytest -q -W error
uv run --locked ruff check .
uv run --locked ruff format --check .
uv build
```

**69 项测试全部通过，无跳过。** asyncio debug 和 warnings-as-errors 下也通过。
此前受限环境跳过的 20 项真实 TCP 测试现已执行通过，额外补充 6 项真实网络/内核检查。
没有为通过测试修改生产代码。

覆盖的关键行为：

- 入站 IPv4/IPv6/DOMAIN 改写成 DOMAIN；显式拒绝不连接上游。
- 下游请求和 payload 合并发送，上游成功回复和 payload 合并发送，内容不丢失。
- 4 MiB 数据先排空再传播写半关闭，目标收到 EOF 后仍能返回响应。
- 小 socket 缓冲、慢接收端、部分 splice、实际 EAGAIN 和就绪竞态注入。
- 实际内核 EOF 和 SHUT_WR；两个方向分别结束。
- IPv6 上游与监听，IPv6 双栈监听接受 IPv4 并规范化 peer 地址。
- 32 条并发隧道，payload 与 callback/session ID 不串线。
- 最大会话数、新连接拒绝、上游 RST、建连/握手失败、pipe 分配失败、取消和 FD 回收。

`tests/test_splice.py` 同时保留可控 EOF 测试与真实内核 EOF 测试，后者会调用真实 shutdown。
受限环境无法创建 TCP socket 时，相应测试明确标记跳过；此次没有跳过。

## 实际程序联调

二进制来自官方固定版本发行包，已核对 GitHub release asset 提供的 SHA-256。
[下载来源及摘要](tcp-interop-binaries.json)、[逐项结果](tcp-interop-results.json) 保留本次证据。

| 上游 | 实测版本 | 配置 |
| --- | --- | --- |
| Xray-core | 26.9.9，`52a412d` | 无认证 SOCKS 入站，UDP 关闭，Freedom 出站；其他策略默认 |
| V2Fly | 5.53.0 | 无认证 SOCKS 入站，UDP 关闭，Freedom 出站；其他策略默认 |
| Shadowsocks Rust | 1.25.0 | sslocal SOCKS → ssserver；chacha20-ietf-poly1305；无插件 |

测试链路为客户端 → 本模块 → 实际程序 → 本机目标。
原目标分别为 IPv4、IPv6、DOMAIN，callback 均返回 `localhost:目标端口`。
目标监听双栈回环可达端点；每个测试发送 1 MiB 二进制数据，校验返回的全部字节。
成功回复中的 BND 由本模块保留上游返回值，不做目标反向映射。

| 场景 | Xray | V2Fly | SS Rust |
| --- | --- | --- | --- |
| 目标收到完整请求后回复；三个原目标类型 | 3/3 通过 | 3/3 通过 | 3/3 通过 |
| 客户端写半关闭；目标收到 EOF 后才回复；三个原目标类型 | 0/3，空响应 | 0/3，空响应 | 3/3 通过 |
| 移除本模块，直接连接上游，写半关闭后等待回复 | 空响应 | 空响应 | 通过 |

总计 21 项程序联调观测，13 通过、8 失败；8 项失败均为上述 Xray/V2Fly 半关闭场景，
其中 2 项是移除本模块的对照。自动化模块测试中的真实 TCP 半关闭通过，
且 SS 链路的同一场景通过，因此不能将这些失败归因于本模块的 splice 状态机。
观察只能说明所列版本和配置的行为，不推断所有 Xray/V2Fly 版本都如此。

这里的特殊请求依赖“请求 EOF”作为响应触发条件。若 B 已结束返回流，M 无法透传一个
尚未得到的响应；延迟传播 EOF 也不能触发目标回复。当前仍保留正确的 TCP 半关闭语义，
不添加基于上游品牌的特殊处理。

## 复现联调

提供包含 `xray`、`v2ray`、`sslocal`、`ssserver` 四个可执行文件的目录，然后运行：

```bash
uv run python tools/check_interop.py \
  --bin-dir /absolute/path/to/proxy-binaries \
  --output-dir /absolute/path/to/test-output
```

工具启动隔离的本机配置和子进程，结束时停止它们；不下载二进制，不改系统配置。
输出目录包含配置、进程日志与 `results.json`。测试密码仅用于本机 SS 测试。
每项 payload/结果有 5 秒期限，进程启动有 10 秒期限。
上述固定版本会因已记录的半关闭失败退出码 1，失败结果不会被隐藏成通过。

后续吞吐/CPU 测量见 [benchmark](benchmark.md)。本节正确性联调未验证 UDP、
Shadowsocks libev、非默认策略、
外部网络或第三方 GUI/分支。当前测试结果支持 TCP 首版的正确性，不提供吞吐数值承诺。

## DNS 增量验证（2026-10-08）

新增独立 DNS 模块首版（仅 A）后，Python 3.14.8/Linux 全量测试 **155 passed，无跳过**，
使用 `PYTHONASYNCIODEBUG=1 python -X dev -m pytest -q -W error`。
原有 SOCKS/splice 测试仍通过；本次新增 DNS 协议 48 项、DNS 服务器 37 项及 DNS 模块导入检查。

DNS 真实回环验证 UDP/TCP 同端口、同步/异步 callback、A/NXDOMAIN、多次查询与 pipeline、
IPv6、查询/连接上限；生命周期检查启动失败/取消后重试、关闭取消、callback 内关闭自身，
并用背压 writer 验证关闭会 abort 回收。协议检查压缩名字、二进制标签、边界/截断、
错误回复及 EDNS/BADVERS，未向公网发送 DNS 请求。
Ruff、格式及 uv 锁文件检查通过。DNS API 和语义见 [文档](dns.md)。

同日扩展为 A/AAAA/CNAME 后，全量 **222 passed，无跳过**，仍使用 asyncio debug、
Python dev 模式和 warnings-as-errors。DNS 协议测试 80 项、服务器测试 72 项，
新增现代双参数 callback/旧接口兼容、地址族匹配、CNAME/IDNA、非支持查询不调用 callback、
IPv6 socket 上的三种答案、超长 CNAME 的 UDP TC/EDNS 及 TCP 完整回复。
Ruff、格式与锁文件检查通过，重新构建 wheel/源码发行包并核对模块内容及 wheel 导入。

随后删除未使用过的旧 DNS callback，统一 IP 对象与域名字符串接口：
DNS 固定双参数且输出仅 `IPv4Address | IPv6Address | str | None`；
SOCKS `Target(host, port)` / `BoundAddress(host, port)` 保留 IP 对象，字符串始终 DOMAIN，
删除旧工厂与三参数构造。全量 **312 passed，无跳过**，使用同样的 debug/dev/-W error 检查；
包括 DNS 协议 80 项、DNS 服务器 83 项、模型 79 项及原 SOCKS/splice/包导入检查。
真实本机网络测试通过，Ruff、格式与锁文件检查通过，工具入口和 JSON 输出也已适配。
重新构建 wheel/源码发行包，并验证 wheel 中严格 DNS 输出及 SOCKS typed-host 编解码。

可选 CNAME 上游补查加入后，全量 **414 passed，无跳过**，同样使用 debug/dev/-W error。
DNS 协议现 133 项、服务器 83 项、上游补查 49 项；全部真实网络使用本机模拟 UDP 上游，
覆盖原问题/ID/TTL 保留、IPv4/IPv6 地址补全、混合 CNAME+地址、失败回退、错误 ID、
不补查分支、重复查询不缓存和关闭时出站 socket 回收。没有发送公网 DNS 查询。
Ruff、格式及锁文件检查通过，发行包重新构建并验证上游配置及 wire helpers 导入。

## 入站用户名/密码收集（2026-10-08）

新增方法选择 `0x02` 优先、`0x00` 回退，以及原始凭据通过 `RewriteContext` 传给 rewrite。
31 项认证协议测试和 13 项真实 TCP 测试通过，包含任意二进制/空/255 字节凭据、
认证与 CONNECT/payload 拼包及分片、并发会话隔离、先认证成功再由 callback 拒绝、
不转发凭据给上游、半关闭，以及错误版本/EOF/超时/关闭时的回收。
全量 **458 passed，无跳过**，使用 asyncio debug、Python dev 模式和 `-W error`；
所有网络测试仅本机回环。Ruff、格式和 uv 锁文件检查通过，发行包已重新构建并验证。
