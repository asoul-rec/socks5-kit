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

## 独立 reverse addon 首版（2026-10-11）

以下保留没有注册 HELLO/ACK 的首版验证。当前协议增加注册协商；VMess/SS 的旧失败
已在后文的「注册 HELLO/ACK」中复测通过，不能用本节旧表判断当前版本的兼容性。

实现独立子包 `socks5_kit.reverse`，按原始 SOCKS username 分组，等概率随机选择空闲资源。
Agent 预建连接，收到反向 CONNECT 后异步补池，每条资源只使用一次。
没有独立控制连接、额外注册 ACK、mux 或自动重发已提交的目标请求。

Python 3.14.8/Linux 全量 **660 passed，无跳过**，其中新增 reverse 检查 201 项和
1 项子包导入检查。使用 `PYTHONASYNCIODEBUG=1 python -X dev -m pytest -q -W error`。

模块检查包括 DOMAIN/IPv4/IPv6、完整成功/失败 REP 与 BND、分片/拼包、2 MiB payload、
目标先发 banner、双向半关闭、不同 username 隔离（含 `None`、空及非 UTF-8 bytes）、
password 不参与分组、随机选取和单次使用、空闲 EOF/超时、注册和已领取资源的额度、
补池时机、注册失败退避与无业务时重试，以及取消、关闭和 FD/pipe 回收。
额外验证已建立 relay 在 Server 宽限关闭期间继续传输、关闭调用方被取消时的完整回收、
非末尾资源移除后的索引更新，以及领取前就绪 EOF/异常字节与残留空闲回调的交接。
握手沿用现有精确读取，转发运行真实 Linux splice；目标连接仅经本机 SOCKS 代理。

测试辅助服务器的关闭顺序调整为先关闭连接并取消持有连接的测试任务，再等待监听器
完全关闭，适配 Python 3.14 的 `Server.wait_closed()` 对活动连接的等待。
没有为通过测试改变已有 SOCKS/DNS 行为。

Ruff、格式、uv 锁文件离线检查通过；重新构建 wheel/源码包，核对其中 reverse 模块，
并在隔离 Python 导入路径下验证 wheel 中的公开导出。
完整接口和代理路由要求见 [reverse 文档](reverse.md)。

### 真实双侧代理链路（无注册协商的首版）

使用前文同一组官方固定版本二进制：Xray 26.9.9 与 V2Fly 5.53.0。
每个品牌启动独立内网/公网代理进程；内网 SOCKS 入站按注册域名分流到载体，
普通业务目标走 Freedom；公网的载体入站和业务 SOCKS 入站均通过带
`user=reverse-test` 的 SOCKS5 出站交给 ReverseServer。所有监听及目标都在本机回环，
没有修改代理代码、启用 mux 或发送公网业务数据。

验证 Agent 不发送任何注册后的业务 payload 时，两条连接能到达指定 user 池并保持 2 秒；
默认无认证池始终为零。随后依次请求 IPv4、IPv6、DOMAIN，双向各传 1 MiB，
核对全部字节、目标主动发出的 38 字节 banner、Agent 收到的目标类型和补池。
代理策略显式设置 `handshake=10`、`connIdle=300`、`uplinkOnly=10`、`downlinkOnly=10`。

| 载体 | Xray | V2Fly |
| --- | --- | --- |
| VLESS/TLS，测试证书显式加入信任 | 预建 + 3/3 双向传输通过 | 预建 + 3/3 双向传输通过 |
| VLESS 裸 TCP，无 TLS | 预建 + 3/3 双向传输通过 | 预建 + 3/3 双向传输通过 |
| VMess AES-128-GCM / TCP | 短时入池，3/3 业务失败 | 预建 + 3/3 双向传输通过 |
| 代理内置 Shadowsocks chacha20-ietf-poly1305 / TCP | 短时入池，3/3 业务失败 | 预建 + 3/3 双向传输通过 |

默认工具使用通过的 VLESS/TLS 配置：自带公开的测试证书/私钥，仅生成本机测试配置，
双方显式信任该证书，设置 `serverName=localhost`，不依赖 `allowInsecure` 或运行时 openssl。
VLESS 裸 TCP 仅用于对照，不提供载体加密。表中的 Shadowsocks 是 Xray/V2Fly 自身的实现，
不是此前验证的 Shadowsocks Rust。

最终默认 VLESS/TLS 拓扑的 **8 项必要检查全部通过**。另做 4 项 EOF 触发响应探针：
两个品牌的直接内网代理及 reverse 链路都未通过，与此前记录的半关闭限制一致。
模块自己的真实半关闭测试通过；这里保留代理链路的实际限制，不用正常传输成功代替它。
各载体、失败对照和最终默认配置结果保存在 [逐项记录](reverse-interop-results.json)。

Xray 的 VMess 问题在不使用 ReverseAgent、ReverseServer 和 splice 的原始载体对照中仍复现：
远端先发的请求能到达客户端，但客户端回写内容没有返回，之后载体关闭。
默认策略约 1 秒关闭，延长单向超时只是延迟关闭，不能让回写通过。
因此本次不为这些载体增加 addon 心跳或改动 CONNECT/REP 约定，也不将短暂入池称为可用链路。
这些结论只适用于本次固定版本和配置；预建流需要代理实际支持无首包等待及服务端先发数据。

复现通过的加密拓扑：

```bash
uv run python tools/check_reverse_interop.py \
  --bin-dir /absolute/path/to/proxy-binaries \
  --output-dir /absolute/path/to/reverse-test-output
```

输出目录保存双方配置、日志及 `results.json`。`--carrier vmess|vless|vless-tls|shadowsocks`
可选择其他载体；必须检查失败项目和退出码。当前工具执行新版注册协商，
历史失败保存在旧 JSON 中，不能用当前工具直接重现无 HELLO 的行为。
`--probe-half-close` 额外记录直接连接内网代理与 reverse 链路的 EOF 触发响应对照；
该探针单列为代理限制，不代替正常传输检查。

## 注册 HELLO/ACK（2026-10-12）

Agent 在本机 SOCKS CONNECT 后立即流水发送 6 字节 HELLO，先于本机 SOCKS REP。
Server 预留资源额度、发送正常 REP，精确读取并校验 HELLO，再写出 6 字节 ACK，随后入池。
Agent 只有收到版本、magic 和消息类型均匹配的完整 ACK，才计为待用资源。
这样确认公网 addon 已接收注册、保留资源且回程可用，也给载体提供及时的客户端首包。
HELLO/ACK 属于后台预建过程；命中热池时的业务 CONNECT/REP 没有增加一轮协商。
帧格式和超时见 [reverse 文档](reverse.md)，两端 addon 必须同时更新。

新增检查覆盖客户端 payload 先于 SOCKS REP、成功回复和后续数据合包、拒绝时 socket 回收、
假 SOCKS 成功不计为就绪、错误/截断/分片 HELLO 和 ACK、ACK 与 CONNECT 合包、
握手超时/取消、预留资源配额和退避重置。
关闭时显式取消等待 HELLO 的注册任务，避免仅关闭 raw socket 无法唤醒 `sock_recv`，
导致非业务握手占满宽限期。已领取的业务资源仍遵循既有宽限关闭。
新增 timeout 参数置于选项字段末尾，保留原位置参数的含义；普通 SOCKS client 用法不变。

全量 **710 passed，无跳过**，使用 asyncio debug、Python dev 模式和 `-W error`；
reverse 检查共 245 项，另有 6 项客户端首包检查。有效 ACK 还会唤醒补池调度器，
不会继续等待其他并行失败所遗留的退避期限。Ruff、格式和 uv 锁文件检查通过。

### 带注册协商的真实代理复测

保持二进制版本、username 分组、路由与载体配置，使用当前工具复测：

| 载体 | 代理策略 | Xray 26.9.9 | V2Fly 5.53.0 |
| --- | --- | --- | --- |
| VMess AES-128-GCM / TCP | 显式超时 | 4/4 通过 | 4/4 通过 |
| VMess AES-128-GCM / TCP | 代理内置默认 | 4/4 通过 | 4/4 通过 |
| 内置 SS chacha20-ietf-poly1305 / TCP | 显式超时 | 4/4 通过 | 4/4 通过 |
| 内置 SS chacha20-ietf-poly1305 / TCP | 代理内置默认 | 4/4 通过 | 4/4 通过 |
| VLESS/TLS | 显式超时 | 4/4 通过 | 4/4 通过 |

每组 4 项包含：注册并保持空闲、IPv4、IPv6、DOMAIN，合计 **40 项必要检查全部通过**。
预建时检查 Agent 和 Server 各有 2 条确认资源，2 秒后仍为 2，注册尝试总数恰为 2，
默认无认证池为零，证明没有靠断线补建掩盖失败。除了注册 HELLO，没有终端业务 payload。
三类业务都先接收目标的 38 字节 greeting，再发送任何业务数据，之后双向各传 1 MiB，
校验完整内容、原始目标和 ACK 确认的补池数量。

此前 Xray VMess/SS 的「短时入池、3/3 业务失败」在这些版本和配置下已消失。
这验证了及时发送首包的兼容性效果，不能推断注册 ACK 能维持任意长时间的空闲连接；
以后仍可能遇到代理/NAT 超时，按原有 EOF 检测及补建处理。
最终 VLESS/TLS 的 4 项额外半关闭探针仍为 TimeoutError：直接内网代理和 reverse 链路
都未通过，注册协商不改变中间代理的半关闭行为。

[新逐项记录](reverse-registration-interop-results.json) 保存五次复测、全部必要检查和可选探针，
并记录 [旧结果](reverse-interop-results.json) 的 SHA-256，旧失败证据保留。
复现默认策略下的 VMess：

```bash
uv run python tools/check_reverse_interop.py \
  --bin-dir /absolute/path/to/proxy-binaries \
  --output-dir /absolute/path/to/reverse-registration-test-output \
  --carrier vmess --default-policy
```

换为 `--carrier shadowsocks` 可复测内置 SS；去掉 `--default-policy` 使用上文的显式超时。
不传 `--carrier` 默认 VLESS/TLS。各运行仅使用本机回环，未修改代理程序代码或系统配置。

### 退避期间单连接试探

注册失败或空闲断连后的重试改为每次仅建立一条连接，并等待其 SOCKS/ACK 完成或失败。
已有批次中尚未完成的注册继续运行，退避时不再额外并发建连；收到有效 ACK 后恢复正常批量补池。
已有业务 CONNECT 只唤醒调度，不会清除注册退避。正常连接数不足时仍立即按额度补足。

新增两个实际回环检查，覆盖等待 ACK 超过重试期限、反复唤醒仍只保留一个试探、
失败后的间隔、ACK 后补足缺口，以及业务 CONNECT 不绕过退避。
全量 **712 passed，无跳过**，使用 asyncio debug、Python dev 模式和 `-W error`；Ruff 和格式检查通过。

### 空池业务请求有界排队

Server 默认按同一 user 的 FIFO 队列等待资源，`queue_timeout=10` 秒，
`max_pending_connections=1024`。新资源仍随机选取，先原子预留给最早的请求再唤醒。
排队名额有独立上限，也计入 `max_connections`；有效队列上限保留一个注册接入位置。
超时或队列已满以一般失败拒绝，最大接入数已满仍直接关闭新连接。
超时、处理任务取消、资源交付竞态和服务关闭均回收名额与已预留资源。
排队不预读业务数据，保留 kernel socket 缓冲及合法写半关闭。

新增 14 项真实网络/内核检查，覆盖等待注册、超时后不误领后来的资源、FIFO、user 隔离、
全局队列限额、最大连接数及注册余量、取消/交付竞态、关闭宽限和 FD 回收。
包括实际 Agent 启动后接管已排队的 SOCKS 客户端请求，通过真实 splice 透传首包与响应。
既有立即拒绝测试显式设置 `max_pending_connections=0`，保留禁用排队时的行为检查。
全量 **739 passed，无跳过**，使用 asyncio debug、Python dev 模式和 `-W error`；
旧 SOCKS、DNS、Agent 退避与注册协商检查均通过。

### 预注册与业务共享 slot 配额

每 user 的占用改为 `max(注册连接数, 已接纳业务数)`，全局占用为各 user 的结果之和。
注册计数覆盖 HELLO/ACK、空闲及已领取连接；业务在入队/领取前就预占名额，
覆盖排队、目标协商和转发，直到结束或取消。超过 `max_resources` 或
`max_resources_per_user` 立即拒绝，不进入队列。新注册可覆盖已有业务名额，反之亦然。
因此同 user 的 32 条注册和 32 条业务计 32 个 slot；不同 user 的两组则计 64。
物理接入数量仍单独受 `max_connections` 约束。

新增 9 项真实网络检查，包含 per-user 配额 32 的 burst 拒绝、两种到达顺序、
满额配对不重复扣配额、不同 user 的全局占用、目标协商/转发期间保留名额、
超时/取消/队列满后的释放，以及交付竞态中的两侧配额与 FD 回收。
全量 **748 passed，无跳过**，使用 asyncio debug、Python dev 模式和 `-W error`；
Ruff 与格式检查通过。
