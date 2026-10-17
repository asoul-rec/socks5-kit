# 独立 reverse addon

已实现于 `socks5_kit.reverse`。采用预建、单次使用、按 SOCKS5 user 分组的反向连接池，
每次从同组的健康空闲连接中随机选择。仅支持 Linux 流式 TCP，运行时无第三方依赖。
注册包含一轮版本化 HELLO/ACK，只有完成这轮协商的资源才成为待用连接。

## 1. 核心设计

所有 Server / Agent 使用统一的注册标记域名，例如 `reverse.example.com`。
identity 由公网代理最终发给 Server 的 SOCKS5 username 表达，与注册域名分开。
Agent 提前经本地代理连接 `reverse.example.com:443`；公网代理按自己的来源/用户规则
选择 SOCKS5 出站及其 user，把请求交给 Server。Server 识别注册域名，先回复 SOCKS 成功，
再校验 Agent 的 HELLO 并回复 ACK，把 socket 放入该 user 的空闲资源池。
Agent 收到 ACK 后才认为公网已接受该资源，随后等待反向 CONNECT。

有业务请求时，Server 从相同 user 的池中独占领取一条 socket，在其已有字节流中发送目标 CONNECT；
取得资源并分配 pipe 后，Server 提前向业务端回复成功，让业务数据紧跟反向 CONNECT。
Agent 经本地代理连接该目标，在等待本机 SOCKS 回复期间就转发上行内容；
返回 SOCKS5 格式的 REP 后，两侧开启下行 splice。连接失败则关闭流。
Agent 收到请求时异步补充新的空闲连接；每条资源只承载一次业务，结束后销毁。

无需独立控制连接、REGISTER/OPEN/ATTACH 消息、ticket 或跨连接请求配对表。
socket 本身就是关联对象。Server 按 `dict[bytes | None, list[ReverseResource]]`
保存空闲资源，另保留建立/活动任务和数量上限。
不同 user 隔离；多个 Agent 可以向同一个 user 池提供资源，形成连接级冗余与分流。
一对一是只有一个 user 和一个 Agent 的特例，不再是接口限制。

## 2. 代理边界与接口

记公网代理为 `P_S`，内网代理为 `P_C`。所有 addon 连接端点都是相邻代理的本机端点；
终端协议、加密运输和真正访问目标仍由代理完成。

注册路径：

```text
Agent
  → 本机 P_C SOCKS5 入站：CONNECT reverse.example.com:443
  → P_C 配置的加密代理出站
  → 公网 P_S 传输入站
  → P_S SOCKS5 出站：使用配置的 user，CONNECT reverse.example.com:443
  → Server addon 的本机 SOCKS5 入口
```

这里有两段独立的 SOCKS 协商：Agent 与 P_C，以及 P_S 与 Server。
最初的 greeting/CONNECT 已被 P_C 消费，P_S 根据目标元信息重新生成它们。
Server 使用的是 **P_S → Server 这一跳**的 username；不推断 Agent 的源 IP，
也不假设 Agent → P_C 的 SOCKS 账户或加密协议的用户会自动变成这个 username。
这些身份如何映射，由 P_S 显式配置；注册流和相应业务流必须映射到相同的 user。
Agent 可以始终通过无认证的本机 SOCKS 请求注册，完全不知道最后的 identity。
SOCKS 出站账户配置参见 [Xray](https://xtls.github.io/config/outbounds/socks.html) 与
[V2Fly](https://www.v2fly.org/config/protocols/socks.html)。
因此公网侧必须使用保留 DOMAIN 目标的 **SOCKS5 出站**交给 addon；只做裸 TCP
转发不能自动把该域名带进 Server。注册域名也不能在到达 Server 前被解析成 IP 丢失。

Agent 将 HELLO 随本机 SOCKS CONNECT 一起发送，不等待本机 SOCKS 成功回复，
使代理立即拿到第一段 tunnel payload。这样兼容需要客户端首包才能完成出站的载体，
也避免在等待业务期间被误识别为已结束的空流。HELLO/ACK 完成后，载体仍须支持
长时间空闲以及服务端主动发送反向 CONNECT。

Server 只需监听一个本机 SOCKS5 端口：DOMAIN 目标匹配配置的注册域名时，加入
`pools[user]`；其他 DOMAIN、IPv4、IPv6 目标作为业务请求，从 `pools[user]` 领取。
注册域名按 DNS 名字的大小写/末尾点规则比较；username 则逐字节比较。
注册端口只服务代理路由和 CONNECT 格式，不用于区分 user，也不参与注册域名匹配。
注册域名在所有端口上均为保留用途，不能同时用作普通业务目的地。

Agent 访问实际业务目标时，也向 P_C 发普通 SOCKS5 CONNECT。注册与业务可以共用
一个本机 SOCKS5 入口，由 P_C 按目标配置不同出站；必要时使用不同本机入口隔离路由。
注册流去公网 Server，真实目标流走业务出站，不能再次回到同一 reverse 入口形成循环。

域名只是路由标记，不要求它对应公网 DNS 中的真实主机。现有 DNS 模块可提供需要的
解析，但 DNS 查询不触发入池或领取：查询次数与 TCP 连接次数没有一一对应关系。

“全局统一”指各组件使用同一个注册域名约定，不是进程全局或跨机器共享资源池。
每个 Server 实例拥有自己的 `pools`；同 user 的注册和业务须到达持有资源的 Server。

### user 的分组规则

沿用现有 SOCKS 凭据收集行为：客户端提供 `0x02` 就选 `0x02`，否则提供 `0x00` 就选
`0x00`，两者都没有则拒绝。`0x02` 子协商版本及帧完整时一律回复成功，不校验账号密码。
username/password 字段格式来自 [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)；
空字段沿用本项目的宽松接收规则。

池键为原始 `bytes | None`，不做 UTF-8 解码或大小写归一化：

- `0x00`：`user=None`，进入默认池。
- `0x02`：使用收到的 username；空 username 是 `b""`，与 `None` 区分。
- password 不参与分组；相同 username、不同 password 仍属于同一池。
- 空池或不存在的 user 按该组排队规则等待，超时或无法入队时回复失败；绝不借用其他 user 的池。

这里的 user 是分组元信息，不是 addon 认证。来源身份与访问权限由公网代理处理。
账户字段不会再随反向 CONNECT 发给 Agent，也不会冒充内网业务 SOCKS 的凭据。

| 最后一跳 SOCKS user | CONNECT 目标 | Server 行为 |
| --- | --- | --- |
| `b"team-a"` | `reverse.example.com:443` | 向 team-a 池提供一条资源 |
| `b"team-a"` | `service.example.com:443` | 从 team-a 池领取一条资源 |
| `b"team-b"` | `service.example.com:443` | 只从 team-b 池领取，不借用 team-a |
| `None` | 注册域名 / 其他目标 | 分别向默认池注册 / 从默认池领取 |

### 冗余和分流的范围

同 user 的新注册追加到资源列表，请求等概率随机选择一条空闲资源；同 user 注册
不视为冲突，也不替换已有资源。选择、移除及空闲监测的交接不跨 `await`。
移除时用末尾项填补空位并更新索引，正常领取和断连剔除均为 O(1)。
如果领取时发现已到达的 EOF、错误或不应出现的字节，剔除该项，再随机选择其他空闲项。
多个 Agent 只要提供同一组的资源，就能共同承接该组的新请求。

这按可用连接分流，不按 Agent 身份等权轮询。Server 不需要知道一条资源来自哪台
Agent；提供的可用资源占比越高，被选中的概率越高，不增加权重或负载上报协议。
同 user 的 Agent 应提供可互换的目标访问能力和路由语义；能力不同则用不同 user 分组。

冗余作用于新连接分配，已占用的流不会迁移。未及时发现的坏资源仍可能导致一次失败；
发出反向 CONNECT 后不自动重发到其他 Agent，保持第 4 节的一次性处理约定。

## 3. 注册、角色切换与字节格式

注册阶段和公网代理交给 Server 的业务请求，都使用完整 SOCKS5 协商。
两类连接都按上一节收集 user，不增加额外 identity 握手或密码校验。
仅支持 TCP CONNECT，BIND / UDP ASSOCIATE 回复 `0x07`。

注册域名匹配且 Server 的总额度和该 user 额度均允许时，先预留资源额度并完整发送 SOCKS 成功回复：

```text
05 00 00 01 00 00 00 00 00 00
   REP=0      BND.ADDR=0.0.0.0 / BND.PORT=0
```

这是 SOCKS 层回复，不是 addon 的注册确认，也不是业务目标成功。
Agent 经本机 SOCKS 协商时，使用 `Socks5Client.connect(..., initial_data=HELLO)`，
将下面的 HELLO 紧接本机 CONNECT 一起写出。中间代理消费 CONNECT，按路由重建目标，
把 HELLO 作为 tunnel payload 转交 Server。

addon 的注册帧固定为 6 字节：

```text
Agent → Server HELLO: 53 35 4b 52 01 01
Server → Agent ACK:   53 35 4b 52 01 02
                     └─ S5KR ─┘ │  └─ 消息类型：HELLO=1，ACK=2
                                └─ 协议版本：1
```

Server 精确读完并校验 HELLO，完整发送 ACK 后立即入池；资源预留和 ACK 写出之间不能
提前被业务领取。Agent 精确读取 ACK，版本、消息类型和 magic 均匹配后才进入 WAIT_CONNECT，
计入 `idle_connections`，并重置注册重试退避。仅收到本机 SOCKS 的 REP=0 时仍属于建立中。

HELLO/ACK 格式错误、EOF 或超时均关闭这条连接，Agent 后台退避补建，不回退到旧协议。
由于 SOCKS 成功已经发出，Server 不再追加一份 SOCKS 错误回复。等待 HELLO 的资源
照常占用总量和该 user 的额度，关闭后释放。两端 addon 必须一起升级到这份协议。

ACK 完成后，Server 不再发送其他字节，直到资源被领取。没有独立控制连接或持续心跳。

资源被领取后，Server 直接在隧道 payload 中发送一次完整 CONNECT 帧：

```text
05 01 00 ATYP DST.ADDR DST.PORT
```

Agent 的回复使用完整 SOCKS5 reply 格式：

```text
05 REP 00 ATYP BND.ADDR BND.PORT
```

这里的 `REP=0` 表示成功，其他值表示失败；线上不是只有一个 REP 字节。
成功回复中的 BND 可保留本机 SOCKS 代理提供的地址，不能当成业务 target。
失败时也生成完整回复，随后关闭当前资源。
反向 CONNECT 与 REP 的格式、注册 HELLO/ACK 及版本均保持原样，只提前发送上行业务数据。
Server 提前给业务端的成功回复使用 `BND=0.0.0.0:0`，此时尚不知道 Agent 的 BND；
Agent 的 REP 由 Server 消费，不作为业务数据转发，也不再向业务端追加第二份回复。

CONNECT 与 REP 的格式复用 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)。
“HELLO/ACK 后角色翻转、等待 CONNECT、不再做 methods 协商”是 addon 双方固定的约定；
这些反向帧对中间代理而言都是普通 tunnel payload。后续纯业务数据不再带 addon 帧。

### 本机 SOCKS 成功不一定代表远端已经完成

不能把 Agent 收到的本机代理 REP=0，严格解释为 Server 已经登记该资源。
例如 Xray 26.9.9 在 SOCKS handshake 中写出成功，随后才执行目标 dispatch。
[SOCKS handshake 源码](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/protocol.go#L207-L211)、
[调用顺序](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/server.go#L112-L150)。

所以注册使用独立 HELLO/ACK：本机代理提前回复成功并不能替代公网 addon 的 ACK。
Agent 的 WAIT_CONNECT 数量现在表示已获 Server 确认的资源，能够证明这条注册流到达了
公网 addon，并且该 addon 预留了资源、校验了协议，回程也可用。
这是一轮注册时的确认，不能保证连接未来始终健康，也不增加账户认证。
业务 REP 仍只能表达本地目标代理报告的结果，不能增强代理对真实目标的成功保证。
Server 提前给业务端的 REP 则表示已取得反向资源、可以提交数据，不保证目标已经建连。

## 4. 一次业务请求

1. 公网代理使用 SOCKS5 出站向 Server 提交真实目标；Server 完成方法/账户协商，取得 user 并读取 CONNECT。
2. Server 从该 user 的池原子领取一条空闲资源；空池时进入同 user 的等待队列。
   新资源优先分配给该 user 最早的等待请求，移出池并移交 socket 所有权。
   领取过程中不跨 await；空闲监测任务必须停止后，业务任务才能接管读写。
3. Server 先分配双向 pipe，向业务端提前回复 `REP=0, BND=0.0.0.0:0`，
   然后完整发送反向 CONNECT。没有业务内容也照常发送 CONNECT。
   上行 splice 随即启动，业务数据紧跟 CONNECT，不等待 Agent 的 REP。
4. Agent 精确读取 CONNECT，立即把资源计为占用并触发后台补池；同时调用本机
   SOCKS 代理。目标可为 DOMAIN、IPv4 或 IPv6，不在 addon 本地解析。
   本机方法协商完成后分配双向 pipe，完整写完本机 CONNECT，随即开启上行 splice，
   让业务数据在本机 REP 到达之前就进入代理。
5. 本机 SOCKS 返回成功后，Agent 写完整成功 REP，然后开启下行 splice。
   拒绝则回传对应 REP；超时或本机异常映射为失败，关闭当前资源。
6. Server 精确消费 Agent 的成功回复后开启下行 splice。
   收到失败、截断、超时或转发错误就关闭业务连接及当前资源，不追加失败回复。
7. 双向传输结束后关闭资源。失败、取消、EOF 后都不重新放回空闲池。

本机 SOCKS 回复与 ACK、ACK 与反向 CONNECT、业务 REP 与目标主动发送的 banner，
都可能紧邻或合包。
所有握手使用 raw socket 的精确读取，后续数据留在内核接收队列，避免预读导致 splice 丢数据。
向业务方发出成功之前完成 Server 的 pipe 分配。等待 REP 时只有上行 splice 工作，
下行 socket 仍由精确读取协商回复的任务独占；完整控制帧写出后才把该方向交给 splice。
切换阶段保留原 pipe 及其中待发送的数据，不另建 relay、不预读或缓存业务 payload。
socket/pipe 的背压自然限制内存，单次调度仍受现有 splice 预算约束。
上行半关闭先排空 pipe 再转发 EOF，仍可等待成功 REP 和下行业务响应。
若转发在协商期间失败，取消并等待对应的回复读任务结束，再关闭 socket，避免遗留 FD 监听。

配额检查、入队时的名额预占、随机领取、资源释放和补池退避完全沿用既有规则。
空池排队及准入失败仍未报告成功，可以正常回复 SOCKS 错误；只有取得资源后采用提前成功。
提前成功后的请求可能已经到达目标，失败以 EOF/连接重置表示，不承诺零字节交付。

如果 Server 已经发出反向 CONNECT，错误时首版直接结束该请求，不自动换另一条资源
重发：目标可能已经被连接，不能把结果未知当成请求从未发生。

## 5. 补池与数量限制

Agent 只需一个小的补池调度器，具体业务任务彼此独立。定义：

- `idle_connections`：希望保持的待用资源数量，例如 1。
- `max_connections`：本实例所有反向资源的总额度。

总额度包括 **正在建立（含等待 ACK）+ WAIT_CONNECT + 正在连接业务目标 + 正在转发**。
每启动一个注册任务先占额度；失败/关闭时释放。对应的本机业务 SOCKS socket 是该资源
所拥有的第二条 socket，不是另一个资源槽位。

只有“待用 + 正在建立”不足目标值，且总额度未满时，才创建补充连接。
收到反向 CONNECT、注册失败、空闲 EOF、业务完成都会触发检查。
补建失败需要有上限退避并独立重试，不能只等下一条业务请求，否则池耗尽后无法自恢复。
正常启动或消费资源时，调度器按额度并发补足缺口。进入退避后，每次到期只新建一条
注册连接；该连接完成 SOCKS/ACK 或失败前不再启动其他尝试。之前批次尚在建立的连接
会继续完成，调度器等待它们的结果。收到任一有效注册 ACK 后才退出退避，恢复并发补池。
已有连接上的业务 CONNECT 会唤醒调度器，但不会让注册重试绕过退避。

`idle_connections=1` 不意味着只能并发一个业务；不断补充可以产生多条活动连接。
`max_connections=1` 才会使这个实例串行：资源占用期间不再补建，结束后才补。
限制 Agent 提供资源确实无需增加线协议；多个 Agent 的额度分别生效，不能自动当作
某 user 的总额度。Server 用 slot 统一约束预注册连接和业务请求：

```text
R[user] = 正在注册 + 空闲 + 已领取/正在转发的注册连接
B[user] = 已接纳、正在排队 + 正在连接目标 + 正在转发的业务请求
slots[user] = max(R[user], B[user])
全局 slots = sum(slots[user])
```

`max_resources_per_user` 限制 `slots[user]`，`max_resources` 限制全局之和。
业务 CONNECT 在进入队列或领取资源之前就同步占用 B 名额，超额直接回复一般失败，
不再进入等待。新注册同步检查 R 名额，同样受限。两侧不重复扣配额：
同一 user 的 32 条注册和 32 条业务占 32 个 slot；没有注册时，32 条排队业务也占 32 个。
若 A 有 32 条注册而 B 有 32 条业务，因资源不能跨 user 共用，全局占 64 个 slot。

当业务先到且已经占满配额时，同 user 的注册仍可加入，直到 R 达到 B，期间不额外增加 slot。
预注册先到时，业务也可加入到同一额度。超过较大值的注册或业务仍立即拒绝。
配额覆盖整个生命周期：业务在超时、失败、取消或转发结束时释放 B；注册在关闭时释放 R。
两侧计数都归零时清理该 user 条目，不维护永久的用户注册记录。

对应 user 空池时，Server 把业务 CONNECT 放入该 user 的 FIFO 等待队列。
只保留连接、目标和等待状态，业务 payload 留在 socket 接收缓冲区，不在 Python 中额外缓存。
同 user 的新注册完成 ACK 后，资源随机领取并预留给最早的等待请求，再唤醒业务任务。
等待超时以一般失败 `REP=0x01` 拒绝；队列已满则立即拒绝。
`queue_timeout=10` 秒从读完业务 CONNECT、进入队列时起算；获资源后才开始独立的
`request_timeout`，不把排队时间算作 Agent 建立目标连接的时间。

排队连接计入 `max_connections`；所有 user 合计最多排队 `max_pending_connections=1024`。
同时必须满足上述全局/per-user slot 配额；队列容量较大不会扩大资源名额。
有效队列上限还取两者约束的最小值 `min(max_pending_connections, max_connections - 1)`，
为全是等待请求时的新注册留一个接入位置。其他握手、注册和活动业务同样占用最大连接额度，
接入已满时仍按原有规则关闭新连接。设置 `max_pending_connections=0` 可关闭排队，恢复空池立即失败。
`max_connections` 统计实际接入 socket，slot 统计可配对的逻辑名额；一条已配对业务有
业务 socket 和注册 socket 两个接入连接，因此仍需为两侧设置足够的总连接额度。

处理任务取消或超时会移出队列；领取与取消发生竞态时也会关闭已预留但未接管的资源。
Server 关闭时立即结束等待请求，宽限期只用于已经领取资源的业务。
排队期间的写半关闭保持为合法 EOF，后续照常透传。
调用方或相邻代理的 SOCKS 握手超时须覆盖排队，否则可能先于 Server 结束等待。
取得资源后的目标协商仍受既有期限限制，只是业务端已经收到成功，随后失败表现为断流。

## 6. 空闲存活、关闭与资源所有权

Server 资源状态：`SOCKS / HELLO / ACK 登记中 → IDLE → CLAIMED → RELAY → CLOSED`。
Agent 资源状态：`SOCKS / 等待 ACK 建立中 → WAIT_CONNECT → CONNECTING_TARGET → RELAY → CLOSED`。
每条资源都是单次使用，失败可从任何阶段进入 CLOSED，不从 RELAY 回到 IDLE。

Server 只把完整写完 ACK 的 socket 加入对应 user 池。空闲期间监测 EOF/错误并剔除资源；
领取与监测的所有权交接必须同步，不能让旧读任务偷走 Agent 的 REP。
同时设定接入握手、反向 CONNECT/REP、代理建连和回复写入超时。

预建流可能被 NAT、防火墙或代理自己的空闲策略关闭。处理方式保持简单：
配置代理允许足够的空闲时间，结合代理运输层保活和失效补建；必要时按配置淘汰过旧的
空闲资源。addon 到本机代理的 TCP keepalive 只检查这一跳，不能保证整个跨网流存活。
内核未报错的 socket 也可能遇到远端黑洞，最终由反向请求超时回收。

首版不向资源插入 PING/PONG；下一帧固定是 CONNECT，混入任意保活字节会破坏协议。
这种选择允许偶发领取失效资源失败，不承诺空闲池内所有连接永久可用。

业务半关闭沿用现有 splice：排空该方向 pipe，再向对端 SHUT_WR，保留反方向。
应用主动关闭时停止补建、关闭空闲资源，按 grace period 等待或取消已占用任务，回收 socket/pipe。
整个 reverse 路径的半关闭效果仍取决于两侧代理，已有版本限制见 [验证记录](validation.md)。

## 7. 延迟与吞吐

HELLO/ACK 给注册增加一次往返，后台补池时完成，不为每条业务额外增加握手。
当 Server 已有健康空闲资源时，注册、加密隧道建立、SOCKS 及 HELLO/ACK 已经完成，
不在当前业务的关键路径上。也不需要先发 OPEN，再等 Agent 建立返回连接。

热池命中后，Server 立即报告成功，把业务请求紧跟 CONNECT 送往 Agent；
Agent 向本机代理同样流水发送 CONNECT 和业务数据。反向 REP 不再阻挡上行请求。
从 Server 取得资源到首次业务响应的大致路径为：

```text
T ≈ RTT(Server ↔ Agent 现有隧道)
    + Agent 本机代理协商及目标建连/处理响应的时间
    + 本机调度/转发开销
```

这消除了“先等反向 REP 回到 Server，再把业务请求送往 Agent”的额外隧道往返。
请求/响应型业务正常只需一轮隧道往返；没有业务内容的 CONNECT 也会立即发出，
目标主动发送的 banner 在 REP 后照常传回。注册 HELLO/ACK 和反向报文均没有增加或改版。

这里的“一轮”描述隧道传输路径，实际首字节仍包含本机 SOCKS 方法协商、DNS、
目标 TCP 建连、代理内部处理及应用自身的等待。addon 不直接连接目标，也不能要求
中间代理在收到首包后立即发往尚未建立的目标；排队、坏资源及网络拥塞同样可能增加时间。

稳态仍为两侧各一组双向 Linux splice，不给业务数据增加帧头。代理内部的加密、
封装、内存复制以及是否使用 mux/连接池仍由代理决定；不能将 addon 局部 splice
等同于端到端零拷贝。每业务独立占用一条代理流，addon 自己不做 mux。

## 8. 使用接口

独立子包 `socks5_kit.reverse` 复用现有 `Target`、地址/CONNECT/REP 编解码、
`read_exact()`、`negotiate_server()`、`Socks5Client` 和 `SpliceRelay`，不改变已有 rewrite callback。
反向握手只读写 CONNECT/REP，不应调用会再次发送 methods 的完整 SOCKS 客户端握手。

默认注册域名是导出的 `DEFAULT_REVERSE_DOMAIN`，值为 `reverse.socks5-kit.invalid`。
也可显式指定其他域名，但双方以及代理路由必须一致。以下两个函数分别运行在公网端和内网端：

```python
from socks5_kit import Socks5Client, Target
from socks5_kit.reverse import (
    DEFAULT_REVERSE_DOMAIN,
    ReverseAgent,
    ReverseAgentOptions,
    ReverseServer,
    ReverseServerOptions,
)


async def serve_server() -> None:
    async with ReverseServer(
        options=ReverseServerOptions(max_resources_per_user=64),
    ) as server:
        await server.start(host="127.0.0.1", port=19000)
        await server.serve_forever()


async def serve_agent() -> None:
    async with ReverseAgent(
        Target(DEFAULT_REVERSE_DOMAIN, 443),
        Socks5Client("127.0.0.1", 1080),
        options=ReverseAgentOptions(idle_connections=2, max_connections=64),
    ) as agent:
        await agent.start()
        await agent.serve_forever()
```

构造不做 I/O。Server 的 `start()` 开始监听，`start(port=0)` 后可读 `server.address`。
Agent 的 `start()` 启动后台补池后立即返回，不等待本机或公网注册成功；
调用方可查看 `agent.idle_connections > 0`，判断是否存在已获公网 ACK 的待用连接。
`serve_forever()` 等待关闭，取消时也回收资源。
`await obj.aclose(grace_period=5)` 停止监听或补建、立即关闭空闲资源，给活动业务最多 5 秒，
随后取消并关闭剩余资源。异步上下文退出等同于 `aclose()`，默认立即关闭。
对象必须在同一 asyncio 事件循环中使用，关闭后不能重启。

Agent 的 `proxy` 用于注册和访问业务目标；可选 `egress_proxy=Socks5Client(...)`
仅替换访问业务目标的本机入口。两者都只连接指定的 SOCKS 代理，绝不直接连接业务目标。
Agent 不增加 identity 参数，由公网代理决定最终 SOCKS user。
Server 支持多个 user，但无需跨实例的 identity 注册表或 Agent 清单。

### 配置与计数

`ReverseServerOptions` 的默认值：

| 选项 | 默认值 | 含义 |
| --- | --- | --- |
| `handshake_timeout` | 10 秒 | methods、凭据、业务或注册 CONNECT 的总期限 |
| `registration_timeout` | 10 秒 | SOCKS 回复成功后等待完整 HELLO 的期限 |
| `queue_timeout` | 10 秒 | 空池业务请求在队列中等待资源的期限 |
| `max_pending_connections` | 1024 | 所有 user 的等待请求总上限，0 关闭排队 |
| `request_timeout` | 10 秒 | 写反向 CONNECT 并读取 Agent REP 的总期限 |
| `reply_timeout` | 5 秒 | 写完整成功或失败回复 |
| `max_connections` | 2048 | 所有接入 socket，包含握手、注册资源和业务入口 |
| `max_resources` | 1024 | 全局各 user 的 `max(注册数, 已接纳业务数)` 之和上限 |
| `max_resources_per_user` | `None` | 每 user 的 slot 上限，`None` 不额外限制 |
| `idle_timeout` | `None` | 从进入空闲池开始计时，`None` 不因空闲超时而淘汰 |
| `backlog` | 128 | 监听队列 |
| `ipv6_only` | `True` | IPv6 监听默认单栈 |
| `splice_byte_budget` | 262144 | 每方向单次调度的字节预算 |
| `splice_call_budget` | 8 | 每方向单次调度的 splice 调用预算 |

`ReverseAgentOptions` 默认 `idle_connections=1`、`max_connections=64`；
补建失败退避从 `reconnect_initial_delay=0.1` 秒指数增长到 `reconnect_max_delay=5` 秒。
这是失败后的重试等待时间，建连、SOCKS 和 ACK 的耗时另计；单纯连接数不足不会触发退避。
有效 ACK 重置注册退避；正常状态收到 CONNECT 后立即补池，退避期间只唤醒调度检查。
`registration_timeout=10` 秒限制
本机 SOCKS 成功后等待完整 ACK 的时间。`request_timeout=10` 秒从收到反向 CONNECT 的
首字节开始计算，只限制剩余请求帧，不限制等待业务的空闲时间；`reply_timeout=5` 秒。
访问本机代理的建连和握手期限由传入的 `Socks5Client` 配置，各默认 10 秒。
splice 两项预算与 Server 相同。数量须为正整数，超时须为有限正数，
Agent 的目标空闲数不能超过总额，最大退避不能小于初始退避。

Server 可读 `active_connections`（所有接入 socket）、`resource_count`（所有注册资源）、
`idle_connections`（所有组空闲资源）、`idle_count(user)`（指定原始 username 的空闲数），
以及 `pending_connections`（所有组等待资源的业务请求数，已包含在 `active_connections` 中）。
`business_connections` 包含等待、连接目标和转发中的业务；`slots_in_use` 是全局占用配额，
`slot_count(user)` 是指定 user 的占用配额。`resource_count` 仍只统计实际注册连接，
不会把等待业务伪装成已建立的注册连接。
`idle_count()` 只查询默认 `None` 组，不是所有组的合计。
Agent 可读 `connection_count`（所有反向资源）、`idle_connections`（已获公网 ACK、等待 CONNECT 的资源）、
`active_connections`（已收到完整 CONNECT、正在建业务连接或透传的资源）。
两侧计数不要求在每个瞬间相等：ACK 传播、领取、断连检测会造成短暂差异。

正常注册、业务请求、排队、资源领取及目标代理成功均有 INFO 访问日志；
DEBUG 另外记录补池决策、等待 ACK、退避和连接预算限制。
启用方式、各阶段耗时与池计数字段见 [访问日志与排队诊断](logging.md)。

## 9. 验证与范围

自动化检查覆盖：

1. HELLO 随 CONNECT 先发，只有完整 ACK 才确认就绪；假 SOCKS 成功、错误版本、
   错误帧、分片、合包、超时和关闭均不会误报待用连接。
2. 热池命中、空池排队、队列超时/满额、多请求原子领取、不同业务不串线；资源永不重复入池。
   多 user 隔离、不跨池回退；`None`、`b""`、大小写不同及非 UTF-8 username 各自分组；
   password 不影响分组，方法优先级沿用既有规则。
3. DOMAIN/IPv4/IPv6、提前成功的占位 BND、Agent 成功/失败 REP、完整 BND、分片/合包、目标主动 banner。
4. 收到请求立即补池、补建失败退避、空池自恢复、总额度覆盖所有状态、关闭期间停止补建。
5. 空闲 EOF、领取瞬间断连、黑洞超时、不重发已经提交的 CONNECT、取消和 FD/pipe 回收。
6. 同 user 的多个资源、随机领取、掉线资源剔除、其余资源继续接收新请求；
   全实例/每 user 额度与空组回收。
7. 多 MiB 业务内容及 EOF 在协商回复之前到达、双向半关闭、目标先发 banner，
   以及池满、失败、取消时的 socket/pipe 回收；控制帧不混入业务数据。

固定版本 Xray/V2Fly 的真实双侧代理拓扑、测试结果及复现方式见 [验证记录](validation.md)。
代理联调与模块测试分开记录；代理不支持的行为不会被模块的回环测试代替。

addon 只收集 SOCKS 账户元信息并按同 user 的空闲资源分流，不验证账户、不增加身份认证。
UDP、mux、Agent 权重/负载调度协议、活动连接迁移、UI 和自动修改代理配置均不在范围内。
