# SOCKS5 UDP 互操作调查：Xray、V2Ray、Shadowsocks

> 当前范围（2026-10-07）：优先实现 TCP，UDP 暂不支持。后续 UDP 采用宽进严出，
> 发向上游的 UDP 头始终 DOMAIN，ASSOCIATE 始终全零，不要求 NAT/FullCone 控制。
> 以下保留源码调查记录；其中待讨论的严格校验和兼容选项以
> [当前架构](architecture.md#6-后续-udp-契约未实现) 为准。


调查日期：2026-10-07。UDP 结论仍来自官方源码静态审计，尚未进行 UDP 联调或抓包测试。
TCP 实际程序联调已完成，结果见 [TCP 验证记录](validation.md)。
本文用于实现前讨论，结论不扩展到所有旧版本、GUI、fork、插件和出站协议组合。

关键结论：**UDP 回包可能带域名，也可能带 IP；一个客户端 UDP 源端点可以访问多个目标；
FullCone 还要求能收到未访问过的远端来源，不能只验证“多个目标使用相同端口”。**
调用方进一步限定：正向只能返回域名或拒绝，IP 回包直接返回，只有 DOMAIN 回包需要还原。
这项已确认规则及客户端归属说明见第 5 节；未据此实现 UDP 代理代码。

## 调查范围与证据

| 项目 | 核查范围 |
| --- | --- |
| Xray-core | [v26.9.9](https://github.com/XTLS/Xray-core/releases/tag/v26.9.9) 的 SOCKS、Freedom、UDP dispatcher、系统 dialer；另交叉检查 [v26.9.30](https://github.com/XTLS/Xray-core/releases/tag/v26.9.30)，快照 `b26a91de4f3294e26a0ad0a970b81a386a41f789`；两者发布页均标记为预发布 |
| V2Ray | 官方 V2Fly [v5.53.0](https://github.com/v2fly/v2ray-core/releases/tag/v5.53.0)，区分 SOCKS 入站 `packetEncoding=None/Packet/Stream`；未把 Xray 与 V2Fly 合并为同一实现 |
| Shadowsocks Rust | [v1.25.0](https://github.com/shadowsocks/shadowsocks-rust/releases/tag/v1.25.0)，快照 `ab388c7466d21f979430e33cc9ef10e22fb05955`；`sslocal` SOCKS 入口、UDP association、远端 `ssserver`，以及新加入的 SOCKS5 出站链调用点 |
| Shadowsocks libev | [v3.3.5 源码](https://github.com/shadowsocks/shadowsocks-libev/tree/v3.3.5) 作为历史兼容基准；交叉检查了 [v3.3.6 UDP 源码](https://raw.githubusercontent.com/shadowsocks/shadowsocks-libev/v3.3.6/src/udprelay.c) |

四个辅助文件只成功读取到官方 main/master：Xray `temp_udp_listen.go`、V2Fly
`app/proxyman/inbound/worker.go` 和 `transport/internet/udp/dispatcher_split.go`、
Rust SOCKS `socks5/udprelay.rs`。下文明确标注这些引用，
它们不是固定 tag 已逐行核验的证据。固定版本的相邻调用点已检查，但仍需运行时交叉验证。
“源码推论”表示从调用链推导出的行为，不表示已测得网络结果。

Shadowsocks 的角色需要分开：`sslocal/ss-local` 给应用提供 SOCKS5；
`ssserver/ss-server` 接收加密 Shadowsocks UDP，二者之间通常没有 SOCKS5 ASSOCIATE。
Rust v1.25.0 的可选 SOCKS5 出站链是另一条路径。[Rust association 创建路径](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/local/net/udp/association.rs#L38-L71)

## 1. 先分清四种地址

| 位置 | 地址的含义 |
| --- | --- |
| TCP 上的 UDP ASSOCIATE 请求：`DST.ADDR/DST.PORT` | 客户端预计发送 UDP 的源端点提示；不知道时填全零，不是最终目标 |
| TCP 上的 ASSOCIATE 成功回复：`BND.ADDR/BND.PORT` | 客户端应该把带 SOCKS 头的数据报发到哪个 UDP relay |
| 发往 relay 的 UDP 包头：`DST.ADDR/DST.PORT` | 当前这个数据报的最终目标；同一 association 的下一包可以不同 |
| relay 发回的 UDP 包头：仍叫 `DST.ADDR/DST.PORT` | 所查实现用它向客户端描述远端来源或回显逻辑目标；域名/IP 取决于具体路径 |

RFC 1928 要求远端回包套同一种 UDP 头，但没有规定“请求是域名，回复必须还原这个域名”。
它明确规定 association 随控制 TCP 结束，以及客户端来源 IP 的校验；端口限制可由实现选择。
[RFC 1928 §6–7](https://www.rfc-editor.org/rfc/rfc1928.html#section-6)

```text
应用 C:c  -- UDP，SOCKS 头目标 A:a -->  本地中继 L:l
本地 U:u -- UDP，SOCKS 头目标 B:b -->  上游 relay R:r
上游 E:e -- 裸 UDP ---------------->  真实目标 B:b

远端 D:d --> E:e --> R:r --> U:u --> L:l --> C:c
                      回包 SOCKS 头描述 D:d；改写中继再按 reverse 规则处理它
```

`C:c`、`U:u`、`E:e` 是三个不同层次的源端点。我们的 socket 固定 `U:u`，
并不保证上游代理及其 NAT 永远固定 `E:e`。

## 2. 域名请求，回包究竟是域名还是 IP？

### 2.1 Xray：直连路径会恢复“最初目标地址”，不是完整域名反向表

SOCKS 入站回复优先使用数据报携带的来源元数据 `b.UDP`；缺失时才回退到创建当前
link 时的请求地址。[SOCKS 回包编码](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/server.go#L174-L200)

在普通 SOCKS → Freedom 直连路径中，Freedom 保存初始拨号地址和解析后的 IP。
收到的真实源 IP 等于该初始 IP 时，地址替换回初始拨号地址，端口保留真实源端口。
所以初始请求为域名时，回包确实可以是 DOMAIN。
其他源 IP 则保留 IP。[Freedom PacketReader](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/freedom/freedom.go#L434-L500)

这是一个初始地址对，不是每个目标的反向 DNS 表。源码推论：同一活动 link 中，
第二个域名对应另一 IP 时通常回 IP；多个域名指向同一个初始 IP 时可能被标成第一个域名。
匹配只比较地址，不比较源端口。发送方向另有域名解析缓存，并不能消除这个歧义。
[Freedom PacketWriter](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/freedom/freedom.go#L504-L617)

SOCKS → SOCKS 链路中，Xray 出站直接保留上游回复头的 ATYP、地址与端口。
因此上游给 IP 就得到 IP，上游给域名就可以得到域名。
[SOCKS UDPReader/UDPWriter](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/protocol.go#L360-L412)

### 2.2 V2Fly：默认模式回显原目标，Packet 模式使用真实来源

默认 `packetEncoding=None` 使用按目标拆分的 dispatcher；回包上下文保留请求头，
SOCKS 服务端用原请求地址和端口编码回复。因此域名请求回域名，IP 请求回 IP。
这不是实际 `recvfrom` 来源的可靠描述：真实发送者若改变，仍可能被标成原目标。
[SOCKS dispatcher 与回包分支](https://github.com/v2fly/v2ray-core/blob/v5.53.0/proxy/socks/server.go#L205-L227)

固定版已核查选择 `NewSplitDispatcher` 和回包编码的调用点；按目标拆流的模式由官方
文档确认，dispatcher 保存逐目标上下文的内部机制仅核查 master。
[官方 None 模式](https://www.v2fly.org/en_US/v5/config/proxy/socks.html#socks-inbound)、
[master SplitDispatcher](https://github.com/v2fly/v2ray-core/blob/master/transport/internet/udp/dispatcher_split.go#L53-L115)

`Packet/Stream` 分支则从带地址的通道读取实际来源，回包不依赖逐目标请求上下文。
但同一 dispatcher **直接丢弃 DOMAIN 目标**，此处支持的是 IP 地址；不能以默认模式
能发域名为由，推断 FullCone 模式也能发域名。
[PacketAddrDispatcher](https://github.com/v2fly/v2ray-core/blob/v5.53.0/transport/internet/udp/dispatcher_packetaddr.go#L24-L44)

SOCKS 出站的普通读取路径解析回复头后只传 payload；Packet 路径保留来源，但构造成
`UDPAddr` 时直接取 `req.Address.IP()`。从代码推断，Packet 路径不能可靠处理 DOMAIN
回复，尚未运行确认具体失败表现。
[出站 UDPReader](https://github.com/v2fly/v2ray-core/blob/v5.53.0/proxy/socks/protocol.go#L386-L411)

### 2.3 Shadowsocks：普通远端路径回真实 IP 与端口

Rust `ssserver` 在远端解析目标域名；收包时取真实 UDP sender 的 `SocketAddr`，
据此编码 Shadowsocks 回复，所以普通直接出站中，域名请求通常回 IP 与真实源端口。
[远端解析与发送](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/server/udprelay.rs#L594-L665)、
[远端收包来源](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/server/udprelay.rs#L460-L500)

本地 association 把这个来源地址传给 SOCKS reply writer，不从出站域名恢复它。
writer 把收到的远端地址写入 SOCKS 头，并规范化 IPv4-mapped IPv6；writer 文件仅核查
master，不能声称该文件的 v1.25.0 已逐行验证。
[固定版 writer 调用点](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/local/net/udp/association.rs#L638-L649)、
[master SOCKS writer](https://github.com/shadowsocks/shadowsocks-rust/blob/master/crates/shadowsocks-service/src/local/socks/server/socks5/udprelay.rs#L88-L117)

libev 的远端也从 `recvfrom` 的真实来源构建头；本地解密后只补 SOCKS 的三个前导零字节。
因此普通域名请求同样回 IP。[libev 回包路径](https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.5/src/udprelay.c#L709-L777)

对我们的直接要求是：回复解析必须接受三种 ATYP，不能假定地址类型与请求一致。
按最新确认规则，IP 回包保留其原地址和端口，不做逆变换；DOMAIN 回包才以完整 Target
查反向 map 或调用 reverse。若上游已经合并或丢失来源信息，本模块不能凭空恢复。

## 3. 一个 association 承载什么？源端口会不会改变？

### 3.1 服务端：一个客户端源端点、多目标；共享 listener 不等于共享 association

| 实现 | UDP 监听与来源区分 | 控制 TCP 与 UDP 状态 |
| --- | --- | --- |
| Xray 所查版本 | 每个 ASSOCIATE 新建 port 0 listener，回复其实际端口；一条 association 可含多个目标 | TCP EOF 关闭 UDP；UDP inactivity 也能关闭 TCP |
| V2Fly | 配置的共享 UDP listener，按实际 UDP source 建立虚拟连接，再由 encoding 决定是否按目标拆分 | SOCKS 控制路径等待 TCP EOF；数据路径未见按该 TCP 注册/删除 association |
| Rust sslocal | 共享 UDP listener，manager 以实际客户端 `IP:port` 为 key，多个目标共享 context | ASSOCIATE 回复固定 relay 后等待 EOF；该函数未注册/删除 UDP manager 状态 |
| libev ss-local | 共享 listener，UDP cache 按实际客户端 source 和代理地址族区分 | TCP 与 UDP cache 路径分离 |

Xray 的独立监听和 TCP 生命周期已有固定版证据：
[创建与 BND 回复](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/protocol.go#L175-L211)、
[TCP/UDP 关闭关联](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/server.go#L155-L170)。
其 source IP/port 校验实现只核查到 main：预期端口为 0 时由符合预期 IP 的首包锁定，
随后其他 source tuple 被丢弃。[main TempUDPConn](https://github.com/XTLS/Xray-core/blob/main/proxy/socks/temp_udp_listen.go#L28-L52)

V2Fly 固定版证实 TCP 控制与 UDP handler 分支分离；按 source 建虚拟连接的 worker
仅核查 master。这支持“UDP 状态没有绑定到某条 ASSOCIATE TCP”的源码推论，
TCP 关闭后是否仍可发包应列入实测。
[固定版 SOCKS handler](https://github.com/v2fly/v2ray-core/blob/v5.53.0/proxy/socks/server.go#L50-L71)、
[控制 TCP 等待](https://github.com/v2fly/v2ray-core/blob/v5.53.0/proxy/socks/server.go#L124-L164)、
[master UDP worker](https://github.com/v2fly/v2ray-core/blob/master/app/proxyman/inbound/worker.go#L237-L282)

Rust 的固定版 SOCKS 控制函数与 association manager 显示同类分离，libev 也如此。
[Rust ASSOCIATE](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/local/socks/server/socks5/tcprelay.rs#L264-L281)、
[Rust source key](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/local/net/udp/association.rs#L120-L204)、
[libev 控制路径](https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.5/src/local.c#L254-L325)

共享 UDP 监听端口本身符合协议；未把 source 检查和状态关闭绑定到控制 TCP，才与
RFC 模型不同。不能根据共享 listener 推断多个独立客户端使用同一个逻辑 association，
也不能让所有客户端共用我们的反向缓存。

### 3.2 客户端：同一 socket 内固定 source；是否创建多个 socket 取决于上层分流

| 出站路径 | 目标改变时怎样发包 |
| --- | --- |
| Xray SOCKS client | 一次 `Process` 建一条控制 TCP 和一个 UDP socket，逐包用 `b.UDP` 指定目标；该 socket 存续期间外层 source port 固定 |
| V2Fly SOCKS client，普通/None 路径 | 一次 `Process` 内目标固定、socket 固定；默认入站按目标拆流，换目标通常另开 `Process`、ASSOCIATE 和 UDP socket |
| V2Fly SOCKS client，Packet 路径 | 一条带地址通道复用一条 ASSOCIATE 和 UDP socket，逐包 `WriteTo` 携带不同 IP/port |
| Rust sslocal 的普通 SS 路径 | 每个实际客户端 source context 保存一个 `proxied_socket`，不同目标复用；传输是 SS UDP，没有 SOCKS ASSOCIATE |
| libev ss-local 的普通 SS 路径 | 同客户端 source 和 SS 服务器地址族命中同一 cache，目标变化不导致重建该 SS socket |

依据：[Xray SOCKS Process](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/client.go#L97-L159)、
[V2Fly 两条 UDP 分支](https://github.com/v2fly/v2ray-core/blob/v5.53.0/proxy/socks/client.go#L155-L206)、
[V2Fly 模式定义](https://www.v2fly.org/en_US/v5/config/proxy/socks.html#socks-inbound)、
[Rust 复用与错误重建](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/local/net/udp/association.rs#L600-L631)、
[libev UDP cache](https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.5/src/udprelay.c#L1059-L1164)。

Rust v1.25.0 的全 SOCKS5 出站链，每个 peer context 创建并保存一个 chain datagram，
后续目标复用。只核实了 `associate_udp()` 调用点；每层握手中的来源 hint、relay 地址修复
和底层源端口细节尚未核实。[chain 创建路径](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/local/net/udp/association.rs#L38-L71)

因此，一个 association 可以承载一个 source endpoint 的多个 destination；
不同应用 source port 应视为不同客户端 UDP 状态。Xray 会 pin source port；
V2Fly/SS 的共享 listener 可以为不同 source 独立建状态，这不构成可移植的“同一
ASSOCIATE 任意换 source port”承诺。空闲、错误、淘汰、出口地址族或路由变化仍可能换端口。

### 3.3 一个会直接影响兼容性的非标准请求

用一个独立示例说明“目标填进来源提示”。设 V2Fly 客户端 C 实际从
`192.0.2.10:53000` 发 UDP，想访问远端 `198.51.100.20:9000`：

| 报文位置 | 正常含义/填写 | 所查 V2Fly 普通出站路径的填写 |
| --- | --- | --- |
| 控制 TCP 的 ASSOCIATE 地址字段 | 声明客户端 UDP source `192.0.2.10:53000`；未知则 `0.0.0.0:0` | 填远端目标 `198.51.100.20:9000` |
| UDP 数据报里的 SOCKS 地址字段 | 真正目标 `198.51.100.20:9000` | 仍是远端目标，填写正常 |

于是服务端如果把控制请求当作真实来源声明，会期待从 `198.51.100.20:9000` 收 UDP，
实际却从 `192.0.2.10:53000` 收到。问题发生在控制请求中的字段复用，
不是实际网络包伪造了源 IP，也不是最终目标没有写进数据报。

Xray SOCKS client 为 UDP ASSOCIATE 发送 `0.0.0.0:0`，符合未知来源的协议约定。
V2Fly v5.53.0 则把出站 request 的目标地址/端口直接写进 ASSOCIATE，没有替换成客户端
source hint；Packet 路径也沿用该握手。严格按来源 hint 校验的服务器可能拒绝其实际 UDP。
[Xray ClientHandshake](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/protocol.go#L458-L497)、
[V2Fly request 初始化](https://github.com/v2fly/v2ray-core/blob/v5.53.0/proxy/socks/client.go#L91-L120)、
[V2Fly ClientHandshake](https://github.com/v2fly/v2ray-core/blob/v5.53.0/proxy/socks/protocol.go#L508-L517)

这里的正常来源提示含义来自 [RFC 1928 §6](https://www.rfc-editor.org/rfc/rfc1928.html#section-6)。

Xray 所查服务端对 DOMAIN/unspecified hint 改用 TCP peer IP，对具体 IP hint 则采用请求
IP/port。源码推论：V2Fly 发送域名 hint 的场景较兼容；把最终目标 IP 当 hint 时仍会与
实际客户端 source 冲突，不能声称这两个项目彼此任意配置都兼容。
[Xray expectedRemote 构造](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/protocol.go#L197-L205)

### 3.4 共享监听怎样找到应接收回包的客户端？

共享入站 UDP socket 用 `recvfrom` 获得实际客户端 source，再给各个 source 分配独立
context。Rust manager 的 key 是 `SocketAddr`，context 保存 `peer_addr` 和自己的
代理 socket；回包从该代理 socket 收到后，交给保存的 peer。
[Rust manager key](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/local/net/udp/association.rs#L120-L191)、
[context 与回包目标](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/local/net/udp/association.rs#L273-L289)、
[回包 writer](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/local/net/udp/association.rs#L638-L649)

V2Fly 所查 master worker 同样以 source 建虚拟连接，保存的 output closure 直接向
`id.src` 写回；透明代理场景可额外包含 original destination，普通 SOCKS 不靠内层
最终目标选择客户端。此 worker 仍只有 master 证据。
[master worker source/output](https://github.com/v2fly/v2ray-core/blob/master/app/proxyman/inbound/worker.go#L244-L281)

我们的 A（下游客户端）、M（本模块）、B（上游 SOCKS5）链路应分成：

```text
A1:port1 -> M context 1 -> 上游 socket U1 -> B
A2:port2 -> M context 2 -> 上游 socket U2 -> B

B -> U1 收到回包 -> context 1 -> A1:port1
B -> U2 收到回包 -> context 2 -> A2:port2
```

B 可以使用同一个 UDP relay 监听地址；M 的 U1/U2 仍须构成不同的上游 UDP 端点，
并各自持有控制 TCP/association。回包从哪个 U socket 收到已经确定了 A，
内层远端地址只用来描述来源、执行头还原，不能拿它查找客户端。

FullCone 允许任意远端给某个 context 的出口发包，并不允许任意客户端共用该 context。
同一个 A UDP 会话的所有目标复用一个 association；不同 A 会话分别建立。
共享入站 listener 是监听资源的复用，不是客户端状态、上游 association 或反向 map 的合并。

## 4. FullCone 如何工作？

### 4.1 需要分别看映射与收包

这里用 FullCone 描述两个应用所需性质：同一客户端 UDP source 的不同目标复用出口
端点，以及其他远端也能向该端点发包。RFC 4787 分别称为 endpoint-independent mapping
和 filtering；它指出传统 cone 分类不足以描述实际 NAT。
[RFC 4787 术语与映射](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.1)、
[过滤行为](https://www.rfc-editor.org/rfc/rfc4787.html#section-5)

例如先向 `A:a` 发包，之后此前未访问的 `B:b` 向同一个出口端口发送数据。
链路应把它作为来自 `B:b` 的包交给应用。只能收到 A 的回复，或把 B 标成 A，
都不能满足这个需求。它仍是原客户端 association 的入站包，不需要为 B 新建 ASSOCIATE。

### 4.2 所查实现的机制与选项

**Xray**：core 默认 `cone=true`，`XRAY_CONE_DISABLED=true` 可关闭；这是 core 上下文
开关，不能据此虚构 SOCKS 配置里的 `fullCone` 字段。
[core 默认值](https://github.com/XTLS/Xray-core/blob/v26.9.9/core/xray.go#L175-L180)、
[环境变量名](https://github.com/XTLS/Xray-core/blob/v26.9.9/common/platform/platform.go#L15-L19)

所查 UDP dispatcher 只持有一个活动 link，多目标复用它；系统 dialer 使用
`ListenPacket`，Freedom 按每包目标 `WriteTo`、以 `ReadFrom` 保留来源。
出口 socket 存续时可复用端口，并接收其他远端。内部 link 有自己的 inactivity 生命周期，
即使控制 TCP 仍存在，也可能重建出口 socket；活动 link 也复用其初始路由选择。
这些是默认直接路径的源码推论，仍受 `finalRules`、网络防火墙与 NAT 影响。
[单活动 link 与超时](https://github.com/XTLS/Xray-core/blob/v26.9.9/transport/internet/udp/dispatcher.go#L43-L100)、
[系统 UDP socket](https://github.com/XTLS/Xray-core/blob/v26.9.9/transport/internet/system_dialer.go#L47-L89)

关闭 cone 改变入站传给 dispatcher 的名义目标；当前 dispatcher 仍复用单个活动 link。
不能据此声称“关 cone 就必定每目标换源端口”。Freedom 目标 override 路径还可能省略
来源元数据，回退到请求目标，从而损坏真实来源语义。
[入站 cone 分支](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/server.go#L249-L255)、
[Freedom override 回包分支](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/freedom/freedom.go#L484-L495)

若走 VMess/VLESS 等远端出站，还要检查 UDP/XUDP 模式；本地 SOCKS 能保存来源不代表
任意远端链路也能保存。Xray 文档说明 `xudpConcurrency` 及 UDP/443 的 reject/allow/skip
选项；FullCone 测试必须记录实际出站配置。
[Xray Mux/XUDP 配置](https://xtls.github.io/config/outbound.html#muxobject)

**V2Fly**：v5 的 SOCKS `packetEncoding` 默认 None，为每个目标分别映射；Packet
可通过兼容出站恢复为共享、带地址的 UDP 通道。Stream 自 v5.53.0 起提供流中带地址和
长度的分帧，也需要兼容出站。两者在 SOCKS 入站都经过上述 IP-only dispatcher；
不能由配置文档推断所有出站都支持 Stream，也不能把所有 V2Ray 都判为无 FullCone。
[官方模式定义](https://www.v2fly.org/en_US/v5/config/proxy/socks.html#socks-inbound)、
[Freedom 对 Packet 地址的处理](https://github.com/v2fly/v2ray-core/blob/v5.53.0/app/proxyman/outbound/handler.go#L243-L249)

**Shadowsocks Rust/libev**：原生远端 UDP 路径按客户端状态复用未连接到某个最终目标的
socket，使用 sendto/recvfrom；所查路径未按“已访问的目标”建立回包白名单。
由此推断具备接收新远端的机制，实际可达性仍取决于部署网络。
Rust v1.25.0 配置解析中未发现 FullCone 选项，不能据此断言所有包装器都没有该开关。
[Rust socket 创建](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks/src/net/udp.rs#L151-L156)、
[Rust 配置解析](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/config.rs)、
[libev 出站 socket 与 cache](https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.5/src/udprelay.c#L1174-L1258)

Rust 有 IPv4/IPv6 两个出站 socket 槽位，但支持 IPv4-mapped IPv6 时先把 IPv4 转成
IPv6，常能共用 IPv6 槽位；栈能力不同则可能分开。libev 的 key 包含地址族，域名未解析
时还可落入 AF_UNSPEC。两者都不能无条件承诺所有域名、IPv4、IPv6 共享同一出口端口。
[Rust 归一化与槽位](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/server/udprelay.rs#L605-L647)、
[libev family key](https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.5/src/udprelay.c#L1059-L1063)

Rust AEAD 2022 的远端状态按 client session ID 区分，允许更新外层 peer 地址；
经典模式则按 peer IP/port 区分。这个 session ID 属于 Shadowsocks，不是 SOCKS5 的能力，
不能用它推断我们的 SOCKS 客户端可以随意换源端口。
[Rust peer 更新](https://github.com/shadowsocks/shadowsocks-rust/blob/v1.25.0/crates/shadowsocks-service/src/server/udprelay.rs#L543-L550)、
[SIP022 UDP](https://shadowsocks.org/doc/sip022.html#_3-2-udp)

### 4.3 外层连接固定 relay，不会因此破坏 FullCone

我们作为 SOCKS client，可以把 UDP socket connect 到固定的上游 relay `R:r`，
让内核只收它的外层包。远端 `A:a/B:b` 的区分在 SOCKS 头里，不在该外层 IP 头里。
应保留并解析内层来源；不能以“内层来源不是先前请求目标”为理由拒绝所有新来源。

最终面向互联网的 UDP 出口若 connect 到单个真实目标，则会限制其他远端收包；
上述 Xray Freedom 和 SS 原生远端路径使用的是未 connect 的 packet socket。
另外，多宿主 relay 必须从客户端期待的 relay 地址回包；需要实测 wildcard 绑定的
source IP 选择，不能只看 SOCKS 内层头。

## 5. 对我们模块的设计建议

本节按调用方最新确认的规则更新。本文中 A 是下游客户端，M 是本模块，B 是外部
SOCKS5 服务器；地址改写不是客户端会话的归属表。尚未据此实现代码。

### 5.1 已确认的 map 与拒绝规则

| 路径 | 行为 |
| --- | --- |
| A → M → B | A 的目标可为 IPv4/IPv6/DOMAIN；rewrite 成功必须给 DOMAIN + port，或明确拒绝 |
| B → M → A，SOCKS 头为 IPv4/IPv6 | 通过协议/上游来源校验后，ATYP、IP、port、payload 原样返回所属 A；不查缓存，不调用 reverse |
| B → M → A，SOCKS 头为 DOMAIN | 先查当前 association 的有效 reverse_map；命中则恢复原完整 Target |
| DOMAIN 回包缓存未命中/过期/淘汰/禁用 | 有 reverse 则调用；无 reverse 或 reverse 拒绝/失败则丢当前包 |

正反向 callback 均支持同步/异步 `Target | None` 返回；`None` 明确表示拒绝，
也支持已有的 `RejectTarget` 异常。正向返回 IP 属于非法结果，不能视为成功或原样放行。
反向只收到 DOMAIN 输入，但可返回原先的 IP 或 DOMAIN。
TCP 正向拒绝回复 SOCKS `0x02` 并关闭，不连上游；UDP 正向/反向拒绝只丢当前包，
不关闭 association，不创建 binding、负缓存或刷新映射 TTL。

反向键仅有改写后的 DOMAIN + port，不建立 IP 别名。`udp_cache_ttl <= 0` 时仍每包
rewrite；DOMAIN 回包依赖 reverse，IP 回包照常透传。IP 回包无法定位某条 binding，
不刷新 binding TTL，但成功转发可刷新 association 的独立活跃时间。

### 5.2 Association 与兼容策略

下表中来源提示、wildcard BND 和具体模拟形式仍是兼容建议，尚未作为额外已确认规则。

| 项目 | 建议 |
| --- | --- |
| UDP 粒度 | 一条下游控制 TCP 对应一条本地/上游 association；一个下游 source 的多目标复用同一个上游 UDP socket，不按目标另开 socket |
| source hint | 为 V2Fly 提供兼容策略：忽略 ASSOCIATE 中声称的 source 地址/端口，以控制 TCP peer IP 和首个合法 UDP 包 pin source；保留严格 hint 校验作为显式策略 |
| 上游握手 | 我们发送 `0.0.0.0:0`；后续不随目标改变外层 source port |
| wildcard BND | 建议兼容上游 `0.0.0.0/::` 回复，保留 BND.PORT、改用已连接的上游 TCP peer IP；其他不可达地址不猜测 |
| cache TTL | 只使正向/反向 Target binding 过期，绝不能因此重开上游 socket 或更换端口；association 生命周期另管 |
| reply metadata | 每包解析完整 ATYP/地址/端口；IP 原样返回，DOMAIN 才还原，不用“最近一次目标”覆盖来源 |
| source 隔离 | 不同下游 source/context 使用独立反向 map；不因共享 listener 或同 IP 就合并 |
| 模拟行为 | 推荐先采用当前 Xray 式独立 UDP listener、TCP 生命周期，再兼容 V2Fly hint；若要复制 V2Fly/SS 的共享 listener 与弱 TCP 绑定，需单独定义模拟模式 |

wildcard BND 兼容有现成依据：Xray/V2Fly SOCKS client 均把 AnyIP/AnyIPv6 改为代理
服务器地址。这是已知 relay 的兼容修复，不是把最终目标域名解析成本地 IP。
[Xray SOCKS client](https://github.com/XTLS/Xray-core/blob/v26.9.9/proxy/socks/client.go#L101-L105)、
[V2Fly BND 修复](https://github.com/v2fly/v2ray-core/blob/v5.53.0/proxy/socks/client.go#L143-L147)

### 5.3 FullCone 在新规则下的边界

此前“所有来源都必须还原”的规则已被替代。新的 IP 来源没有历史改写记录，也能
由所属上游 socket 确定应交给的 A；直接转发即可，不再因 reverse map miss 被丢弃。
DOMAIN 来源仍要能还原：缓存未命中且 reverse 拒绝时丢包，因此不能保证任意 DOMAIN
来源均被接受。上游如何表示来源仍会影响结果。

IP 透传是调用方选定的策略，不等于 DNS 解析后的 IP 在逻辑上绝不可能关联域名；
本项目明确不推断这类关联，也不把该 IP 强行恢复为 A 原来的目标。

**固定版本的实际兼容限制：出站总是 DOMAIN，与 V2Fly v5.53.0 SOCKS 入站的
Packet/Stream 路径不兼容**，该 dispatcher 直接丢弃域名目标。
None 模式可接受域名，但按目标拆流，不能指望它提供同一多目标出口的 FullCone。
要保留新规则并继承 FullCone，必须选择支持 DOMAIN 多目标 UDP 和完整来源信息的
上游路径，例如所查 Xray 的普通 SOCKS → Freedom 路径；完整链路仍需实测。
[V2Fly DOMAIN 丢弃分支](https://github.com/v2fly/v2ray-core/blob/v5.53.0/transport/internet/udp/dispatcher_packetaddr.go#L24-L34)、
[官方模式定义](https://www.v2fly.org/en_US/v5/config/proxy/socks.html#socks-inbound)

我们的能力表述为：保持各客户端独立的上游 association、多目标 socket 复用、
IP 来源透传和 DOMAIN 来源按规则还原；端到端 FullCone 取决于上游与 DOMAIN 还原策略。

## 6. 实现前后的互操作验证矩阵

下面是后续运行与抓包计划，本次没有执行。应固定二进制版本、出站协议/配置、地址族、
socket timeout 和网络拓扑；不要只记录应用返回“UDP 正常”。

| 场景 | 需要观察/断言的内容 |
| --- | --- |
| 一个 source 依次向两个 IP、同 IP 不同端口发送 | 控制 TCP/ASSOCIATE 数量，客户端外层 source、代理真实出口 source，回复实际来源 |
| 两个客户端 UDP source，含同 IP 不同端口 | 状态和反向 map 分离；Xray pin 行为与共享 listener 行为的差别 |
| 域名首目标、第二域名、两个域名同 IP、同域名多 IP | 双方向 ATYP/地址/端口；Xray 初始域名回填、V2 None 回显、SS IP 回复 |
| V2Fly None/Packet/Stream | IP/domain 是否转发；每目标是否拆 ASSOCIATE；具体出站是否支持该 encoding |
| V2Fly 具体 IP 目标作为 ASSOCIATE hint | 我们兼容策略能否接收实际 source；严格策略的失败结果 |
| 未访问的远端 IP 和未访问的远端端口主动发包 | 映射稳定与过滤独立分别验证；IP 头原样返回所属 A，不查 map、不调 reverse；DOMAIN 来源走还原/拒绝规则 |
| rewrite TTL 到期而 association 仍存活 | binding 过期；我们上游 socket/端口不变；IP 回包照常返回，DOMAIN 按 reverse/drop 规则处理 |
| 正反向拒绝、正向非法返回 IP | None/RejectTarget 拒绝 TCP 请求或丢当前 UDP 包，不建 binding/负缓存；非法 IP 结果不发给 B |
| 多个 A 从同一个新远端收到相同来源头的回包 | 按收到回包的独立上游 socket 确定 A，不用远端 Target 或反向 map 分客户端 |
| UDP 静默、出口 link 重建、TCP 分别关闭 | 出口端口是否变化、UDP 状态是否继续、FD 和缓冲是否回收 |
| 上游 BND 为 wildcard、多宿主 relay、IPv4/IPv6/mapped | relay 地址修复、外层回包 source、地址族转换及出口端口范围 |
| 回包源端口改变、迟到包、非零 FRAG、截断和零 payload | 元数据、丢包原因、边界保持；记录不同项目的宽松/严格行为 |

FullCone 测试至少需要一个不同远端地址/端口的主动 sender；普通同目标 UDP echo
只能验证往返。STUN 行为探测也区分映射与过滤，应使用支持相应测试的端点。
[RFC 5780 行为探测](https://www.rfc-editor.org/rfc/rfc5780.html)

## 7. 尚未证实的边界

- 四个仅 main/master 可读的辅助文件，需要下载固定 release 源码后补充核对。
- Rust SOCKS5 出站链逐层握手、收包过滤、源端口与 relay 地址处理尚未逐行核实。
- V2Fly Packet 路径收到 DOMAIN 回复的具体失败方式，以及 Stream 与各出站的组合，尚未运行验证。
- 多宿主、双栈、外部 NAT、防火墙、XUDP/其他出站链的端到端行为，需要按实际部署测试。
- 以上是互操作事实和设计建议；当前 Python 项目仍是骨架，没有开始代理实现。
