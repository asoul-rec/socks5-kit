# 访问日志与 reverse 排队诊断

所有模块使用 Python 标准 `logging`，logger 名称位于 `socks5_kit` 下。
库不调用 `basicConfig()`，不添加 handler，也不修改调用方的日志级别。
正常连接、注册和 DNS 回复使用 INFO；握手过程、补池决策和正常关闭细节使用 DEBUG。
明显异常使用 WARNING / ERROR，因此只启用 WARNING 时仍能看到故障和容量问题。

| 级别 | 使用场景 |
| --- | --- |
| DEBUG | 握手进度、正常关闭、补池决策及该决策相关的池快照 |
| INFO | 成功访问、正常空闲断连、重连调度，以及明确的策略拒绝或不支持的操作 |
| WARNING | 配额或队列已满、连接或握手超时、上游拒绝连接、格式错误及注册 ACK 无效 |
| ERROR | 意外的内部异常，例如不应发生的 `RuntimeError` / `TypeError` |

已经开始透传后，常见的连接中断仍按普通状态处理：reverse 使用 INFO，
rewrite 中继使用 DEBUG；正常空闲 EOF 也不提升为告警。
失败级别不会改变协议回复、重试或资源释放行为。WARNING / ERROR 仍只记录异常类型和
相关事件字段，不附加异常的任意消息内容或业务数据。
空闲资源收到不应出现的数据或 socket 错误使用 WARNING；
接入循环或 Agent 补池管理任务意外退出使用 ERROR。

## 启用

在应用初始化时配置，例如：

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

# 排查 reverse 排队时额外启用池调度和握手细节。
logging.getLogger("socks5_kit.reverse").setLevel(logging.DEBUG)
```

已有日志配置时，复用自己的 handler；其级别也需要允许希望输出的 INFO/DEBUG。
仅设置 logger 的级别不会替应用创建输出 handler。

| Logger | 正常访问记录 |
| --- | --- |
| `socks5_kit.client` | SOCKS 代理端点、目标、返回的 BND、建连及协商总耗时 |
| `socks5_kit.server` | 来源端点、原目标、改写目标、上游代理、允许及建立成功 |
| `socks5_kit.dns` | UDP/TCP、来源、查询域名、查询类型、RCODE、回答数量及处理耗时 |
| `socks5_kit.reverse._server` | 注册、业务请求、入队、领取、提前接受及 Agent 回复成功 |
| `socks5_kit.reverse._agent` | 注册确认、收到反向 CONNECT、本机目标代理成功及重连退避 |

时间使用单调时钟计算，`elapsed_ms` / `wait_ms` / `duration_ms` / `idle_ms` /
`retry_in_ms` 的单位均为毫秒。
DNS 中的 `qtype` 和 `rcode` 是协议数值，例如 A=1、AAAA=28、CNAME=5，
NOERROR=0、NXDOMAIN=3。回答数量来自实际回复报文。
日志不输出密码、业务 payload、callback 的任意异常消息或无效返回对象。
日志会包含访问目标和 reverse username；username 用 Python bytes 的转义表示，
保留 `None`、`b""`、大小写及非 UTF-8 内容之间的区别。

## reverse 的关键事件

reverse 日志包含 `event=...`，同时通过 `LogRecord` 的额外字段提供相同字段，
可用于调用方的结构化 handler。每条记录只包含与当前事件相关的信息：
成功访问不重复输出池快照和配置，不附加无关的 `target=None`、`stage=None` 等字段。
`user=None` 表示默认组，属于有效的身份信息，会保留。
标识只用于本进程日志，不写进隧道协议。
同一 Server 请求的 `server_id + connection_id` 一致；其 `resource_id` 可关联到
注册记录。Agent 使用独立的 `agent_id + resource_id`，不能把双方的数值视为同一个 ID。

Server 的业务访问记录以 `server_id`、`connection_id`、`user`、`target` 为基础，
只有实际取得资源后才增加 `resource_id`。Agent 的资源记录以 `agent_id`、`resource_id`
为基础；只有收到业务 CONNECT 后才包含 `target`。

| 访问与故障事件 | 含义和事件专属字段 |
| --- | --- |
| `reverse_registered` | Server 已校验 HELLO、写出 ACK 并发布资源；包含注册目标、资源标识和 `elapsed_ms` |
| `reverse_agent_registered` | Agent 已验证公网 ACK；仅资源标识和 `elapsed_ms` |
| `reverse_business_requested` | Server 已读完业务 CONNECT，尚未保证通过配额检查 |
| `reverse_business_queued` | 已占业务名额等待资源；增加 `user_pending`、`queue_timeout` |
| `reverse_resource_claimed` | 取得资源；增加 `wait_ms`，热池命中时通常很小 |
| `reverse_business_accepted` | 已向业务端提前回复成功；增加 `elapsed_ms`，尚不表示目标代理成功 |
| `reverse_agent_business_requested` | Agent 收到完整反向 CONNECT，开始经本机代理访问目标 |
| `reverse_agent_target_connected` | Agent 的本机目标 SOCKS 代理已回复成功；增加 `elapsed_ms` |
| `reverse_target_connected` | Server 已完整消费 Agent 的成功 REP；增加 `elapsed_ms`，随后开启下行透传 |
| `reverse_session_failed` / `reverse_agent_resource_failed` | 按上述异常分类选择 INFO / WARNING / ERROR；包含标识、已知目标及 `stage`、`error_type`、`elapsed_ms` |
| `reverse_agent_idle_disconnected` | 空闲资源已断连；仅资源标识和 `idle_ms` |
| `reverse_agent_retry_scheduled` | INFO，安排注册重试；仅 `agent_id` 和 `retry_in_ms`，具体失败级别见对应失败事件 |

例如，Agent 注册完成的记录只需：

```text
event=reverse_agent_registered agent_id=... resource_id=42 elapsed_ms=8.217
```

代理地址、注册目标、目标空闲数和连接上限在 Agent 启动记录中提供，
不随每次注册和业务访问重复。DEBUG 的关闭记录只包含关联标识、适用的目标、
阶段、关闭原因及耗时。

本机 SOCKS 代理可能提前报告成功，`target_connected` 仍表示代理报告的结果，
不额外保证互联网或内网目标已经完成 TCP 建连。普通 `socks5_kit.client` 的成功日志
同样不能替代 reverse 注册 ACK。

Server 的 `reverse_target_connected.elapsed_ms` 从发送反向 CONNECT 前开始计时，
包含现有隧道往返、本机代理目标协商及调度耗时；它不包含先前的资源排队。
`reverse_registered` 与 `reverse_agent_registered` 的耗时覆盖各自的注册过程。

## 定位 Server 排队时间长

先按 `user` 关联 `reverse_business_queued` 与 `reverse_resource_claimed`：
入队记录提供该组的 `user_pending` 和超时限制，领取记录的 `wait_ms` 提供实际等待时间。
其他 user 有空闲资源不会帮助当前 user。

达到限制时，仅记录触发的限制和对应占用：

- `reverse_queue_rejected`：`pending` 和 `queue_limit`；后者是结合实际连接上限后的有效队列上限。
- `reverse_slot_rejected`：`reason=max_resources_per_user` 时提供 `user_slots` 和
  `max_resources_per_user`；`reason=max_resources` 时提供 `slots` 和 `max_resources`。
- `reverse_connection_rejected`：`connections` 和 `max_connections`。

逻辑配额仍按各组的 `max(注册资源数, 已接纳业务数)` 求和计算。
队列超时记录为 `stage=resource_wait error_type=TimeoutError`，包含 `wait_ms`；
尚未提前回复时，失败日志包含准备发送的 `reply_code`；已有提前成功时省略该字段，
不会再发送第二份 SOCKS 回复。

然后查看 Agent 的 DEBUG 事件 `reverse_agent_pool`：

| `decision` | 排查方向 |
| --- | --- |
| `refill` | 正常补建，`spawn_count` 是本次计划启动的数量 |
| `probe` | 失败退避后的单条试探，本次最多补一条 |
| `backoff` | 正在等待重试期限，查看 `retry_in_ms` |
| `probe_in_flight` | 退避恢复期间已有注册未完成，不额外启动其他连接 |
| `registration_in_flight` | 注册正在建立或等待 ACK，计入目标数量，尚未成为已确认空闲连接 |
| `capacity_full` | 空闲数不足，但总连接预算已耗尽；查看 `busy` 和 `max_connections` |
| `idle_satisfied` | 本 Agent 的已确认空闲数已达到配置目标 |

池快照只出现在 DEBUG 的 `reverse_agent_pool`。其中 `idle`、`opening`、`busy`、`total`
分别为已确认空闲、登记中、业务中和总数量；`desired_idle` 为配置的目标空闲数。
仅 `refill` / `probe` 包含 `spawn_count`，快照在新任务启动前记录；
仅 `backoff` 包含 `retry_in_ms`。关闭事件不附带池快照，下一轮池决策反映释放后的数量。

默认 `idle_connections=1`、`max_connections=64`。目标空闲数统计时会把建立中的资源算入，
避免慢协商期间重复补建；总上限同时覆盖登记、空闲和业务中的资源。
所以 `opening>0` 但 `idle=0` 可能是代理连接或公网 ACK 慢；
`busy=total=max_connections` 时则是没有补池额度。
DEBUG 的 `reverse_agent_registration_started` 和
`reverse_agent_registration_proxy_connected` 可以区分本机 SOCKS 阶段与随后等待公网 ACK 的阶段。

这些改动只增加日志，不调整资源数、队列、协议、超时、退避或 splice 的数据转发路径。
日志不在每次 splice 调用或每个数据块上产生；高并发下同步日志输出仍有成本，
如需长期打开 DEBUG，可由应用使用 `QueueHandler` 等方式安排输出。
