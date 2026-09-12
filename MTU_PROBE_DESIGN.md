# 方案 B 设计稿：MTU 自动探测（probe + commit）

状态：**待用户决策，未实施**。前置依赖「方案 D」已落地（`tunnel/mtu.go`，`max_pkt`
运行时可配，发送侧分块上限已从编译期常量改为运行时值）——本方案只是把那个值的
**填法**从「人工配置」换成「自动探测」。

---

## 1. 目标与非目标

**目标**：客户端在建立会话时自动找出当前路径能承载的最大 v2 记录尺寸，两端据此
收敛发送分块上限；全程零人工配置，UDP 被窄 MTU 路径（1420 隧道等）卡死的症状
自愈。

**非目标**：
- 不做内核级 PMTUD（`IP_RECVERR`/errqueue 在 Go 不可移植，且 IPv6 路径上分片根本
  不存在）；
- 不做会话中途降档（见 §5 的硬约束，cap 在会话生命周期内**不可变**）；
- 不覆盖「会话中途路径变窄」的场景（只在新会话/TTL 到期/重连时重探）。

## 2. 为什么必须是「会话内新命令」而不是握手 TLV

`parseTargetTLV`（protocol.go:424）用**精确长度**校验，且 `server.go:866` 显式拒绝
`trailing bytes in payload`。往 SYN 里追加任何字段都会被老服务端以
`[Handshake] Rejected SYN ... trailing bytes in payload` 拒掉，握手直接失败。

新命令则不同：老服务端在 `decodeUDPCFrame`（protocol.go:348 调用
`validUDPCCommand`）的结构校验阶段就丢弃未知命令——**发生在 MAC 验证之前**，即
「握手与会话完全不受影响，探测只是永远等不到回包 → 超时回退默认值」。这是唯一
一条天然向后兼容的路。

## 3. 线格式（3 个新命令，记录格式零改动）

记录格式仍是 `40 + PayloadLen + 16`（PROTOCOL_V2.md 不变）。只加命令号与 shape：

```go
CMD_MTU_PROBE       = 0x0A
CMD_MTU_PROBE_REPLY = 0x0B
CMD_MTU_COMMIT      = 0x0C
```

`validUDPCCommand` 上界从 `CMD_PATH_RESPONSE` 改为 `CMD_MTU_COMMIT`；
`validSessionFrameShape` 增加：

| 命令 | Seq | Payload |
| :--- | :--- | :--- |
| `MTU_PROBE` | 0 | `probeID[8] || zeros`，长度 = `N - 56`（`8 ≤ len ≤ ceiling-56`） |
| `MTU_PROBE_REPLY` | 0 | **逐字节回显**请求 payload（同长度，含 probeID 与填充） |
| `MTU_COMMIT` | 0 | 恰好 2 字节：`uint16 BE` 收敛后的记录尺寸 N |

- 三者都是 established 记录：`PacketNo != 0`，走各自方向的 AEAD + 重放窗。探测
  因此**不可伪造**，回放被重放窗拒绝（无放大）。
- probeID 用于客户端匹配回包（并发探测时防串扰）；填充字节凑长度，不参与语义。
- **为什么需要 COMMIT**：服务端只知道自己收到了多大的探测，无法知道自己发的
  REPLY 是否到达，因此无法自行推断「下游能用多大」。客户端是唯一同时知道双向
  结果的一方，必须显式发布。

## 4. 信息流

```
客户端                                  服务端
  │ handshake ACK 到达（已有会话密钥）
  │ PROBE(N=1450) ──────────────────────► 收到 ⇒ 上行 ≥ N
  │                                       REPLY(回显 N) ──┐
  │ ◄────────────────────────────────────┴─ 收到 ⇒ 下行 ≥ N
  │ N 通过 ⇒ 尝试更大？(阶梯向上已到顶) ⇒ 收敛于 N
  │ COMMIT(N) ──────────────────────────► sess.maxPkt = min(本地, N)
  │ 此后 DATA 按 N 分块                    此后 DATA 按 N 分块
```

一次成功探测同时验证双向。失败（超时）只说明「某个方向在 N 上不通」，降档重试。

## 5. 硬约束：收敛必须发生在数据路径打开之前

PROTOCOL_V2.md：重传必须复用**完全相同**的已编码字节（同 PacketNo/nonce/密文/
tag）→ 在飞的超尺寸帧**无法重新分块**。若探测晚于数据泵启动，应用首批大写入会
以 1450 编码发出、被路径黑洞，然后只能原样重传到会话重传窗口耗尽。

因此：
- **客户端**：探测插在 `client.go:603 establish()` 内、`handshake()` 返回之后、
  第 637-645 行启动 pump goroutine **之前**，阻塞直到收敛或放弃。
- **cap 会话内不可变**：`clientSession.sendCap` 与 `ServerSession.maxPkt` 在建立期
  定死，之后不再变。重探只影响**新**会话。这消除了所有中途 resize 的复杂度
  （泵缓冲重分配、TCP/UDP 分块语义变化、unacked 表里的旧尺寸帧）。
- 服务端不需要延迟启动泵：客户端在泵启动前不发 DATA，服务端 `upstreamToUdpLoop`
  （server.go:1085 启动）只是空转，target 的 TCP 接收缓冲自然吸收，且隧道本就有
  send window 背压。

## 6. 客户端探测状态机

```
阶梯: [1450, 1200, 1000, 800, 548]      // 548 = 576 MTU - 20 IP - 8 UDP，
                                        // 是 IPv4 上永不分片的最大记录尺寸
起点 = min(配置的 max_pkt, 阶梯首项)     // max_pkt 是天花板，探测不会超过它
每级: 最多 2 次探测，单次超时 300ms
成功: 停在该级 ⇒ 收敛
失败: 降一级；最底级仍失败 ⇒ 收敛于 max_pkt（等于「探测无效，用配置值」）
最坏: 5 级 × 2 次 × 300ms ≈ 3s；典型(1500 路径): 1 次往返，≈ 0 额外延迟
```

- **缓存**：挂在 `Client` 上（每客户端一个服务端地址），`effectiveMaxPkt` +
  `probedAt`，TTL 10 分钟。`establish` 先查缓存，命中则零开销。
- **重探触发（v1）**：TTL 到期、`AutoReconnect` 重连（挂 `Reconnecting` 事件）、
  `Client` 重建。「大帧连续首传失败」的被动触发**不做**（ARQ 未按尺寸分桶统计，
  且即便触发也只惠及新会话，收益低）——列入 future work。
- 与握手/target dial **并行**：探测需要会话密钥，无法与 SYN 并行，但 target 的
  连接与探测可并行（服务端在握手期已 dial target）。

## 7. 服务端改动

1. `handleControl`（server.go:1298 的 switch）加两个 case：
   - `CMD_MTU_PROBE`：校验 shape 与长度上限，回 `CMD_MTU_PROBE_REPLY`（payload
     逐字节回显，新 PacketNo），走 `sendToSession`；
   - `CMD_MTU_COMMIT`：`sess.maxPkt = clamp(uint16(N), maxPktFloor, min(本地
     maxPkt, maxPktCeiling))`，INFO 日志。
2. `ServerSession` 增加 `maxPkt int`（0 = 未 commit ⇒ 用本地值）；`sendData` 守卫与
   `upstreamToUdpLoop` 的分块改用 `sess.maxPayload()` = `min(server.maxPayload(),
   sess.maxPkt)`。
3. **泵的分块语义**（关键）：读缓冲仍按**本地** cap 分配（不截断 target 的
   UDP 报文），读出后再按会话 cap 处理：
   - `tcp` target：一个读块拆成 k 个 DATA 帧（字节流语义不变）；
   - `udp` target：一个报文 = 一个 DATA 帧（边界语义不可拆），报文 > 会话 cap 时
     WARN + 丢弃——窄路径上这本来就是必丢的，现在变成可见日志。

## 8. 兼容性矩阵

| 组合 | 行为 |
| :--- | :--- |
| 老客户端 + 新服务端 | 老客户端不发探测 → 零变化；新服务端 shape switch 新增 case 不影响既有命令 |
| 新客户端 + 老服务端 | `validUDPCCommand` 上界未扩 → 探测在**解码阶段**（auth 之前）被丢弃 → 300ms×2 超时 → 逐级降档全部失败 → 回退 `max_pkt`。握手与会话零影响，代价是首个会话多等 ~3s（可配 `mtu_probe=false` 关掉） |
| 两端都新 | 全功能 |
| 探测被中间设备吞 | 同上，回退默认值（这就是现状行为，不会更差） |

**混版部署期间 B 等于不存在**——这是接受本方案的前提，必须两端同升才能生效。

## 9. 安全分析

- 探测/回显/commit 全部走会话 AEAD + PacketNo 重放窗：不可伪造、不可回放。
- 降档诱导：on-path 攻击者持续丢弃大尺寸探测可把客户端压到低档（降低吞吐），
  但这与「直接丢数据」是同一种 DoS，无新增攻击面。不做额外的反制（如跨探测的
  一致性投票）。
- 探测报文是「尽可能大的合法记录」，DPI 视角与普通大 DATA 帧无异。
- 服务端必须校验 PROBE 长度上限（≤ ceiling-56），防止伪造超大 payload 触发
  `MarshalBinary` 错误路径。

## 10. 配置面

| 字段 | 端 | 默认 | 语义 |
| :--- | :--- | :--- | :--- |
| `mtu_probe` | client | `true` | false = 不探测，`max_pkt` 原样生效（排障/已知路径时用） |
| `mtu_probe` | server | `true` | false = 丢弃探测，客户端自动回退（服务端 kill switch） |
| `max_pkt` | both | `1450` | **探测天花板 + 回退值**；显式设置不关闭探测（要「钉死」就 `max_pkt=X` + `mtu_probe=false`，无隐式陷阱） |

## 11. 实施清单（估 ~600 行含测试）

| 文件 | 内容 |
| :--- | :--- |
| `tunnel/protocol.go` | 3 个命令常量、`validUDPCCommand` 上界、`validSessionFrameShape` 3 个 case、`mtuProbeBase`/`mtuCommitSize` |
| `tunnel/mtuprobe.go`（新） | 客户端 prober 状态机 + `Client` 缓存 + 超时/阶梯逻辑（transport 经 `dialer.Send` 注入，可在测试中替换） |
| `tunnel/client.go` | `establish()` 接线（handshake 后、pump 前）、`clientSession.sendCap`、`localToRemote`/`sendData` 改用 sendCap、`ClientConfig.MtuProbe` |
| `tunnel/server.go` | `ServerSession.maxPkt`、`handleControl` 两个 case、泵分块（TCP 拆帧 / UDP 丢弃告警）、`ServerConfig.MtuProbe` |
| `main.go` + 2 个 config 模板 + README + PROTOCOL_V2.md（新增 "Transport probing records" 节） | 透传与文档 |
| 测试 | shape 正/负用例；rig 上 PROBE→REPLY 回显断言；COMMIT 后 DATA 尺寸断言；prober 用假服务端（只应答 ≤ X / 永不应答）验证收敛与回退；全量回归 + 交叉编译矩阵 |

## 12. 需要用户拍板的 4 个点

1. **阶梯取值** `1450/1200/1000/800/548` 与每级 2 次尝试、300ms 超时——是否接受？
2. **首个会话的额外延迟**：典型 +1 RTT，混版最坏 +3s。是否接受，还是要把「探测
   失败即放弃」改为「失败后跳过剩余阶梯直接回退」（更快但可能错过中间档）？
3. **`mtu_probe` 默认值**：默认开（推荐，混版有回退保底）还是默认关（零风险，
   但没人会去开）？
4. **UDP target 超限报文的处理**：WARN + 丢弃（本设计稿的选择）还是 WARN +
   仍然分帧发送（破坏数据报边界语义，不建议）？

确认后按 §11 清单实施；改动涉及线协议，两端（含 myssh 拉新 tag）需同步升级。
