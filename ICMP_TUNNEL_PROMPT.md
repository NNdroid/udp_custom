# ICMP 隧道实现提示词（udp_custom / tunnel）

ICMP 版**不是重写协议**，而是在 `tunnel/` 里新增一个**传输 profile**：v2 记录格式、Noise/PSK
加密、ARQ、目标转发全部复用，只把承载层从 UDP 换成 ICMP Echo Request/Reply。

下面第一部分是可直接粘贴给编码代理的提示词；附录是「为什么必须写进去」的理由与机制映射，
用于你自己 review 提示词时对照。

---

## 一、提示词（复制以下全文）

```text
# 任务

在 E:\GolandProjects\udp_custom 仓库中，为 tunnel/ 包新增「ICMP 传输 profile」：在 ICMP
Echo Request/Reply 上承载完整的 udp_custom v2 记录，实现与现有 UDP profile 等价的能力
（多会话、per-session 目标转发、可靠有序、加密认证、NAT 保活），使其能在 UDP 被封或按目的
端口限速的网络中作为替代通路。

本阶段范围：服务端 + Go 客户端。Android/myssh 客户端不在本阶段范围。

# 背景（必读，不要重新调研）

- 线协议规范见 PROTOCOL_V2.md：固定 40 字节头 + 16 字节 AEAD tag，Ack 累积，PacketNo 独立
  重放窗 2048，Seq 64 位，握手用 HMAC-SHA256-128，会话记录 ChaCha20-Poly1305。
- 现有 UDP profile 的三件套：客户端 spread.go 随机目的端口扩散 → 防火墙 DNAT 折到单一
  listen 端口 → 服务端 origdst_linux.go 还原 pre-DNAT 目的端口，sendsock.go 用该端口套接字
  回包（源端口镜像）。回包能被 CGNAT 放行，靠的就是这个「镜像观察到的键」。
- 帧/加密/ARQ 已经与传输解耦：framing.go、noise.go、replayfilter、rtt_estimator.go 不依赖
  UDP，不要改它们的语义。
- 可注入接缝已存在：NewServerWithConn(cfg, conn, dial)、NewServerWithDialer、TargetDialer、
  ClientConfig.ListenUDP (UDPListenFunc)。新传输必须通过这些接缝可注入，否则测试无法在非
  root 环境运行。
- 现有常量：UDPC_MAX_PKT = 1450，UDPC_HDR_SIZE = 40，UDPC_TRAILER_SIZE = 16，
  UDPC_MAX_DATA = 1394。

# 硬约束（违反即返工）

1. 配置只能来自 -c <file>。禁止任何环境变量、自动扫描 config.server.json、默认路径兜底。
2. 所有代码注释与日志必须英文，不得引入 mojibake。
3. 不新增第三方依赖（stdlib + golang.org/x/crypto + 现有 go.mod）。
4. 不改动 v2 线格式的字节布局。ICMP 载荷 = 完整 v2 记录的字节原样，不新增 ICMP 专属头。
5. port_range / origdst / sendsock_max / receive_sockets 只在 UDP profile 生效；ICMP 路径
   不得读它们，也不得因此报错或 panic。
6. 非 Linux 或无 CAP_NET_RAW 时必须显式报错并给出可操作提示，不得静默降级为「成功」。
7. 不要执行任何 git 操作（不 commit、不 stash、不 branch）。
8. 全部改动必须通过交叉编译：linux amd64/arm64/arm/386、darwin amd64/arm64、windows amd64、
   android arm64。
9. 只输出方案与文件清单，等我确认后再写代码。

# 必须自行决定的设计点（不要提问，按以下结论实现）

1. 会话解复用。ICMP 没有端口，唯一可用的原生 demux 字段是 Echo 头的 16 位 Identifier。
   结论：内层 v2 SessionID 是唯一权威会话键，Identifier 只做廉价预过滤；服务端状态表以
   SessionID 为准。理由：Identifier 只有 16 位，且会被中间 NAT 改写。

2. 下行方向。ICMP 上唯一被几乎所有 NAT/CFW 放行的模式是「请求-应答」。结论：客户端以
   Echo Request 作为下行机会（poll + pacing），服务端把下行数据放在 Echo Reply 载荷里；
   复用 v2 的 PING/PONG 做保活与 poll。允许在观测到映射新鲜时做「服务端主动 Echo Request」
   的反向探测，但必须可配置禁用、失败可平滑降级。

3. 回包镜像。服务端必须原样镜像收到的 Identifier 与 Echo 序列号来构造 Echo Reply，绝不假设
   客户端选择的值（对称于 origdst 的「镜像观察到的值」原则）。客户端必须能接受 id/seq 被
   中间 NAT 改写后的回包。

4. MTU 与分片。ICMP 载荷上限做成 profile 参数 icmp.max_payload，默认 1200，最小支持 548
   （IPv4 最小重组 576 的保守值）。UDPC_MAX_PKT 不得全局修改（会破坏 UDP profile），必须让
   帧尺寸上限按 profile 取值。CGNAT 常丢 IPv4 分片，默认路径不得触发分片。

5. 包率与限速。ICMP 受 net.ipv4.icmp_ratelimit / icmp_msgs_per_sec 及中间设备限速，丢包可能
   突发到 30%–50%。结论：需要发送 pacing（可配 icmp.pace_ms）+ 更保守的重传退避，并保证
   ARQ 在该丢包率下仍能推进。

6. 原始套接字。Linux 用 SOCK_RAW + IPPROTO_ICMP（需 CAP_NET_RAW / root）。不要用 ping
   socket（SOCK_DGRAM + IPPROTO_ICMP）：内核会重写 Identifier，客户端失去 id 控制权。
   IPv4 优先；ICMPv6 的校验和需要伪首部（含目的地址），本阶段只留接口不实现。

7. Identifier 扩散。这是 UDP「端口扩散」的类比物：用可配 id 池（icmp.id_range）替代
   port_range，让 NAT/conntrack 上的流键分散。但收益与 UDP 不同源，必须在 README 里说清，
   不要宣传成等价的按端口限速绕过。

# 交付物

- tunnel/transport.go：传输抽象接口（读 / 写 / 关闭 / 本地与远端标识），UDP 与 ICMP 两个
  实现都满足它。
- tunnel/icmp_linux.go + tunnel/icmp_other.go：build tag 分离，非 Linux 返回明确不支持错误。
- tunnel/icmpprofile.go：Identifier 选择与池、pacing、载荷预算、回包镜像、poll 调度。
- 接线：ServerConfig / ClientConfig 增加传输选择与 ICMP 字段（JSON tag，-c 读取）。
- 测试：tunnel/icmp_test.go 用注入式假传输，非 root 环境必须全绿；
  tunnel/icmp_raw_linux_test.go（//go:build linux）跑真实回环、需 root，缺权限时 t.Skip。
- 配置模板 config.server.json / config.client.json 新字段；README 新增 ICMP transport
  profile 章节；PROTOCOL_V2.md 新增 Transport profiles 章节，明确记录格式与传输无关。
- gen-icmp-rules 辅助命令：生成放行 echo request 的 iptables/nftables 规则，并提示 ratelimit
  调优建议。
- 一份「UDP 专有机制在 ICMP 路径失效清单」：port_range 扩散、DNAT、origdst、sendsock 池、
  reuseport 接收扩展。

# 验收标准

- go build ./... / go vet ./... / go test ./... 全绿，含非 root 本机。
- 交叉编译矩阵（约束 8）全绿。
- 客户端与服务端日志必须能区分三种情形：ICMP 路径正常 / 内核或中间设备限速丢包 / 中间设备
  完全阻断，沿用现有 debug 日志风格。

# 输出格式

先给：设计说明（传输接口签名 + 状态机 + 与 ARQ 的交互）+ 改动文件清单 + 分阶段计划。
等我确认后再开始实现。
```

---

## 附录 A：为什么这 7 条必须钉死

| 决策点 | 不写进提示词的后果 |
| --- | --- |
| SessionID 才是真键 | 代理会用 16 位 Identifier 当会话键，NAT 一改写就串话 |
| 下行靠 poll + Reply 承载 | 代理会让服务端直接发 Echo Request 给客户端，穿透 NAT 时静默失败 |
| 原样镜像 id/seq | 代理会假设客户端选的 id 原样回来，遇到改写型 NAT 全丢 |
| 载荷上限按 profile | 代理会直接改 `UDPC_MAX_PKT`，一次性破坏 UDP profile |
| pacing + 抗高丢包 | 代理会紧凑发 Echo Request，被内核 `icmp_ratelimit` 吞掉，表现为「随机卡死」 |
| 必须 SOCK_RAW | 代理会用 ping socket，内核重写 id → 扩散策略整体失效且难以定位 |
| 只输出方案 | 代理会直接大改代码，与你「先方案后实施」的流程冲突 |

## 附录 B：UDP 机制 → ICMP 映射

| UDP profile 现状 | ICMP profile 的对应物 | 是否等价 |
| --- | --- | --- |
| 目的端口扩散（`port_range`） | Echo Identifier 池（`icmp.id_range`，16 位） | 形式类似，收益不同源 |
| 防火墙 DNAT 折到单端口 | 不需要，ICMP 无端口 | 不适用 |
| `origdst` 还原目的端口 | 不需要，Identifier 就在 ICMP 头里 | 不适用 |
| `sendsock` per-port 回包镜像 | Echo Reply 原样镜像 id/seq | 等价 |
| 5 元组作为路径标识 | 路径 = 源 IP + Identifier；会话键 = 内层 SessionID | 不等价，必须显式 |
| MTU 预算 1450 / 载荷 1394 | 默认 1200，保守 548 | 变小 |
| `reuseport` 多接收 socket | 单 raw socket + 按 SessionID 分发 | 变弱 |

关键差异：UDP 的按端口限速是**每 (目的IP, 目的端口)** 计费，扩散 N 个端口就是 N 倍额度；
ICMP 的限速是**每目的 IP**（`icmp_ratelimit` / `icmp_msgs_per_sec`）加上全局额度，id 扩散
只能分散 conntrack / 中间设备流键，**换不来同样的倍数**。ICMP 模式的主要价值是
「UDP 被整体封禁或被 DPI 抑制时的可用替代通路」，不是「更大的限速额度」。这一点必须在
文档和预期里提前对齐。

## 附录 C：Android 现实约束

非 root 的 Android 应用拿不到 `CAP_NET_RAW`，无法创建 raw ICMP socket，因此 myssh 客户端在
常规设备上**无法实现 ICMP 隧道**。可能的出路（都需要实测确认，不要当成已验证结论）：

1. `net.ipv4.ping_group_range` 若覆盖应用 UID，可用 `SOCK_DGRAM + IPPROTO_ICMP` ping socket，
   但内核会接管 Identifier，只能用「每个 socket 一个 id」换取有限扩散；
2. root / system 应用可用 raw socket；
3. VpnService 无法替代：它只能处理进入 tun 的流量，无法为出站方向手工构造 ICMP 报文。

结论：把 ICMP profile 定位为**桌面/服务端能力**，Android 端保持 UDP profile，文档里写清。

## 附录 D：人工验收清单

- [ ] 提示词第 9 条被执行：先拿到方案与文件清单，再批准实现
- [ ] `icmp_test.go` 在本机非 root 下全绿（证明注入接缝真的存在）
- [ ] 交叉编译矩阵全绿，尤其 windows/darwin 不因 build tag 缺失而编译失败
- [ ] 没有任何非 `-c` 的配置入口被引入
- [ ] `port_range` / `origdst` / `sendsock_max` 未在 ICMP 路径被读取
- [ ] README 明确写出「ICMP 模式不提供按端口限速的等价绕过」
- [ ] 真机/真服务器验证：`ping` 通、隧道通、`tcpdump -i any icmp` 能看到 Reply 里的载荷
