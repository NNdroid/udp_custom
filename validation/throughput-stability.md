# 吞吐量与稳定性验证

日期：2026-10-02。实现基于 `origin/perf/throughput-pipeline` 的
`c33f390d787087583c0b19adb5654171fd4efb51`，分支为
`codex/throughput-stability`。保留该分支的 Linux 接收批处理，未混入
`perf/throughput-p0` 的另一套原始系统调用实现。

## 完成的优化

1. 每会话一个有序写入者，最多保留 512 个已认证 DATA，隔离慢应用与慢后端；
   完成写入后才推进累计 ACK，队列满时允许原始 DATA 重传。
2. 握手独立协商 SACK 与接收信用；覆盖完整 512 帧窗口，验证反馈范围和新旧顺序，
   快速修复缺口，按实际发送截止时间调度重传，修复丢失信用反馈造成的停发。
3. 自动窗口从最多 64 帧增长到 512，丢包缩窗；DATA、修复和 FEC 共用 RTT 节奏控制。
   显式窗口仍限制上界，旧端保持固定窗口与累计 ACK。
4. ACK 每两次交付合并一次，单次交付等待最多 1ms；缺口和重复包即时反馈。
5. 有界发送队列合并就绪数据；Linux 使用非阻塞 sendmmsg，正确处理部分发送、
   IPv4/IPv6、端口分散和 socket 修复，其他平台保留普通 UDP 写入。
6. FEC 在无损路径跳过复制和定时器，复用内部源列表与分片存储，保持独立 payload
   所有权；接收端避免对完整或无法恢复的块分配分片数组。
7. 额外修复 Server.Start 重复调用：同一 socket 只启动一个读者。
   Linux 重复验证曾复现双读者造成批量读取锁等待、握手/回显超时；修复后通过。

协议与所有权细节见 [设计说明](../docs/transport-optimization.md)。

## 正确性与稳定性

- Windows：`go test -count=1 ./...`、`go vet ./...` 通过。
- Linux amd64：`go test -race -count=1 -timeout 5m ./...`、`go vet ./...` 通过。
- Linux 重点场景 race 重复 10 次通过；reuseport 收包测试额外重复 20 次通过。
  覆盖慢消费者、并发有序队列、ACK 定时器、SACK、过期/畸形反馈、信用探测、
  发送部分成功及修复、重复 Start、真实 UDP 丢包/乱序/重复注入（FEC 开/关）。
- Linux 386：tunnel 包完整测试二进制实际运行通过，无 32 位原子对齐 panic。
- Linux amd64/arm64/arm/386 与 Darwin arm64 主程序交叉构建通过。
- 新旧互通：同一探针分别用基线与最终代码构建，PSK/Noise 下的旧服务端→新客户端、
  新服务端→旧客户端四组均完成 64 KiB 非零数据回显校验，默认 FEC 开启。
  探针见 [interop_probe.go](../scripts/interop_probe.go)。
- 本地与 Linux 验证目录的全部 Go 源码、go.mod、go.sum 逐文件 SHA-256 一致。
  探针缩小数据量后重新构建两端；此脚本使用 ignore build tag，不影响完整包测试。
- CI 已加入重点场景 race 重复测试和 FEC 微基准，移除临时改源码的 delayed-ACK 工作流。
  这些是本次本地/隔离远端验证结果；尚未执行发布后的 GitHub CI。

互通边界：最初的 512 KiB 同时双向旧服务端探针超时，随后使用 64 KiB 验证协议互通。
该失败尚未单独定位根因，旧端大流量互通仍有验证缺口，未将小流量通过扩大解释为
大流量稳定性证明。

## 性能测量

在 ndjc-nas0 的独立 `/tmp/udp-custom-validation-20261002` 目录运行，未替换任何服务。
环境：Fedora 43、Intel Celeron J1900、Linux amd64、Go 1.26.1、GOMAXPROCS=4。
基线和最终代码串行测量，每项 7 次、每次 1 秒，以 benchstat 对比。
端到端测试使用同机回环 TCP/UDP 后端与真实 UDP 隧道；每项沿用仓库既有基准的
数据量与配置。FEC 无损微基准在基线添加相同函数，跳过四个 bootstrap 块后计时。

结果见同目录的 benchmark-base.txt、benchmark-head.txt 与 benchstat.txt。

| 项目 | 基线中位数 MiB/s | 最终中位数 MiB/s | 吞吐变化 |
| --- | ---: | ---: | ---: |
| TCP / PSK | 6.180 | 8.783 | +42.13% |
| TCP / Noise | 6.084 | 8.726 | +43.42% |
| UDP / PSK | 5.484 | 6.723 | +22.61% |
| UDP / Noise | 5.474 | 6.847 | +25.09% |

各项吞吐差异的 benchstat 检验均为 p=0.001、n=7。FEC 无损 sender 微基准从
2245 ns/op、1487 B/op、1 alloc/op 降为 63.41 ns/op、0 B/op、0 alloc/op。
此结果衡量跳过无用工作的开销，不是可恢复丢包吞吐量；不使用它与端到端结果的
几何均值来表述整体收益。

TCP 每轮分配次数下降约 10.6%，分配字节下降约 1.2%；UDP 每轮分配次数下降
约 3.25%，分配字节增加约 0.3%。交付采用独立拥有的 payload、发送队列与 x/net
批量消息对象，保证隔离和缓冲区生命周期。每轮分配字节不是进程驻留内存。

测量还发现重传检查在没有到期 DATA 时分配排序列表；改为按需分配后重新执行
完整测试与以上 7 次基准。最终 CPU 与 alloc_space 采样摘要见 cpu-top.txt、
alloc-top.txt，原始 profile 留在隔离验证目录，未提交二进制产物。
最终分配热点主要是认证 wire、FEC 接收缓存和有序交付所需的独立 payload。

复现端到端基准：在基线与当前代码分别运行
`GOMAXPROCS=4 go test -run '^$' -bench 'Benchmark(TCP|UDP)Target_' -benchmem -benchtime=1s -count=7 ./tunnel`。
再用 `go run golang.org/x/perf/cmd/benchstat@latest benchmark-base.txt benchmark-head.txt`
比较，避免同时运行两组或与 CPU 密集验证重叠。

## 尚未验证的边界

公网 RTT/带宽、长时运行、DNAT/CGNAT 多路径、生产并发容量、Android 与真实 ARM
运行尚未验证。Darwin 是交叉构建结果，Windows 本次未运行 race；race 证据来自 Linux。
窗口控制是有界 TCP 风格控制器，并非 BBR 或带宽估计器。回环吞吐量不代表生产收益。
