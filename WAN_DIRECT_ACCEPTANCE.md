# 公网端点直连：2026-10-27 隔离实机验收

## 结论

**部分通过，不是生产就绪或稳定性全绿。** 28425↔29663 的独立 P2P 原型已经在公网端点上完成双向、非 circuit 的对象传输，32 MiB 样本亦有 SHA-256 校验成功记录。两端针对这些公网端点的 OS 路由都指向物理 `eth0` 和本地网关，不走 `tun0`/`tailscale0`。这比只有 `path=direct` 标签的旧证据更强，但不是逐包抓包或所有外部网络跳的证明。

同时，重启后的单边 direct-only 冷拨两方向均为 **0/8**；受控强制中继的 32 MiB 上传两方向都未完成；持续探测保留了超时、截断和停止时中断记录。因此不能宣称自动重连、慢链路大对象、所有 NAT 组合或生产 P2P 接线已通过。

代码基线为 `f238548b1bc292012210a57926b0e912e0946c90`，分支 `feat/admin-console`。本批不修改生产或原型 Go 源码，只归档验收文档与[结构化证据](scripts/transferlab/evidence/2026-10-27-wan-direct.json)。它不改变 [2026-10-24 实机验收](TRANSFER_PLANNING_REAL_ACCEPTANCE.md) 对 27119↔28425 的未通过结论；本次成功的是另一对设备。

## 1. 拓扑与隔离范围

- 中心 26666 运行独立 `wanrunner relay` 和 `control`，公网端口分别为 4001、4000；TCP/QUIC 公网地址均有配置。
- A=28425，物理地址 `192.168.1.4`；B=29663，物理地址 `192.168.3.85`。两端都用 `-public-only -listen-port 44431`，只允许本轮授权 PeerID。
- `run_id=wan-direct-d3ecf815af94`。独立目录、测试身份、对象和进程；正式 9420/9421 服务不停止、不替换。
- Linux amd64 二进制 SHA-256 为 `c1fb32ebd976c81b9a83088f2eaff773b2925dedde41711e80a523bafa80aeae`，三台校验一致。
- EasyTier/Tailscale 保持运行，仅用于发现和 SSH 管理。测试 peer 对私网/CGNAT/loopback 等端点的拨号拒绝有日志，不能把管理通道误称为 payload 直连证据。
- 中心防火墙只加带自动到期时间的 runtime 规则，不改 permanent。持续探测后的查询已显示原规则到期；受控对照前另外恢复一小时 TTL，并逐条查询生效。
- 所有对象都是随机测试内容；本批不验收正式文件模型、AEAD、账号授权到 P2P 身份的生产映射或生产调度器接线。

`wanrunner` 的 CLI 是 `wanrunner <role> [flags]`，角色必须先于 `-state`。部署时出现过参数顺序错误、错误平台二进制和 NAS 文件传输超时，修正后才开始有效测量；原始失败日志保留，不计作传输成功。

## 2. 路径与成功口径

三个事实分别记录，不能合并：

1. `policy` 是请求的策略。
2. probe 的 `fallback` / perf 的 `fallback_attempted` 表示先直拨失败后尝试中继。**forced-relay 本身不是 fallback**，所以其值为 false 仍可实际走 circuit。
3. `path` 是所开流所属连接的实际类别。`direct` 仅表示非 circuit，不单独证明无 overlay；`circuit` 的 remote multiaddr 含 `/p2p-circuit`。

`fallback_upgraded=true` 表示尝试过 relay，但最终打开的流落在直连上。它是升级结果证据，**不单凭该字段确定谁发起 DCUtR、具体打洞机制或外部网络跳**。后续阶段复用已经出现的直连时，`fallback=false` 也不代表此前没有经过中继协调。

forced-relay 在流打开时检查 circuit 和 `Limited`，若选到已升级直连则明确报错，不静默将直连计为中继。libp2p 流绑定于所开连接；后来的直连影响后续流选择，不迁移这条已打开流。

实现参照：`prototypes/peertransport/listener.go` 的 `dialRelay`、`openVerifiedStream`、`wrapStream`；`cmd/wanrunner/main.go` 的 `refreshPath` 和 `probeTransfer`。

成功条件严格保留：

- PUT 必须 HTTP 201，服务端 manifest 的长度和 SHA-256 与上传一致。
- GET 必须下载长度、SHA-256 与上传对象一致。
- probe 成功行没有 `err`，`match=true`，`bytes>0`；失败行 `bytes=0`。失败时写出或读到的 `wire_bytes` 不是已确认内容。
- 吞吐单位是 **MiB/s**，不是 MB/s 或 Mbit/s。`wire_bytes` 包含流上 HTTP 开销，不是逐包网卡计数，不参与成功吞吐计算。
- 64 KiB 与 32 MiB 分组统计。最初 `probe-summary.json` 混合两种大小的桶不能作为单一吞吐基准，正式证据已替换为按大小分组。

## 3. 公网端点直连：能力通过，长期稳定性未通过

### 端点和路由

有效直连记录的实际端点：

- A 操作 B：`/ip4/161.142.118.111/tcp/1375`，A 本地 `192.168.1.4:44431`。
- B 操作 A：`/ip4/183.241.108.130/tcp/34950`，B 本地 `192.168.3.85:44431`。
- 后续受控复测也观察到 B 的公网端点 `/ip4/161.142.118.111/tcp/1099`，说明观测地址并非固定。不能据此把所有冷拨失败定性为端口漂移。

两端路由核查原文：

```text
A: 161.142.118.111 via 192.168.1.1 dev eth0 src 192.168.1.4
B: 183.241.108.130 via 192.168.3.1 dev eth0 src 192.168.3.85
```

路由采样与实际流端点、公网连接门相互佐证：**这些直连使用公网端点，采样时主机路由不经过 EasyTier/Tailscale 接口**。这是主机路由层证据，不是持续逐包观测，也不推断运营商或网关背后的每一跳。

### 全量操作记录

持续探测日志从 2026-10-27 07:07 到 18:01（UTC+8），约 10 小时 55 分钟；最后两条 PUT 与本轮主动停止窗口相邻。下表包含整个窗口，早期成功快照不重复相加。

| 发起端 | 操作记录 | 校验成功 | direct 成功 | circuit 成功 | 失败或中断 |
|---|---:|---:|---:|---:|---:|
| A=28425 | 1,485 | 1,326 | 1,302 | 24 | 159 |
| B=29663 | 1,656 | 1,436 | 1,397 | 39 | 220 |
| 合计 | 3,141 | 2,762 | 2,699 | 63 | 379 |

所有上述成功操作都满足长度/校验条件。`direct` 的 32 MiB 成功操作共有 **1,063 次**，不是只测通了小包。

早期快照只有 63 条操作：54 条 direct 成功、7 条 circuit 成功、2 条失败；其中 B 有一组 32 MiB PUT/GET 的 `fallback_upgraded=true`。这组记录是全量日志的子集，不能把 54 次再加到 2,699 次上。

### 32 MiB direct 成功窗口的性能

下表只统计**同大小、校验成功**的操作，同时给出单操作速率中位数与总确认字节/总成功耗时，避免长尾被中位数隐藏。失败耗时不进入这两个速率，但失败次数在上表完整保留。

| 操作 | 成功次数 | 单操作速率中位数 MiB/s | 成功窗口聚合 MiB/s |
|---|---:|---:|---:|
| A PUT B | 314 | 7.779 | 1.234 |
| A GET B | 239 | 10.678 | 4.226 |
| B PUT A | 255 | 9.760 | 2.843 |
| B GET A | 255 | 9.377 | 5.372 |

这些是应用请求完成窗口，不是网卡线速、精确 RTT、整窗口用户可用吞吐或与 relay 的受控加速倍数。成功 32 MiB 操作也有上百秒长尾；仅报“约 10 MiB/s”会误导。

持续窗口存在两端周期互探的流量重叠，原 runtime 规则后段已到期，不是干净的串行性能或生产可靠性实验。它仍真实保留了失败：248 条服务端 `i/o deadline reached`、70 条 `unexpected EOF`，以及连接写超时、keepalive timeout、stream reset、拨号失败等。最后两条与主动停止相关的记录也保留在 379 中，不通过删掉它们制造全绿。

本轮没有对运营商、NAT、磁盘或关闭连接的具体发起方作独立根因隔离，不将所有症状归于同一层。

## 4. 无后台探测的受控对照

先安全停止两端 probe。作为目标的一端以同一测试身份、`-probe-every 0` 和 relay 预留运行；发起端复用其原身份和监听端口运行 perf，避免新身份被 allowlist 拒绝。每个场景串行执行，原始退出码、成功次数与错误均归档。

perf 每轮 connect 拆掉目标连接后再拨号；request 的首个暖请求不进入计时。connect/request 的 `n` 只计成功；任何失败使整个 perf 非零退出，即使之前有部分成功。后续 phase 未到达就是未测试，不写成零速率或成功。

### direct-only 冷拨：两方向未通过

A 使用先前 B 的 `/tcp/1375`，B 使用先前 A 的 `/tcp/34950`，各 8 次：

- 两方向都是 `n=0`，退出码 1，错误为 direct connect 的 `context deadline exceeded`。
- 没有 fallback，也没有到达 request/up/down；不存在受控 direct 吞吐数字。

这说明先前观测端点不保证新单侧冷拨成功。它不否定运行中直连传输的成功，也不证明两个失败都由 NAT 端口变化造成。

### forced-relay 32 MiB：建连和小请求通过，大上传失败

| 发起端 | connect | 1 KiB request | 32 MiB PUT | GET |
|---|---|---|---|---|
| A | 8/8，circuit | 8/8，circuit | 超时，0 已确认字节 | 未到达 |
| B | 8/8，circuit | 8/8，circuit | 超时，0 已确认字节 | 未到达 |

A 的失败上传流写出 8,916,992 字节，B 写出 1,572,825 字节；都报 `connection write timeout`，不能用部分字节计算成功吞吐。这两次是连接层写超时记录，不能混称为后述 120 秒服务端读期限。

### forced-relay 64 KiB：A 通过，B 被严格路径校验拒绝

A 的小对象对照完整退出码 0：connect 8/8、request 8/8、PUT/GET 长度与 SHA-256 一致，四阶段都是 circuit。PUT 712.786 ms，GET 1195.245 ms；这是小对象完成延迟，不推广为大对象带宽。

B 的两次小对象尝试都在 connect 阶段为 7/8，错误是：

```text
expected limited circuit connection, got /ip4/183.241.108.130/tcp/34950 (limited=false)
```

这实际观察到一个非 limited 公网直连被流选择命中，同时验证了 forced-relay 护栏：没有把它静默计为中继成功。两个场景均退出 1，request/up/down 未到达；未为获得绿灯而关掉打洞、降低轮次或丢弃失败。

### direct-then-relay：能恢复直连，但大上传仍失败

另外各做一次 1 轮、32 MiB 的有界复测：

- B：connect 先 fallback 到 circuit，request 已走公网 direct；32 MiB PUT 又走 direct，但服务端返回 `HTTP 400: read body: i/o deadline reached`，0 已确认字节。
- A：connect/request 走 fallback circuit，32 MiB PUT 的实际连接已经是 B 的公网 direct `/tcp/1099`；同样触发服务端读期限，0 已确认字节。

这进一步说明“冷拨失败”和“中继协调后又出现直连”可以同时成立，也说明仅打通路径并不能保证慢/停滞的大对象完成。不能由这些失败输出计算 direct 或 relay 的加速倍数。

## 5. 本轮识别的工程边界

以下是取证后的报告项，本批未擅自改变实现：

- **期限不是一层。** 原型对象服务对每 PUT/GET 有 120 秒墙钟期限；32 MiB 若持续低于约 0.267 MiB/s 有效字节率便无法在该窗口内完成。连接写超时、keepalive 与服务器读期限另有独立症状。生产 flight 的续租不能自动延长这个独立原型的期限。
- **背靠背探测。** 两端每 45 秒启动的同步 probe 若一轮超过间隔，ticker 的待处理 tick 会使下一轮紧接开始。它不是严格的“完成后休息 45 秒”，慢网时会持续加压；后续工具优化宜从完成时间、退避和总样本预算着手。
- **升级与 strict relay 相容性。** forced-relay 不允许选中直连，护栏是正确的；自动升级又可能让后续流更倾向 direct。受控中继基准必须保留这种硬失败，生产路径选择则需区别“路径不符合实验策略”与“对象传输失败”。
- **地址生命周期。** 公网端点和已有连接不能当永久可冷拨地址。发现、NAT 重建、协调打洞与失败后重连闭环仍需专门验收。
- **证据粒度。** `LastStats` 汇总同一个 DialConfig 所有流的字节，但路径字段来自最后一条连接。跨多连接的长 phase 不应仅用一个末尾路径标签代表整段；本次 probe 单请求使用独立 config，并保留 perf 的实际阶段路径，不据此证明全阶段逐包行为。
- relay 的原型资源上限为一小时、每方向 256 MiB，不是 libp2p 默认 128 KiB；32 MiB 小于这个上限。没有把本轮 32 MiB 失败武断归于默认 relay 容量限制。

## 6. 清理与现网复核

已逐项核实：

- 先检查 owner 的 `run_id`/uid/绝对路径，再检查 PID 启动时间和可执行文件；只停止本轮自有进程，未按进程名批量 kill。
- 两 NAS probe/idle/perf 与中心 relay/control 均已停止。清理前对整个自有目录拒绝符号链接，确认无存活自有 executable，再删除。
- 26666 `/root/.atoll-wan-direct-d3ecf815af94`、28425 `/volume2/homes/jimo/.atoll-wan-direct-d3ecf815af94`、29663 `/volume1/homes/jimo/.atoll-wan-direct-d3ecf815af94` 全部核实不存在；累计移除约 18 GiB 的本轮测试对象与工具。
- 4000/4001 的 TCP/UDP 四条 runtime 规则主动移除，runtime/permanent 查询均为 `no`；永久防火墙、系统 DNS、hosts 与 EasyTier 配置未修改。
- 上传绕行时在中心 `/root/.ssh/known_hosts` 追加过 29663 的受信主机公钥；清理时通过文件哈希、唯一匹配和末尾行校验，只撤回这条本轮新增记录。原有十条记录逐字节不变，权限保留，新增项查询已为不存在。
- 中心和 28425 正式健康检查在清理前后均为 200；三台 EasyTier/Tailscale 进程的 PID/启动时间前后相同。
- 29663 本机 DNS 仍把自己的域名解析到公网占位地址；中心 DNS 正确返回其 EasyTier 地址且在线表中有该设备。本机 9421 没有监听、没有 Atoll 正式进程、loopback 返回 connection refused，与此前已记录“该机无正式节点”的状态一致；没有把它报告为健康 200，也没有擅自部署正式节点或修 DNS。

**旧残留仍挂起：**中心实际在线表没有 27119，DNS 返回公网占位地址。本次不猜 IP、不替换主机；此前 `/volume1/@fake_home_link/jimo/.atoll-transfer-346fbb3b43fe-zowqlse0` 的最终状态仍无法验证。上线后只能精确核对归属和 PID 再处理。

## 7. 证据与本地回归

私有完整证据保留在 `~/.atoll-realtests/wan-direct-d3ecf815af94/`，包括停止后的全量日志、9 个受控 perf 场景的真实退出码、route/进程采样和清理回执。生成结构化证据时，逐个核对本机归档日志的 SHA-256/字节数与远端删除前哈希一致，再重算全量计数、尺寸分组、吞吐与失败类别。

仓库只提交筛选的统计、事件、场景结果和证据哈希；不提交 SSH 设置、密码、测试私钥、原始全机列表或测试二进制。早期快照明确标为子集，受控 perf 结果与持续 probe 不相加。

本地原型全量 `go test -race -p 1 ./...` 通过（peertransport 30.815s、wanrunner 3.665s），`go vet ./...` 通过；证据统计/远端日志哈希验证通过。生产源码未修改，未重新执行根模块全量测试或内核 FUSE 挂载测试，不将它们写成已通过。

这是一份**部分通过的隔离原型验收**。没有合并 main，没有现网部署，没有迁移正式数据，也没有拆除 EasyTier；这些动作仍需单独确认。
