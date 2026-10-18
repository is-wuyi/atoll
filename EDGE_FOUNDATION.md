# 边缘主存储：完整性基础与隔离原型

> 这是前一批完整性基础的验收记录。后续已接入默认关闭的持久自治多副本循环，并新增身份/加密基础库；当前状态以 [自治多副本说明](AUTONOMY.md) 为准。再之后接入的可选安全模式（账号/空间/节点身份/在线票据）见 [安全说明](SECURITY.md)。本文“未接执行器/观测”的表述记录的是前一批交付时点。

本批沿用 Go、bbolt、CLI/FUSE 和控制台，在现有数据路径中加固完整性，并提供两条可运行的旁路原型。它不是账号、密钥、EC、桌面客户端或生产网络迁移的整体完成版。

## 本批边界

| 部分 | 已实现的范围 | 尚未启用或实现 |
| --- | --- | --- |
| 对象完整性 | Master 权威对象描述；按描述验证复制与修复；版本绑定的可疑副本上报；校验后确认 | 抗恶意节点的密码学存储证明；每设备独立授权（该批尚未提供，后续安全模式已补节点独立身份，见 [SECURITY.md](SECURITY.md)） |
| FUSE/CLI 读取 | 已知校验和的 chunk 全量校验后返回；严格 Range；有界共享校验缓存；换副本与可疑上报 | 细粒度随机读摘要/认证加密块；大于一个 ChunkSize 的旧整对象 FUSE 内容校验 |
| 自主调度 | `internal/scheduler`、JSON 回放 CLI；副本/RS 候选与独立校验 | 生产执行器、实际 EC 编解码、迁移及降副本 |
| 内置网络 | 独立 libp2p 模块；持久 PeerID、直连/真实 Circuit Relay v2、授权及有限资源测试 | WAN 打洞验证、AutoNAT 探测服务、生产接线及替换 EasyTier |

没有部署真集群、裁剪现有副本、改变 EasyTier 或自动启用新调度策略。**EasyTier overlay 在本文档时点及当前现网部署中仍在使用**：内置 libp2p 网络原型只是独立嵌套模块，未接入生产、未替换 EasyTier。陌生 NAS 上的静态加密、密钥托管、账号/空间权限、回收站和恢复包仍属于后续阶段（账号/空间与节点身份已在后续安全批接入，见 [SECURITY.md](SECURITY.md)）。

## 对象完整性协议

物理对象描述 `types.ObjectIntegrity` 含 ObjectID、逻辑文件身份、内容代、块下标、长度、CRC32C、`checksum_known`、副本成员、完成/可疑状态和 `integrity_epoch`。

- `GET /files/replication?object_id=...&node_id=...` 返回 `integrity-v1` 描述、未完成目标和可用源。查询本身不表示数据已经校验。
- `POST /files/replicated/verified` 接收完整对象描述与节点 ID。Master 在事务中核对内容身份、长度、CRC、当前副本资格及 integrity epoch，再恢复完成状态。重复回执仍经 `EnsureDurable` 确认，不能绕过此前失败的同步备份确认。
- `POST /files/replicated/present` 仅用于没有已记录校验和的旧数据；它不宣称内容已验证，也不能解除可疑状态。
- `POST /files/chunks/suspect` 使用读取快照的 FileID、Generation、chunk index、ObjectID、size、checksum 和 node ID 做条件更新。旧版本或非成员报告不修改当前版本。
- `POST /files/objects/suspect` 使用完整对象描述，供复制/修复路径报告错误源。
- 节点 `POST /verify/{id}` 从 Master 取得描述，实际读取本地内容，完成校验和持久化确认后发送回执；仅返回 HTTP 200 不能替代回执。

复制不再把源磁盘现算的 CRC 当作权威。源端按 Master 描述检查后才发送，目标也独立获取 Master 描述，检查完整长度与 CRC，临时文件同步、原子改名及目录同步完成后才上报。注册节点对新的不可变物理对象上传同样检查权威描述，不能用“不同内容加自身合法 CRC”覆盖一个已分配对象。

可疑上报只撤销健康标记，不立即删除物理对象。标疑会推进 integrity epoch，使标疑前生成的迟到校验回执失效；副本重分配同样使旧确认失效。没有完好源时明确保持降级，不通过删除唯一副本来触发自愈。普通存在性探测和旧无内容回执都不能解除可疑状态。

这不等于已经实现周期性全盘 scrub：一个已 Done、心跳正常的节点后来丢失或损坏文件，仍需要读取、复制校验或显式验证发现问题；当前扫描器不会持续读取全部已 Done 对象来证明磁盘内容仍完好。

### 兼容与升级注意

1. 已有非零 CRC 视为已记录；新 chunk 明确保存 `checksum_known`，真实 CRC=0 也能验证。旧元数据中 CRC=0 且没有 known 标记的内容仍按“未知”处理，不能凭空恢复历史校验值。新节点对这种旧数据复制检查长度；旧兼容探测最多证明对象存在，不提供内容验证保证。
2. 已知 CRC 的对象访问旧 `/files/replica-targets` 或 `/files/replicated` 返回 **426 Upgrade Required**，要求使用新协议。节点查询不支持新协议的 Master 会失败，不自动退回源端自算 CRC。
3. 旧 `/files/corrupt` 不含版本身份，现返回 **426**；新 CLI/FUSE 使用只标疑、不删除的接口。
4. 升级需协调 Master、node、CLI/FUSE 版本。先更新 Master 可保留旧数据读取，但旧节点对已知 CRC 对象的复制确认会暂停，直到节点更新。没有做线上滚动升级验收。
5. 老程序不理解可疑状态及 epoch，可能覆盖新状态；不要在已使用新状态的元数据上直接降级运行老写入程序。

CRC32C 只检测意外损坏，不抵御有意碰撞。**本文档时点**生产仍使用共享 Bearer/TLS 体系；节点可伪造自身上报的威胁不由 CRC 或 epoch 解决。新 P2P 原型的身份授权也尚未接入生产对象协议。（后续安全批在 `-secure` 下补了节点 Ed25519 独立身份，见 [SECURITY.md](SECURITY.md)；但节点仍不可信、本批未提供节点机密性。）

## 读取成本与剩余优化

目前的权威摘要粒度仍是整块。在只请求 4 KiB 的首次读取时，一个已知 CRC 的 64 MiB 块也必须完整取回并验证，之后通过共享缓存摊销。没有拿部分 Range 的 CRC 与整块 CRC 比较。整块读取给每个副本独立的、按长度缩放的超时，某个慢副本超时后仍可尝试健康副本；外部请求取消则停止整个读取。

已知校验和的旧整对象在不超过 ChunkSize 时采用同类全量校验；更大的旧整对象 FUSE 路径仍只有严格 Range/长度防护，没有内容 CRC 保证。CLI 全对象下载仍能在完成后核对整对象 CRC。

对象从 staging 被采纳到正式 inode 后，当前物理块反查可能遍历 inode 表；尚未实现持久反向索引。完整性确认也增加控制往返和磁盘读，不应引用以前小文件优化的性能数字作为本批新协议的性能结果。后续应以同口径实测决定摘要粒度、描述缓存、批量确认和反向索引，不能为了速度省略验证。

## 调度旁路原型

```bash
# 从仓库根目录运行，输入为完整快照，输出为 JSON 决策。
go run ./cmd/atoll-scheduler -input examples/scheduler/trace-new-object.json -now 2026-10-06T12:00:00Z
```

性能/普通/安全作为优化偏好，不映射为固定副本数或固定 k/m。候选和计划必须经过独立 validator；当前可读性、容错余量、预测可读性分别报告。超过精确求解预算时，硬约束使用可证明的保守下界，而不是用启发式试探结果证明安全。概率评分可以使用独立性假设，但概率硬闸使用不依赖分片独立的下界；预测为 0 的分片也必须计入。重复的同代 shard 副本不能被计算为多个不同 shard。

计划的新增位置和字节数从当前同代布局重新推导，同次回放按对象顺序预留容量；这只是一次运行内的联合预算，不是跨次运行的持久预留或生产执行器。当前历史预测是短窗口实验模型，支持输入在线记录或上游预测，尚未完成多日/周周期学习和现网校准。

输出是 **shadow** 建议。输入目前是 JSON 快照和在线事件轨迹，不是已经接入现网的持续遥测采集器。它也还不是把“旧 EC 基础对象＋新 COW 增量”接入文件读写的 extent 引擎。RS 只是布局候选，实际编码/重建后端没有启用；不能拿“可解码”或评分较好作为删除源副本的授权。

## 网络本地原型

```bash
# 根 go test ./... 不会遍历此嵌套 module。
go -C prototypes/peertransport test -race -count=1 ./...
go -C prototypes/peertransport run ./cmd/demo -state "$(mktemp -d /tmp/atoll-peer-demo.XXXXXX)"
```

模块固定依赖 `go-libp2p v0.50.0` 与 `go-multiaddr v0.16.1`，不改根依赖。拓扑包含控制节点、三个存储 peer 和可分离的 relay。TCP/QUIC 直连及强制 Circuit Relay v2 分别测试；72 MiB 中继往返用摘要和实际 `/p2p-circuit`、Limited 连接属性共同验证。

所有网络证据仅来自 loopback。DCUtR 服务选项已接线，AutoNAT 探测服务未启用，不能据此声称家庭 NAT 或全国 WAN 打洞成功。端到端传输加密也不等于磁盘数据加密。测试所用对象服务只验证传输和进程内可见的原子改名，不是具备 fsync、持久 manifest 与重启恢复的生产存储引擎。详细测试和资源限制见 [P2P 原型说明](prototypes/peertransport/README.md)。

## 本地验证命令

本轮最终串行验收：根模块完整 race 测试、FUSE 内核套件（73 个顶层测试，无 Skip）、`go vet`、`git diff --check` 均通过。独立 P2P 模块 race 测试及 7 项本地 demo 场景通过；20 节点样例在固定 `-now`、跨秒重放时输出逐字节一致。中途失败及尚未定位事项仍按下文记录，不因最终通过而抹去。

```bash
# 本机及集群访问需要绕过系统代理。
NO_PROXY='*' no_proxy='*' go test -race -p 1 ./... -count=1
NO_PROXY='*' no_proxy='*' go test -race -p 1 -tags fuse ./mount -count=1 -v
NO_PROXY='*' no_proxy='*' go -C prototypes/peertransport test -race -count=1 ./...
go vet ./...
git diff --check
```

FUSE 测试需要操作系统实际支持挂载；环境不足导致 Skip 不等于通过内核验证。本轮一次整包运行中 `TestReadInProgressFile` 创建文件曾返回 `result too large`；未修改创建逻辑的单项 3 次、组合 5 轮及后续整包重跑均通过。首次失败日志被保留，原因未定位，不能称为已修复。

后续安全批在完整 FUSE 回归中再次复现首次创建的同类错误，并捕获协议证据：go-fuse v2.11.0 对 macFUSE 单向 `MONITOR` 通知错误回包。2026-10-15 已以本地可重现依赖修复通知抑制标志，协议回归与 120 次实际挂载首次操作通过（480 次 MONITOR、无 ERANGE 回包）。修复和完整最终验收见 [安全说明](SECURITY.md)；此前未捕获协议的单次失败不追认其根因。

公共模块下载是否走代理另按本机网络设置，不把本地绕代理要求误用于所有公网下载。
