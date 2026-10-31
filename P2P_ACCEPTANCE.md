# 内置 P2P 最小接线：本地与 Linux CI 验收

## 结论

**生产 P2P 最小接线已通过本地与 Linux CI 验收，可交付开发分支。** [Linux 完整验证 41182185516](https://github.com/is-wuyi/atoll/actions/runs/41182185516) 的根模块竞态、vet 和两个独立模块均退出 0；macOS 已提交源码快照的带取证全根竞态也退出 0（1143.411 秒）。真实 TLS、授权发现、AEAD、多块恢复、节点复制、直连/中继、同身份重启和完整 CLI 进程用例均已覆盖。历史失败、预验收提交及其修正保留在下文，不宣称所有轮次全绿。

历史目录初始化超时在最终 Linux/macOS 回归中未复现，两端阶段取证保留；其根因仍未证实，不能把这次通过表述为“目录超时已修复”。本批验收不包含公网、跨 NAS 或内核 FUSE。

本批没有部署现网、访问 NAS 创建隔离资源、迁移数据、合并 main 或修改 EasyTier。验收源码在专用 CI 分支留有预验收提交，完整批次按授权交付 `feat/admin-console`。结构化结果见 [本地与 CI 验收证据](scripts/transferlab/evidence/2026-10-31-production-p2p-local.json)；原始日志和源码清单另存私有持久归档，不提交凭据或二进制。

## 范围与基线

基线为 `cab4ed6299f13ad91b651767460fd64e10193f77`，开发分支 `feat/admin-console`。本批把独立 peer runtime、设备双身份证明、HTTPS 授权目录、客户端登记与退出、真实 TLS 数据面接入生产 Master、节点、CLI 和挂载客户端；默认关闭，显式 `-p2p`。

本报告记录本机及 GitHub Actions Linux 隔离验收。没有替换正式服务、合并 main、迁移正式数据、修改 EasyTier 或在 NAS 创建隔离资源。既有 WAN 原型结果不能当作本批生产接线的公网证明。`direct` 只表示实际连接不含 circuit，不保证非 overlay。

运行环境为 Go 1.26.7、macOS/amd64；根模块要求仍为 Go 1.26.0。源码工作区位于 SMB 挂载，测试对象、临时数据库和 CLI 子进程数据使用本地临时目录。不同命令是否通过以其退出码为准，不以子任务完成状态或日志中个别 PASS 推导全量成功。

## 安全与兼容契约

- 设备私钥、peer 私钥、内容 KEK/DEK 相互独立。数字 NodeID 不替换成 libp2p PeerID；双签绑定同一设备挑战和确切 Master HTTPS origin。
- Master 在 WAL 中持久保存 peer 配置、设备绑定、地址发布和撤销；计划写配置升级到版本 4，持久标记或配置缺失、开关不匹配时拒绝运行。用户 client peer 和访问票据不进入 WAL。
- 节点地址租期最多两分钟，每个地址集合最多 16 项；目录最多 512 个端点、8 MiB。登记/发布/释放请求仍独立限制为 64 KiB，并拒绝重复 JSON 键、别名、null 和未知字段。
- 客户端登记的 CAS 修订与授权代次分离。同会话同空间续租保留在途票据；切换、过期和退出后重新登记推进授权代次，旧票据不能复活。
- 每用户最多四个有效 client peer。正常退出有界签名释放；失败交由租期到期兜底。持久 peer 身份可以用当前修订和新签名重新登记，不被永久封死。
- HTTP 节点请求只携带短期票据。真实 SourcePeerID 从已认证连接取得，用户会话和设备凭据只发固定 Master origin。
- runtime 返回前完成协议协商。指定 direct/circuit 时校验实际连接；严格 circuit 使用独立拨号 host，禁止为了切路径关闭其它活跃上传。中继尝试、实际路径、内容完成分别记录。
- 连接数由有限资源管理器硬拒新连接，不使用会关闭活跃流的连接管理器裁剪。授权回调与负缓存有界，回调代次变化、调用取消和 runtime 关闭均拒绝陈旧授权。

## 已执行的真实组件用例

`integration/peer` 使用真实 bbolt Master、用户邀请/登录、设备挑战/双签、地址发布、目录读取、生产 runtime、证书链验证、在线访问票据和生产上传/读取逻辑。没有手工地址到 PeerID 的 resolver 表，没有 `InsecureSkipVerify` 或伪造的 TLS 请求状态。

### 完整 CLI 进程

`TestPeerCLIProcessesAndRelease` 构建带 race 检测的实际 `atoll` 二进制，依次运行：

- 离线 `auth init`、`content-key-init`；启动安全 Master 和节点；真实 CLI 登录。
- 三轮 `put/get`，共六个临时 peer 命令。每个命令结束后立即读权威目录，断言没有残留有效 client peer；每轮读回字节一致。
- 查询已发布 manifest，断言 AEAD 编码、CRC 已知和完整副本 Done。
- 同一持久客户端 peer 身份重复执行命令，验证退出后合法重新登记。
- 节点 SIGTERM 退出后以相同数据目录、NodeID、PeerID、逻辑地址重启，传输端口改变，旧文件仍可读取。Master 的显式 `-p2p-identity` 确实被使用。

首轮独立执行 `-race` 通过（97.578 秒）。后续完整回归中曾因测试辅助控制请求仅给五秒窗口，在 `/auth/invites` 超时；保留该失败，将测试辅助窗口与生产控制请求的三十秒上限对齐后重新验收。不把该超时记作网络测速或功能通过。

### 真实接收中断与 AEAD 块恢复

`TestPeerAEADRecoveryPreservesCiphertext` 使用三个真实节点、128 KiB 测试块、192 KiB 文件和明确 `MaxReplicas=1` 的夹具上限。这个上限仅为确定性安排替代节点，不改变生产调度规则。

第二块的第一个接收节点在生产 Handler 实际读取 32 KiB 后返回读错误；同目标三次完整块尝试均中断，然后由 Master 重规划到其它节点。没有预读 body 后伪造接收活性。

断言包括：

- UploadID、PlanID、Revision、内容对象、编码、长度、CRC 和 HardUntil 不变。
- 第二块 epoch 1→2、恢复次数恰为 1；第一块仍 epoch 1、只传一次。
- 失败目标被排除，副本数和必要确认数没有降低。
- 三次失败请求的实际密文前缀等于最终完整落盘密文前缀；来源是该客户端真实 PeerID。
- 每块完整 Done、落盘尺寸/CRC、KEK 解包后的逐 AEAD 记录解密，以及最终文件读回一致。
- 出站路径 reporter 与 required-direct 约束都指向真实 peer 数据面。

独立 `-race` 通过（13.015 秒）。这是块级重传，不是块内 byte-range 续传。

### 节点复制、路径与负向测试

- `TestPeerNodeReplicateDirect` 显式设置安全保护偏好，客户端并发预算为 1，实际落库传输计划必须为单入口且含节点复制腿。目标节点 ledger 必须记录 `/replicate/` 且真实源 PeerID 为该腿源节点；不能用客户端多 PUT 替代证明。
- `TestPeerDirectRoundTrip` 在立即上传和读取时要求 direct，并核对实际路径 reporter。
- `TestPeerStrictRelayCircuit` 校验真实 circuit 请求；runtime 另覆盖同 peer 的 direct 与 circuit 同时打开、两流各自双向交换字节，不互相关闭。
- `TestPeerNodeRestartSameIdentity` 关闭旧节点后重启，复用同一客户端缓存，验证地址失效后的重新发现，不使用新客户端掩盖缓存问题。
- `TestPeerPlannedAEADMultiBlock` 为 1.5 MiB 文件、1 MiB 测试块，恰好两块；逐块核对 AEAD、CRC、Done、落盘密文及解密内容。
- 错误证书被真实 TLS 拒绝；未登记来源在连接/流授权层拒绝；已登记但无票据的 PUT 到达 Handler 后 401；注销会话后请求失效。
- 明文负向先建立授权 peer stream，再发送明文 HTTP，真实外层 TLS 拒绝且 Handler ledger 不变。裸 TCP 上 Noise 拒绝仅作为不同层的旁证。

## 定点协议与并发回归

`pkg/peerauth`、`master/meta`、`master`、`client`、`node`、`pkg/peertransport` 包覆盖：双签篡改、CAS 竞争、WAL 重放、撤销、短租期、配额与退出墓碑、固定源凭据、后台和在途注册关闭、初次目录强刷、真实协议协商取消、回调替换代次、负缓存上限、连接预算与并行路径。

主审独立结果包括：Master peer 元数据 `-race` 通过（81.559 秒），Master peer HTTP `-race` 通过（41.885 秒），冻结后的 runtime `-race -count=3` 通过（14.579 秒）。这些定点结果不替代最终完整包回归。

## 回归中发现并修复的旧兼容提交窗口

第一轮完整回归中的 `TestMultiChunkPutGet` 曾在第一次提交可能成功后，重试收到 `not a staging inode`。单独重跑三次通过，但源码仍存在明确的两事务窗口：`CommitStagingFile` 已发布文件，随后 `PutOpResult` 才记录幂等结果。

新增 `TestLegacyChunkCommitRecordsReplayBeforeDurabilityFailure` 通过 post-commit 钩子确定性复现“文件已发布、幂等结果缺失”。修复后非 secure 的分块提交也把请求指纹与结果放进同一个发布事务；事务内再次判断重放，避免两个请求同时通过 HTTP 前置查询。重放仍必须经过 `EnsureDurable`，同 op 不同请求冲突。旧 secure 的精确指纹检查未放宽。

`TestCommitStagingConcurrentReplayIsAtomic` 对新建、覆盖各用八路同步起跑，验证同结果、同代次、只有一次旧对象返回、每个结果都经过持久确认，并从 WAL 重建发布与幂等记录。两组相关 `-race -count=3` 定点回归通过。

第一轮完整回归另暴露旧保护拉取的续租缺口：报告末字节时决策与验证器均禁止续租，尚未完成的校验/回执可能跨过租约；三十秒续租窗口只提前十秒判断，又短于节点十五秒进度周期。日志显示末字节报告距旧租约仅 299 微秒，节点即使收到延长答复也可能已按旧租约取消。

本批同步修正决策和验证器，末字节仍可利用已有的校验/回执余量申请一次有界续租；重复字节、零增长、到期租约、次数上限和 HardUntil 继续拒绝延期。Master 提前窗覆盖现有十五秒上报周期与十秒控制超时，并仍限制在续租窗口和一分钟以内。共享常量保持节点原有周期不变。纯函数和元数据时间线定点 `-race -count=3` 通过；真实慢传 E2E 保留原夹具和完整回执断言，`-race -count=2` 通过（79.042 秒）。

## 第一阶段：完整回归与构建记录

本节保留第二阶段修改之前的结果；这里的“最终快照”仅指第一阶段末尾快照。

第一阶段最后一轮完整根模块回归退出码为 1：旧 400 毫秒故障注入用例失败，P2P 直连用例在目录初始化阶段超时。其余根模块包全部通过，包括 Master 440.261 秒、元数据 144.833 秒、节点 31.804 秒；没有竞态检测报告。**该轮不是全根回归通过，后续成功不能抹去它。**

最终发布快照完整 `integration/peer -race` 单独通过（233.834 秒），含真实 CLI 子进程、全部负向用例和节点复制硬断言；节点整包通过（52.949 秒），旧并发上传、CRC 故障转移与多块提交定点三轮通过。各轮失败与本机完整同步延迟证据见下文，不使用定点结果覆盖完整回归的失败结论。

此前完整 `integration/peer -race` 亦通过一轮（206.567 秒）。之后统一快照回归的证书负向用例曾在 `EnableP2P` 的目录读取阶段超时，尚未进入证书断言；同快照该用例单独 `-race -count=3` 通过（24.185 秒）。各轮失败仍保留，不能以重跑抹去。

已完成的独立模块回归：

```sh
go -C prototypes/peertransport test ./... -count=1 -timeout=300s
go -C prototypes/peertransport-production test -tags integration ./... -count=1 -timeout=300s
```

两者通过。第一阶段末尾快照的 `go vet ./...` 通过；`CGO_ENABLED=0` 的 Linux/amd64 和 Darwin/amd64 CLI 均构建成功。该阶段源码清单 SHA-256 为 `59dc9b738d5b5d45d5e9acde677636e3feda8aaf60ec2a90e19ef4bdd28f5c31`，当时拟提交源码和测试逐项一致；不用于描述第二阶段增量。

构建产物 SHA-256（仅作本地构建记录，不作为源码提交标识）：

- Linux/amd64：`7b643e05286ddad3caf15c9780e303566fbfb81ff1f58f55f347a5f82ce2d2d4`。
- Darwin/amd64：`fd03b3382654ed79489236771fe7fcc08e6fb0c6df53847aa8f25898e59a4793`。

第一轮完整根模块命令为：

```sh
GOMAXPROCS=2 go test -race -p 1 ./... -count=1 -timeout=600s
```

该轮保留的失败：上述旧兼容提交窗口、CLI 夹具控制请求超时，以及 `TestProtectionFlightE2ESlowPayloadCrossesInitialLease` 失败和 Master 包总时限超时。末字节续租问题由日志和源码交叉确认后修复；Master 超时是包累计用时到达十分钟，不宣称某个测试死锁。

第一次本地快照回归另在旧 `TestGetChecksumFailover` 的损坏注入之前，等待三个完整副本超时。日志确认主副本的三次复制尝试都发生在 legacy commit 可见之前，均得到 `legacy content is not committed`；commit 最终成功，但之后没有新的复制请求，两个从副本从未收到 payload。该项不是延长 `waitDone` 能修复的测试时限问题。

节点现对“未提交”使用独立 sentinel 和最多三十秒元数据等待；拿到已提交计划后结束该等待，真实网络/内容/授权错误仍最多三次，不给大对象 payload 套三十秒总时限。回归覆盖延迟提交后两份真实副本与回执、永不提交不发 payload、普通错误保持三次，以及普通传输重试跨过等待预算仍不被截断。最终节点整包 `-race` 通过（52.949 秒）。

最后关联补跑曾在旧并发分块上传的 `/files`、`/files/chunks` 元数据请求阶段超时，CLI 用例亦曾在 `/auth/login` 超时，均发生在数据面校验之前。停止额外并行长包后，未修改代码、生产超时或断言，旧并发上传、CRC 故障转移和多块提交三项在最终快照上 `-race -count=3` 通过。全部失败日志保留，不把它们记成成功。

较早快照在续租修复落盘后主动停止，不记作完整通过。最终全根回归使用固定本地源码快照，逐文件 SHA-256 与工作树核对，`-p 1` 串行执行；包级 watchdog 改为二十分钟，仅允许完整套件执行完，不修改测试内部的租约、确认或失败条件。结果如本节记录，未获得全根稳定通过。

## 第一阶段：本机验证稳定性限制

最后串行全根回归仍出现过旧 `TestFaultStalledNodeReassignsToHealthy` 失败，以及 P2P 目录初始化超时。因此不能将本批描述为“所有完整回归轮次全绿”。旧故障用例把健康节点的整个 PUT 限为 400 毫秒，包含真实文件同步。

主审核对 Go 1.26.7 的 `internal/poll/fd_fsync_darwin.go` 与 bbolt 1.3.11：macOS 的 `File.Sync()` 实际调用 `F_FULLFSYNC`。本机同系统调用的六次独立测量为 3.442、0.378、0.345、1.775、2.278、1.847 秒；稍后四次测量又恢复到 0.018～0.025 秒，显示时变持久化延迟。普通 `fsync` 的约 0.0001 秒不代表 Go 实际使用的完整同步。该证据能解释健康节点在 400 毫秒夹具中被判超时，但不把所有目录停顿未经逐项证明都归于磁盘。

没有修改 `NoSync`、没有替换 Go 标准库、没有放宽生产网络超时或删除安全断言来获取通过。重复运行产生的真实失败与后续通过均归档。旧 400 毫秒故障用例随后在相同最终快照上独立 `-race -count=3` 通过（13.667 秒）。

目录停顿的只读调用链检查未发现明确锁回路或授权递归，但静态分析不能代替故障当时的线程栈。主审使用仅增加请求计时和三秒阻塞栈触发器的本地 overlay 运行十次直连测试，全部通过（58.037 秒），目录 Handler 耗时约 0.67～2.14 毫秒，没有触发三秒阻塞采集。该运行没有复现原停顿，**不能据此将目录超时归因为刷盘或宣布已修复**。更早一轮 overlay 使用了 `/var` 别名而未命中 Go 的 `/private/var` 实路径，不能算作带诊断取证；修正路径后已确认计时日志真实输出。

第一阶段结束时验收状态固定为“本地功能用例通过、全量稳定性仍受阻”。随后增加确定性故障、两端取证和 Linux 对照，而不是无改动地反复重跑选择最好一次。

## 第二阶段：确定性故障与两端诊断

第一阶段的完整根模块失败记录、源码清单和构建哈希保留在上文；它们只对应当时快照，不代表下面这些增量的当前源码或新构建。

`TestFaultStalledNodeReassignsToHealthy` 现在由三个节点共享同步屏障：首个实际到达 Handler 的 PUT 选定故障节点，测试确认请求在途后以 `http.ErrAbortHandler` 中止连接；该节点在本文件剩余尝试中继续失败。健康节点使用原默认超时，不再把真实持久化限定为 400 毫秒。八个文件逐个验证恢复请求明确排除故障节点、恰好一次重分配和拦截、权威块表仅有健康完整副本，以及完整读回一致。唯一节点超时失败和读取超时用例未放宽。

主审独立 `go test -race -p 1 ./client -run 'TestFault|TestProbeCache' -count=1 -timeout=240s` 通过（17.227 秒）。收紧单副本与 Done 断言后，使用 Go overlay 仅对隔离副本移除 `reassignChunk` 的 `exclude`：首个文件在 0.929 秒内以“恢复请求 exclude 应包含被拦节点”失败；原生产文件未修改，对照版本通过（7.098 秒）。这证明测试能确定性识别缺失排除名单，不依赖随机重选坏节点。

新增 opt-in `internal/peertrace`：客户端记录连接取得、DNS、TCP、TLS、请求发送、首响应字节和正文读取；Master 记录配置检查、授权、目录读库和响应写出，以独立诊断 ID 关联。诊断头不参与授权，未装 observer 时不改变请求。事件不采集查询串、请求正文、凭据、证书或原始错误文本。

真实组件夹具为每次测试保留最多 512 个阶段事件；三秒慢请求或期限错误触发最多三份、每份最多 512 KiB 的 goroutine 栈。采集关闭、上限和落盘已有竞态测试；连接拒绝、TLS 证书拒绝和 Handler 等待分别有区分阶段的测试。正式 CLI 子进程尚未装 observer，因此这些 JSON 不覆盖其所有控制请求。

带诊断的直连、错误证书和同身份重启三场景各执行五次，全部通过（156.448 秒）；15 份 JSON 中有 50 个目录客户端完成事件与 50 个服务端完成事件。客户端中位 1.450 毫秒、最大 5.924 毫秒，服务端最大 2.163 毫秒；无目录错误或慢请求栈。**这轮未复现自然目录超时，不能据此宣布其根因已消失。**

新增 `.github/workflows/p2p-validation.yml` 只在专用 `ci/p2p-validation-*` 分支 push 或手动触发：Linux/amd64、Go 1.26.7，完整根模块 race、根 vet、两个独立模块 race（第二个带 integration tag）。每步保存真实退出码和完整日志，失败后仍收集诊断，最后聚合闸门拒绝缺失或非零退出码。Actions 只有仓库读取权限，不使用私有凭据、不部署、不自动写回或开 PR。实际运行链接、失败和通过记录见下文。

## Linux 对照：已保留的失败与修正

- [运行 41180940609](https://github.com/is-wuyi/atoll/actions/runs/41180940609)，提交 `ddba3c2`：工作流在分配 runner 前被拒绝，未执行测试。原因是 job 级 `env` 不允许使用 `runner.temp`。主审初次 YAML/bash 语法检查也未覆盖这一语义；随后 actionlint 对旧版明确报错、修正版通过，改为 Prepare 步骤通过 `RUNNER_TEMP` 和 `GITHUB_ENV` 设置诊断目录。
- [运行 41181286044](https://github.com/is-wuyi/atoll/actions/runs/41181286044)，提交 `0bed2a0`：Go 1.26.7、Linux/amd64、CGO=1，完整根模块退出 1；唯一失败为既有 `TestApplyDNSOverrideProxyCache`。`integration/peer` 完整竞态通过（69.905 秒），其它生产包通过；根 vet、两个原型模块竞态均退出 0。聚合 Guard 正确拒绝，不因各步骤 `continue-on-error` 而假绿。
- 失败日志中的查询 flags 为 `0x0120`（RD+AD）。Go resolver 会继承系统 `trust-ad`，而 lab DNS 代理明确对 AD/CD 查询旁路、不缓存；旧测试错误地要求所有平台缓存命中。修正仅在两个测试文件中：真实 resolver 用例依据实际 AD 标志检查准确上游次数，新增真实 UDP 普通/AD/CD/再普通序列，证明普通查询仍缓存、安全标志原样转发且不误用普通缓存。`dnsproxy.go`、系统 DNS、代理安全策略和超时均未修改。
- 相关 DNS 竞态测试三轮通过（6.169 秒）。反向 overlay 仅允许 AD 误入普通缓存，新测试在 AD 子用例以“上游 got 1 want 3”失败，正常生产文件保持不变。提交 `054a2d5` 重新触发完整 Linux 验证，结果单独记录，不覆盖前轮失败。

首轮 Linux 产物已下载并核验四个 `.exit`、完整日志和十份真实组件诊断 JSON。目录请求客户端完成 38 次、服务端完成 38 次，最大约 2.133 毫秒，无三秒慢请求栈；正式 CLI 子进程依然不在这套 JSON 覆盖内。

## 最终验收与源码对应

[Linux 最终运行 41182185516](https://github.com/is-wuyi/atoll/actions/runs/41182185516) 测试提交为 `054a2d5ff9a64c02e5e8b5f095bc6fd341691a1f`，Go 1.26.7、Linux/amd64、CGO=1。主审下载 `p2p-diag-41182185516-1`，逐项核对四个 `.exit`、全部日志、成功的 Guard 与诊断 JSON：

| 验证 | 退出码 | 执行记录 |
| --- | --- | --- |
| Linux 根模块 `go test -race -p 1 ./... -count=1 -timeout=20m` | 0 | CI 步骤 590 秒，22 个测试包通过、1 个包无测试；完整 P2P 组件 79.176 秒 |
| Linux 根 `go vet ./...` | 0 | CI 步骤 6 秒 |
| 独立 `prototypes/peertransport` 竞态 | 0 | CI 步骤 38 秒 |
| 独立 `prototypes/peertransport-production -tags integration` 竞态 | 0 | CI 步骤 8 秒 |
| macOS 全根竞态，`GOMAXPROCS=2`、同样 `-p 1 -timeout=20m` | 0 | 总用时 1143.411 秒，完整 P2P 组件 221.063 秒 |
| macOS 最终 `cmd/transferlab` 整包竞态、根 vet | 0 | DNS 测试增量整包 7.816 秒，根 vet 通过 |

上述 CI 步骤时间包括构建/准备，不是网络传输耗时；未使用 `-short`，真实 CLI 进程测试没有跳过。

macOS 全根及双平台 CLI 构建来自精确提交 `ddba3c21ae45d9b6ca7fcdecb8ae22027d3cc671` 的本地源码快照。到 Linux 验收提交 `054a2d5` 之间只变化了 CI YAML 和两个 DNS 测试文件；340 项非测试 Go 文件及根 go.mod/go.sum 的逐项摘要完全一致，合并摘要为 `85997a7b482682554ad7d8ddbbd06b949c81490daf5e2e7f01ac1a2c216dafab`。最新 DNS 测试增量另在 macOS 整包和 Linux 全根验证，不把不同提交直接冒称同一快照。

当前验收构建 SHA-256（CGO=0，仅验证可构建，不是现网二进制）：

- Linux/amd64：`f4891a6f51fe601a778f6ca6051dae742fb43178ed35d7be1b81a489bd5c6543`。
- Darwin/amd64：`44d49d0427d1a831e2b32929300875b2a31f7be7f4a0d622cd879583b9dabce0`。

最终 Linux/macOS 各有十份真实组件阶段 JSON。目录客户端/服务端完成事件分别为 Linux 38/38、macOS 37/37；客户端最大约 2.282/6.182 毫秒，无目录错误、无三秒慢请求栈、无 race 检测报告。它们证明这两轮完整回归通过，不证明历史目录停顿根因已修复。

本批代码与验收记录交付 `feat/admin-console`；仅文档/证据的收尾提交不改变经过上述检查的生产代码。main、正式服务和 EasyTier 保持不变。

## 未覆盖的边界

- 真实公网直连、NAT 打洞、跨 NAS 中继和公网地址变化尚未在本批执行；本地 direct 不能证明非 overlay。部分组件夹具监听全部本机网卡，CLI 子进程夹具显式仅监听 loopback。
- 未执行内核 FUSE 挂载；挂载侧仅复用同一生产客户端 transport。
- 未运行正式集群升级、恢复材料迁移或全损灾备演练。
- 断流后的安全由既有块级重传与重规划契约负责，已经打开的流不会被透明迁移。
- 调度输入中的注入 RTT/路径只用于确定性选路，不能作为实测延迟或吞吐；没有公布网络吞吐数字。
