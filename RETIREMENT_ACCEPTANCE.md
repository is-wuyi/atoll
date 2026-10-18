# 对象退隐批次验收记录

## 范围

基线为开发分支 `feat/admin-console` 的 `f7009ed`。本批实现未发布上传的持久退隐、节点封禁与已证明容量释放，同时将已发布旧版本保留为 `held`。生产行为、升级要求和剩余边界见 [RETIREMENT.md](RETIREMENT.md)。没有部署真实 NAS、合并 main、迁移正式数据或修改 EasyTier。

这里的“安全回收”不是完整回收站或有效读租约：仅处理已经终结且从未发布的上传。旧版本、未知磁盘孤儿和不确定历史容量不因空间紧张而被删掉。

## 已落地的验收覆盖

- 节点先持久化 fence，之后才删除；删除失败时 fence 仍存在，原对象和用量保留，重试不会绕过目录同步。
- 已有 payload 落入临时文件、在途预留非零时，退隐返回未完成；迟到写入不能 rename，临时文件清理后同 fence 新 attempt 才可完成。
- 满容量不可变对象重放同样检查 fence；对象、预留和其他在途操作不被错误释放。
- 崩溃窗口模拟保留 fence 和对象，启动对账删除已封禁对象；损坏、超长和符号链接 fence 拒绝启动和写入。
- Abort/过期在同一事务移除 staging inode、写入退隐记录，但保留对象/节点预留；完整匹配回执才能释放。
- `removed_bytes=0` 的持久缺席证明可释放该对象预留，但不减历史用量下限。
- 最新 attempt、fence、节点受众、原始正文摘要均绑定；旧 attempt、篡改正文和已确认操作的旧控制票据拒绝。
- 重复确认、同步 WAL 策略失败后重放以及独立 WAL 恢复均保留 tombstone，不重复核减。
- 初始化后的退隐 journal 或标记缺失/损坏拒绝打开；快照校验和 WAL 重放拒绝缺失状态。
- 真实安全模式 Master、节点与用户客户端完成计划上传、取消、物理退隐和容量释放；已发布版本覆盖后旧、新物理对象都保留。
- runner 对空 200、202、404、409、不完整、重复字段、错节点、错 attempt、超长与截断响应均不释放预留。
- 后台回收 worker 随 Scanner 取消停止并 Wait，不在数据库关闭后继续访问。

## 主审发现与修复

独立只读报告未找到容量少计，不作为验收结论。主线程构造实际元数据时序：150 字节对象退隐后采样 800 字节，其响应迟到；另一个 50 字节自治副本已完成并提交 verified 回执，但 `markProtectionDone` 丢弃回执中的节点用量且撤销其预留。迟到退隐确认因此产生 `Accounted=800, Reserved=0, Free=224`，实际用量为 850 字节、可用应为 174 字节。确定性回归先失败，再接入自治用量证明和统一对象/节点独立预留后通过。测试保留在 `master/meta/retirement_capacity_safety_test.go`。

统一容量入口还覆盖小对象和旧分块对象，避免将元数据占用与旧心跳的 `max` 错当成并集。只有完整性确认及同 epoch、足够新序号的用量证明匹配，才认为样本已经包含该对象；否则继续独立预留，可能高估但不通过删计划制造空间。

## 中途失败记录

- 接线期间缺少 import 和尚未添加 worker，导致编译失败；补齐后实际编译和定点回归通过。辅助 overlay 运行不作为最终验收。
- 自治“已落盘但回执丢失”旧夹具直接 `os.WriteFile`，没有更新节点用量，新增用量约束因此拒绝；夹具在补回执前调用启动对账，不改变原验证内容及不重传断言。
- 三节点复制的主副本磁盘丢失用例借用旧 `DELETE /objects` 来注入故障，该接口对注册节点现在应返回 426。改为在隔离测试目录直接移除主副本物理文件，保留“其余两份内容和 CRC 完好”的原断言；不把活内容退隐当作故障注入。
- 旧 GC/客户端测试期望未知孤儿经多轮扫描自动删除，或删除命名空间后立即销毁已发布对象。新合同明确禁止这两种推断；改为实际检查未知孤儿仍可报告、已发布对象持久 held 和原内容保留，不删测试掩盖问题。
- 多次子任务因额度、认证或中转并发限制中断，与测试失败分开记录。端到端测试由主线程实际写出和运行；不以“任务结束”代替验收。

## 最终验收结果

2026-10-18，在真实工作树和隔离本地数据目录完成最终串行验收。环境为 Go `go1.26.7`、macOS darwin/amd64，所有测试均绕过系统代理访问 loopback：

| 项目 | 最终结果 |
| --- | --- |
| 根模块完整 `-race -p 1` | 701 个顶层测试、341 个子测试通过，测试级 Skip 为 0 |
| 真实 macFUSE 完整套件 | 99 个顶层测试、82 个子测试通过，Skip 为 0 |
| 根模块 `go vet`、`go mod verify` | 通过 |
| 独立 P2P race 与 Darwin MONITOR 协议回归 | 通过 |
| 暂存区 `git diff --check` | 通过 |
| 源码一致性 | 最终验收前后 208 个根模块 Go/模块文件完全一致 |

按排序后的路径与文件 SHA-256 汇总，根模块源码摘要为：

`673e797a2f84f45f1e81e77d583c5db826006721c4c13dd06fdc0e61db950958`

最终完整原始输出和结果曾写入本机独立临时验收目录，包含 `final-2/results.json`、`root-race.jsonl`、`kernel-fuse.jsonl` 以及源码摘要记录。临时目录不是长期归档；仓库保存回归测试和上述可重跑依据，不提供失效的本机链接。前面失败的完整运行保留，并在修正后重新执行整套验收，不以定点通过替代全量结果。

## 可重跑命令

```bash
NO_PROXY='*' no_proxy='*' go test -mod=readonly -race -p 1 ./... -count=1 -timeout=10m
NO_PROXY='*' no_proxy='*' go test -mod=readonly -race -p 1 -tags fuse ./mount -count=1 -timeout=10m
NO_PROXY='*' no_proxy='*' go test -mod=readonly -race ./master -run 'TestSecureRetirement|TestRetirementScanner|TestRetirementWorker' -count=1
NO_PROXY='*' no_proxy='*' go test -mod=readonly -race ./master/meta -run 'TestRetirement|TestProtection|TestWriteUsage' -count=1
NO_PROXY='*' no_proxy='*' go test -mod=readonly -race ./node -run 'TestRetire|TestFence' -count=1
NO_PROXY='*' no_proxy='*' go -C prototypes/peertransport test -mod=readonly -race -p 1 ./... -count=1
NO_PROXY='*' no_proxy='*' go -C third_party/go-fuse test -mod=readonly -race ./fuse -run TestMonitorNotificationsNeverReply -count=1
go vet -p 1 ./...
go mod verify
git diff --check
```

真实 FUSE 测试必须有可用内核挂载环境；Skip 不算验收通过。无测试文件包的包级 skip 与测试用例 Skip 分开统计，根模块与 FUSE 覆盖重叠，不将数量简单相加。

## 剩余限制

- 内容仍明文，CRC 不防恶意节点；内容 AEAD、密钥托管和加密灾备未因此完成。
- 已发布旧内容暂时保留，不提供 30 天回收站、恢复 API 或可撤回的旧读字节。
- 不保证释放全部历史保守高估；并发基线变化、epoch 变化及缺少用量证明可能继续保留预算。
- 不裁剪计划/操作历史或 fence tombstone；全量历史扫描、对象反查和基线重算仍有性能优化空间。
- 当前 GC 响应的 `deleted` 仍对应未知孤儿报告，未提供后台退隐的独立统计；未知孤儿不删，因此该字段可能为 0，即使 runner 已完成其他上传对象的退隐。容量和持久 journal 才是本批确认依据，完整管理界面统计仍待补齐。
- 对象服务逻辑账不是操作系统磁盘块配额，外部写盘、备份 blob 和已打开文件的物理块占用不在本批完整预算边界内。
- 未实现正式 EC/COW、生产 P2P 网络替换或 Master 自动接管。
