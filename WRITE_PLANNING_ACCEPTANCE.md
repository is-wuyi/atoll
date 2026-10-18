# 计划写入批次验收记录

## 范围与状态

本批落地统一内容版本/不可变对象描述、目录与文件保护偏好继承，以及调度器新写入计划、具体确认集合、持久预留和原子发布。使用与限制见 [WRITE_PLANNING.md](WRITE_PLANNING.md)。

工作区分支为 `feat/admin-console`，实现与原验收基线 HEAD 为 `7537663efe962ae1e4d80ba3fc7e2672110946ec`。2026-10-18 按已批准的发布规则整理提交并推送开发分支；没有部署真实 NAS、迁移数据或修改 EasyTier。原始验收结果记录下文，发布前另行复跑，不以临时日志路径作为长期可用的证据。

**三路定点复核、主线程修复和最终整套验收已完成。** 根模块完整竞态回归、真实 macFUSE 套件、TLS CLI、独立 P2P、MONITOR、静态与依赖来源检查全部通过，没有测试用例跳过。最终验收期间 479 个 Go 源码与模块文件未变化。

## 已验证的关键行为

- 调度器在可执行复制布局和具体确认集合之间联合评分；档位仅为权重，默认没有隐藏的单节点故障硬下限。显式容量、在线、故障域等约束在独立验证器中重算。
- Begin 冻结 actor/space、有效策略、覆盖目标 ID/Generation 和操作 ID；每块在上传前冻结对象 ID、尺寸、编码、CRC、目标和确认集合。
- 原子发布检查连续块表、真实总长、所有指定确认节点、当前权限和目标 CAS。非指定节点不能补齐缺失的指定确认。
- 普通文件覆盖保留 FileID，增加 Generation，发布新的独立 ContentVersion；空文件没有虚构对象或副本。
- 客户端小文件、多块、流式和空文件均可走新协议；非空 payload 直接发计划节点。旧客户端数字参数不改变确认条件。
- 网络丢失提交响应时，以同 operation ID/binding 重放；FUSE 同句柄计划错误之后不自动创建另一上传。
- 容量竞争、已用量盖住新预留、提交后重复分配、旧心跳乱序，以及缺少节点用量证明时的保守预留都有回归。
- secure 模式下真实节点在线换票、当前用户/团队权限、设备有效性及平台管理员访问继续生效；静态控制凭据不能作为文件写入用户。
- 状态、计划、结果和必要容量证据写入 WAL；重放成功仍执行 `EnsureDurable`。同库进程重启和独立 WAL 重建分别测试，不混同集群灾备。
- 新内容清单与兼容块表交叉校验，`plain-v1` 以外编码及尺寸不一致拒绝。

## 验证环境与结果

环境：macOS/darwin amd64，Go `go1.26.7`。全部使用真实工作树和隔离本地数据目录，网络设置 `NO_PROXY='*' no_proxy='*'`。未采用 overlay 或删减原测试替代真实实现。

| 验收项 | 当前结果 |
| --- | --- |
| 新写调度、元数据、HTTP、安全、客户端和挂载定点 race 回归 | 通过 |
| 真实 CLI：TLS Master、两个受邀节点、保护偏好、空/小/大文件、同库重启、漏开关拒绝 | 通过 |
| 完整 macFUSE 挂载套件 | 99 个顶层、82 个子测试通过，0 个测试跳过 |
| 满容量节点同对象重试、坏请求拒绝、慢请求与删除交错 | 通过 |
| 根模块最终完整 race 回归 | 666 个顶层、305 个子测试通过，0 个测试跳过 |
| 独立 P2P race 回归 | 21 个顶层、4 个子测试通过，0 个测试跳过 |
| Darwin MONITOR 协议回归 | 1 个顶层测试通过，内部覆盖根、普通 inode 与启动探针通知 |
| 静态与来源检查 | 根模块、P2P、go-fuse 的相关 vet、mod verify 和 git diff --check 均通过 |
| 三路独立复核 | 已收拢；三个问题由主线程复现并修复，定点回归通过 |

没有测试文件的包可能出现包级 skip，不等同于测试用例跳过。挂载套件与根模块有覆盖重叠，不把测试数简单相加。CLI 测试运行真实构建的子进程；父测试带 race 不表示普通 `go build` 产生的子进程也被 race 插桩。

## 中途失败与修复

1. 旧调度验证器把零容错也视作一次故障要求。本批新写入口使用独立验证逻辑，默认零是实际零；旧自治修复行为未被无意改写。
2. 首次持久结果比较误把 `time.Time` 的未序列化单调时钟纳入比较，改为比较实际 JSON 持久结果，保留幂等和同步失败重放测试。
3. 新能力协商使旧小文件请求次数断言失败。协商前移到挂载初始化，未启用结果短缓存；原单小文件写请求断言恢复，不删除断言。
4. 部分旧 mock 对所有 URL 返回错误，导致初始化失败、原目录/容量错误语义测试无法开始。只让夹具放行 `/capabilities`，业务请求保留原失败注入。
5. 新挂载反旁路测试曾错误把 `/files/replicated/verified` 算作旧上传。修正为精确匹配旧上传入口，内容绑定节点回执仍是必需流程。
6. 真实内核验收发现已提交零块空文件被 FUSE 的“无节点地址”检查拒绝为 EIO。现只对非空文件要求节点地址，修复后完整内核套件通过。
7. 同一不可变对象重试在节点满容量时错误要求第二份临时空间。新增反例先失败，再加入验证已落盘对象与完整请求的重放路径；失败不改旧对象、不减其他预留。慢请求不长时间持有对象分片锁，提交前再次核对文件身份；并发删除后不得迟到确认。

8. 调度复核反例显示 `MaxCandidates=256` 实际评分 6115 个候选。主线程将通过和被拒绝的候选对都纳入总预算，并在布局规模间分配预算，先尝试故障域分散的种子；12/20/32 节点、预算 1～4096 的回归均通过。扩展测试又发现“32 选 32”组合递归仍遍历不可能完成的分支并触发 90 秒超时，补齐剩余位置剪枝后通过。
9. 跨启动代的迟到心跳可把旧对象占用与历史占用的并集算少：1024B 总容量、800B 历史占用、150B 新内容，真实 free=74B，旧样本回退后却报告 224B 并放行新写。主线程修正测试夹具后复现；现在跨随机 epoch 保留用量下限，变化记入 WAL，设备重认证保留它，不能用迟到样本释放空间。该方案可能保守高估，尚未实现证明安全的下限释放器。
10. 共享 FUSE 写句柄时，后台计划错误可能在 Close/dropStreamingLocked 中被丢弃，随后 Flush 新建上传并成功。主线程用真实本地 Master/node 重建反例；现在丢弃流式会话前后都保留原错误，主动取消本身不伪装成上传失败。额外补充客户端并发 Close/Finish 和等待中的 Push 测试，Close 取消后会等待正在结束的 Finish 请求退出。

中途失败均保留日志。子 agent 的报告仅作为线索：容量测试有反向断言，生命周期夹具有不存在字段、缺失流式前提和引入内容截断的问题，均由主线程修正后才采纳；不以“报告称已复现”替代实际执行。

## 明确未完成的能力

- 内容 AEAD 生产接线、中心密钥托管与加密灾备恢复包；对象仍明文落盘，CRC 不是恶意节点存储证明。
- 正式 EC/COW、通用 extent 执行器、30 天回收站和完整的有效句柄引用生命周期。
- 内置 P2P 的生产接线与真实 WAN/NAS 校准、Master 自动接管。
- 本批原验收时尚无自动安全释放不确定字节、跨启动代用量下限及计划历史裁剪；后续 [对象退隐批次](RETIREMENT.md) 补了未发布上传的持久封禁、回收确认和有限基线扣减。已发布旧内容、未知容量和计划历史裁剪仍保守保留，不会为腾预算删除计划假释放。
- 当前探测 RTT 是 Master 到节点的观测，不代表客户端链路或节点间吞吐。全量容量/对象扫描和每块规划仍有优化空间，本地小规模测试不构成性能承诺。

## 源码一致性与复跑

最终串行验收记录了运行前后的 Go 源码、go.mod 和 go.sum，479 个文件完全一致；按排序后的路径与文件摘要聚合，SHA-256 为：

`9bc3e55d7a437c5c1b43d939987e57041e8c242aed22ee4300633026ff723a00`

本批未新增根模块依赖。根 `go.mod` 相对 HEAD 的本地 go-fuse replace 来自前一安全批；根 `go.sum` 未改。原始运行结果保存在 `review-final/results.json`，源码一致性记录 `review-final/source-check.json` 的 `changed` 为 `[]`。

```bash
NO_PROXY='*' no_proxy='*' go test -race -p 1 ./... -count=1
NO_PROXY='*' no_proxy='*' go test -race -p 1 -tags fuse ./mount -count=1
NO_PROXY='*' no_proxy='*' go -C prototypes/peertransport test -race -p 1 ./... -count=1
NO_PROXY='*' no_proxy='*' go -C third_party/go-fuse test -race ./fuse -run TestMonitorNotificationsNeverReply -count=1
go vet -p 1 ./...
go -C prototypes/peertransport vet -p 1 ./...
go -C third_party/go-fuse vet ./fuse
go mod verify
git diff --check
```

## 2026-10-18 发布前复跑

整理提交前重新在实际工作树运行完整验收：根模块 `-race -p 1` 为 666 个顶层测试、305 个子测试通过；真实 macFUSE 套件为 99 个顶层测试、82 个子测试通过，测试级跳过均为 0。根模块 `go vet`、`go mod verify` 通过，运行前后 `.go`、`go.mod`、`go.sum` 无变化。P2P 嵌套模块单独通过 21 个顶层、4 个子测试与三次 7 场景 demo；Darwin MONITOR 协议回归通过。

本次先前两次测试启动因辅助脚本拼错日志路径而未执行，不计为测试失败或通过。修正后只统计实际执行产生的退出码与 JSON 事件；主线程接手完成 FUSE、静态检查和源码摘要核验。已提交的上游 go-fuse 原始文件保留其原有空白，Atoll 自身新增与改动通过暂存区 `git diff --check`。

## 原始证据

原验收日志曾保存在本机独立临时目录。2026-10-18 发布整理时该目录已不存在；以下名称仅说明原证据构成，不代表仓库内提供了日志归档。

- `baseline-source.tar.gz`、`baseline.json`：本轮接手时源码基线。
- `first-regression.log`、`root-regression-2.jsonl`：中途完整回归及失败记录。
- `kernel-planned.log`、`kernel-planned-2.log`：空文件内核反例与修复后验证。
- `fuse-regression.jsonl`：复核前完整 macFUSE 基线验收。
- `targeted-review.log`：计划/容量/权限/CLI 定点竞态回归。
- `search-review-before.log`、`search-review-after.log`、`search-review-after-2.log`：候选预算反例、组合枚举超时及修复后回归。
- `capacity-review-before.log`、`lifecycle-review-before.log`：主线程实际复现的容量与共享句柄反例。
- `review-fixes-targeted.log`、`review-lifecycle-capacity-after.log`：修复过程中的定点验证；中途夹具编译错误保留。
- `root-final.out`、`validation-results.json`：复核前完整基线验收。
- `review-final/root.out`、`review-final/fuse.out`、`review-final/p2p.out`、`review-final/monitor.out`：复核修正后的最终测试。
- `review-final/results.json`、`review-final/summary.json`、`review-final/source-check.json`：最终结果、用例数量和源码一致性。

`/tmp` 不是永久归档；测试和本文件保留可重跑依据，不假定重启后原始目录仍在。
