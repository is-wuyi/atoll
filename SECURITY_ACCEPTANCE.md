# 安全模式批次验收记录

## 结论

2026-10-15，账号、空间、节点身份与在线访问票据批次完成本地实现和主线程最终验收。**最终全部测试与检查通过，测试期间源码未变化，FUSE 没有跳过项。**

本记录对应工作区分支 `feat/admin-console`，实现与原验收基线 HEAD 为 `7537663efe962ae1e4d80ba3fc7e2672110946ec`。2026-10-18 按已批准的发布规则整理提交并推送开发分支。没有部署真实 NAS，也没有修改或重启 EasyTier。下述测试数与摘要属于本批原验收，不与后续批次复跑混为同一次运行。

使用方法和产品边界见 [SECURITY.md](SECURITY.md)。本次完成的是账号与授权链路，不是整个边缘存储重构计划完成。

## 交付范围

- 受邀账号、bcrypt 密码校验、24 小时用户会话、登出、改密及禁用。
- 独立个人空间、多团队空间、owner/read/write 权限及平台管理员全空间访问。
- 节点持久 Ed25519 身份、一次性设备邀请、挑战登录、设备会话续期和吊销。
- 用户与设备会话只发送给 Master；节点对象访问使用短期受众绑定票据，逐请求在线检查当前授权。
- 分块上传、读取、节点复制、修复和自治增加副本的安全接线。实际复制与修复检查了各目标磁盘内容及 verified 回执，不仅检查下载成功。
- 已初始化库与节点目录的防降级保护；配置损坏、身份标记不匹配时拒绝。
- 有界安全记录清扫、设备挑战数量上限、失败请求资源清理、请求目标与超时边界。
- 真实 TLS 命令行和 macFUSE 内核挂载测试。

## 主线程最终测试

环境为 macOS / darwin amd64，Go `go1.26.7`。全部在真实工作树运行，没有 overlay 或镜像代码替代；网络测试使用本地隔离组件并配置 `NO_PROXY='*' no_proxy='*'`。

| 验收项目 | 最终结果 |
| --- | --- |
| 根模块 `go test -mod=readonly -race -p 1 ./... -count=1` | 614 个顶层测试、193 个子测试通过，无测试 Skip |
| 完整挂载套件 `go test -mod=readonly -race -p 1 -tags fuse ./mount -count=1` | 94 个顶层测试、77 个子测试通过，无 Skip |
| 安全模式内核测试 | 上述挂载套件内 20 个 `TestSecureKernel*` 全部通过 |
| TLS CLI 实际子进程验收 | 根模块套件内 13 个子测试全部通过 |
| 独立 P2P 模块 race 回归 | 21 个顶层测试、4 个子测试通过，无测试 Skip |
| Darwin `MONITOR` 协议回归 | 根目录、普通 inode、启动探针 inode 的两类通知均不回包 |
| 额外启动压力测试 | 120 次真实挂载首次创建操作通过；捕获 480 次 MONITOR，无 ERANGE 回包 |
| 静态与来源检查 | 根模块、P2P、本地 go-fuse 的相关 `go vet`，`go mod verify`，`git diff --check` 全部通过 |

没有测试文件的包在 `go test -json` 中会产生包级 skip 事件，未计入“测试 Skip”；以上无 Skip 指测试用例没有跳过。根模块与挂载套件有覆盖重叠，不将两者数量相加当作独立用例总数。

TLS CLI 测试构建并运行实际 Atoll 二进制，生成测试 CA 与有效主机名证书，启动一个 TLS Master 和两个受邀节点；覆盖空、小、分块文件往返，个人/团队空间，权限降级和移除，登出，吊销幂等，证书错误、不安全配置拒绝及同库重启。子进程结束后执行 Wait；这证明本地数据库持久化，不代替集群灾备恢复演练。

安全 FUSE 测试实际调用 `fs.Mount`，挂载失败为 Fatal。包含写入、空文件、覆盖、目录、改名、删除、重挂读回和权限撤销。独立读取进程不等于绕过内核页缓存；持久读回和权限验证分别使用重挂以及真实 HTTP 票据核验。已经交付或缓存的字节不能被远程撤回。

## 复核与修复记录

关键结论经过主线程代码核对和独立回归，而非只接受子 agent 的完成报告。

1. **安全配置损坏降级**：原实现把解析失败当作未启用。现区分错误、未初始化及有效初始化，心跳、节点列表和启动入口在损坏时拒绝。缺失配置但残留账号状态也不能回到 legacy。
2. **吊销重试**：已吊销设备重复调用不再报认证错误；即使本地状态已生效，返回成功前仍按持久化策略确认。补了持久化失败重试、缺失 liveness 行等回归。
3. **设备会话续期**：收到 401 后按实际被拒的 token 条件重建；迟到的旧 token 请求不能反复作废新会话。Master 区分无效设备会话的 401 与合法设备越权的 403，实际节点测试验证本地仍未临期的失效会话可以恢复。
4. **节点身份标记**：首建使用原子不覆盖发布，已有文件验证类型、身份和 Master 绑定，并同步文件及目录。拒绝符号链接、损坏、超长标记和不同身份覆盖。
5. **客户端与传输契约**：换票期限取父期限与 30 秒的较早者；拒绝不一致的请求目标；失败授权关闭请求体而不消费对象 payload。登录错误响应不能覆盖有效旧会话；空 `SetSession` 保持合法清会话语义，指定空间但无会话的 CLI 不回退旧根。
6. **安全记录清扫**：每个前缀最多检查 4096 条，游标属于单个 Store 并与清扫串行管理。直接调用 `SweepSecurityTickets` 也能续扫，未向调用方暴露内部游标。挑战复用包含邀请绑定，过期/已用凭据回收不会放宽授权。
7. **测试夹具**：修正了注册/登录使用不同用户名、用户 ID 与空间 ID 混用、硬编码错误对象 ID、挂载点清理次序等问题，保留了真实权限与节点访问测试。

## macFUSE 首次操作 ERANGE：失败证据与真正修复

最终验收前，两轮完整 FUSE 套件曾失败：一轮的两个旧测试在首次 create/mkdir 返回 `result too large`，另一轮新增启动诊断用例有四个子测试复现。单独重复旧测试与初次 40 次启动测试曾全部通过，**当时没有据此宣称已修复**。

失败与成功协议对照定位到 go-fuse v2.11.0：

- `.go-fuse-epoll-hack` 的 `MONITOR` 通知落入 `doPollHackLookup` 默认分支，产生 `ERANGE`。
- 普通 inode 的 `doMonitor` 虽设置请求级 `suppressReply`，分发器尾部却按 handler 的 `SuppressReply` 覆盖为 false。
- 因而本应无响应的 MONITOR 被回包；失败日志中该响应与后续用户请求编号复用交错。

协议级回归先对原始行为失败，再在 Darwin handler 注册中增加 `SuppressReply: true` 后通过，覆盖根、普通 inode 和启动探针 inode。修复后的 120 次实际启动压力测试、完整 FUSE 回归全部通过。没有使用睡眠、重试创建操作或关闭并发来掩盖缺陷。

根 `go.mod` 新增本地 `replace`，使用 [third_party/go-fuse](third_party/go-fuse/ATOLL_PATCHES.md)。它来自已校验的原始 v2.11.0 模块归档，保留 LICENSE 与全部原文件：仅 `fuse/opcode_darwin.go` 有上游生产代码差异，新增本地补丁说明和一份回归测试。依赖版本未升级，根 `go.sum` 逐字节未变，未修改 Go 模块缓存。更早没有协议日志的偶发错误不追认根因。

## 证据与可重跑性

原验收曾将完整日志写到本机临时目录。该目录不是长期归档，2026-10-18 发布整理时已不存在，因此这里仅保留日志名称，不提供失效的本机链接：

- `summary.json`：最终汇总。
- `root-race.jsonl`、`fuse-race.jsonl`：根模块及完整 FUSE race。
- `monitor-protocol.jsonl`、`peertransport-race.jsonl`：Darwin 协议及 P2P race。
- `fuse-startup-failed-protocol.txt`、`fuse-startup-fixed-after-reboot.log`：失败启动协议与修复后的启动压力日志。

本文件保存原验收结论，回归测试与本地依赖补丁保存在仓库。原最终运行前后所有 Go 源码、go.mod/go.sum 内容汇总 SHA-256 一致：

`8d335ea5c00bcf0fdd7b67fd3d44bdc2eb78f1972f3e5faa2529c6cd946bfe56`

复跑命令：

```bash
NO_PROXY='*' no_proxy='*' go test -mod=readonly -race -p 1 ./... -count=1 -timeout=10m
NO_PROXY='*' no_proxy='*' go test -mod=readonly -race -p 1 -tags fuse ./mount -count=1 -timeout=10m
NO_PROXY='*' no_proxy='*' go -C third_party/go-fuse test -mod=readonly -race ./fuse -run TestMonitorNotificationsNeverReply -count=1
NO_PROXY='*' no_proxy='*' go -C prototypes/peertransport test -mod=readonly -race -p 1 ./... -count=1 -timeout=5m
go vet ./...
go -C prototypes/peertransport vet ./...
go -C third_party/go-fuse vet ./fuse
go mod verify
git diff --check
```

## 未完成与部署限制

- 文件仍未在客户端加密，节点能读取所持对象；内容加密、密钥托管和恢复包尚未接线。
- secure 模式集群元数据备份/恢复主动禁用，必须保管离线本地数据库备份。
- 仍无回收站、正式 EC、extent/COW、自动接管或桌面账号 GUI；内置 P2P 未替换 EasyTier。
- CLI 小文件仍可能经 Master 代理；安全 FUSE 非空写入及分块文件数据直连节点。
- 逐请求在线授权依赖单 Master；失联时拒绝访问，不能撤回在途请求或已缓存数据。
- 有限挑战配额与认证并发不等于完整公网防滥用。全路径带宽整形、周期全盘 scrub、长期在线规律模型及真实 WAN/NAS 灰度不在本次验收范围。

后续值得优化但本批未扩展的部分：全局命名空间准入锁会串行化部分请求；逐次换票与整块校验增加控制往返和随机读开销；部分对象反查仍需遍历。优化应保留当前授权、校验和持久化契约，不通过省略检查换取表面速度。
