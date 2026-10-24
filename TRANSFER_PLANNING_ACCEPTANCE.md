# 拓扑感知传输验收记录

## 状态

开发分支 `feat/admin-console`，基线 `e42836e`。本批没有现网部署、数据迁移、main 合并或 EasyTier 修改。使用和范围见 [TRANSFER_PLANNING.md](TRANSFER_PLANNING.md)。

完整 root 最终复跑 `go test -race -p 1 ./... -count=1 -timeout=600s` 已通过，所有有测试包均为 `ok`，无失败；master 321.717s、meta 156.608s、client 57.189s。没有把两次完整运行的时长或用例数简单相加。末尾的节点观测隔离收尾另行复跑 affected backend 包，结果见下文。

## 已验证的行为

- 纯调度器：方向性输入、入口转复制、多个入口、保持指定确认、过期/失败/反向链路拒绝、共享上下行预算、篡改路线拒绝、输入纯函数与确定性。
- 写入元数据：路线写入 WAL、并发预算复核、Done 才释放流、提交后未完成的非必要目标仍计带宽账、覆盖旧内容的保守持有、租约边界、缺开关和旧特性门禁。
- 真实普通组件：客户端不能连接第二个确认节点时只上传入口，由入口复制；最终两个节点完整落盘确认且 Master 不接收对象 payload。
- 节点执行：上/下行限速器共享预算与取消、入站滴灌读在租约到期释放并发槽与临时文件、不发布半对象。
- HTTPS-over-peer：真实外层 TLS、证书校验、准确 Master origin、路径要求与实际连接不符拒绝、未知路径不冒充直连、控制换票不继承数据路径或污染数据观测。
- 独立 P2P 原型：请求策略、fallback 尝试和实际承载路径分开，错误拨号不返回 typed-nil conn，DirectTimeout 生效；吞吐只按成功已确认字节统计，上/下行与冷拨号分别测量。
- 真实安全栈的独立 nested harness：Master+受邀节点+客户端，计划 Put→verified receipt→Commit→Get；真实 libp2p 直连与强制 CircuitRelay 路径，数据只带 at1_，匿名 healthz 不带会话，明文/错误 peer/伪票据拒绝。路径映射为受控 fixture，不等同生产自动发现。
- 多源复制：多个 immutable block 任务来源分散、同一 flow 在来源上行和目标下行分别核算、失败不偷换绑定、新租约重新选择健康源、回执丢失后本地 verify 不重传。

## 本轮修复与口径校准

1. 旧 perf 忽略策略、读取未使用 dial stats、混 PUT/GET、失败计速度且缺下行。修后分阶段计时、成功字节核验、实际路径记录和非零错误退出；旧速度数字全部作废。
2. 节点复制本就可满足 Done，但旧客户端遍历 Confirmations 直写。新增 Transfer.UploadTargets，原确认集合不减少。
3. HTTPS-over-stream 不需要伪造 `r.TLS`；真实 TLS listener 保持旧权限检查。原 draft 的双 TLS listener 用法与若干不存在的 Go API 已纠正。
4. 新数据路径 context 若透传到 Master 换票，会触发主源禁止 P2P 的闸。控制包装显式清路径/数据观测，取消与 deadline 仍继承。
5. 多源草稿误将一个租约 source+target 双算 global active、遗留 claim 无 budget 失效、预算 unsigned 下溢、第一条占满目标下行、快端速率记满造成假饱和、execute 偷换绑定。修法与测试均保留。
6. 入站计划读缺租约 deadline，可占满下载 slot。真实 TCP 滴灌回归通过，读 deadline 和 ctx 双重约束。
7. 提交后非 required 副本仍可传，不能 commit 就清全部带宽账；未 Done 腿保留至 Done 或 lease。旧内容覆盖后的 Result 快照只用于保守持有，不虚称完成。
8. 路由计数有界不代表乘积成本小。新增方向性索引及每候选有界入口组合，稠密连接测试约束执行成本；不声称全球最优。

9. 最终全 root `-race` 首轮失败于新多源测试夹具：`autKeepAlive` 并发遍历 `s.nodes` 时测试调用 `startNode` 追加 C。未忽略报告，改为所有节点加入后再启动保活；四个物理 e2e 重复三轮 `-race` 通过，随后重跑完整 root 验收。
10. Peer nested 验收在节点可达性规则更新后出现过时断言：传输计划不再要求 Master 直接 probe 节点，测试仍以“必须出现直接 Master probe”为前提。只移除该前提，保留普通地址不得承载数据、peer路径/身份/TLS/票据必须验证的断言，修后 nested `-race` 通过。

11. 节点链路观测最初串行挂在心跳与复制确认前，会被慢节点拖延。改为单个有超时的后台观测批次、最多 8 路探测，不阻塞心跳/对象确认；慢发现服务与连续心跳回归通过。

## 已完成的独立验收

- 主线程 affected backend 完整 `-race -p 1`：peerhttp、node、client、master/meta、master、cmd/atoll、scheduler 全通过。完整 root 最终复跑结果见下节；首次 root race 的夹具失败与修复已记录，不冒称首轮全绿。
- 最终节点观测隔离后 `go test -race -p 1 ./node ./master ./client ./cmd/atoll -count=1`：通过（node 12.102s、master 203.047s、client 63.797s、CLI 31.915s）。完整 root 的非 affected 包结果仍采用前一轮冻结源码验收，不伪称其在这一条命令里重跑。
- 最终真实 macFUSE `-race -p 1 -tags fuse ./mount`：通过（182.509s）。
- 最终独立 peertransport 全模块 `-race -p 1 ./...`：通过（原型 37.816s、wanrunner 4.337s），包括主线程补的 DialContext 真 nil 回归。
- 最终 peertransport-production `-race -p 1 -tags integration ./...`：通过（8.492s；观测隔离收尾后），真实 secure 直连、中继与传输计划三变体，另有原始 transport 桥负向测试。
- 根模块和两个 nested 模块的相关 `go vet`、根 `go mod verify`、`git diff --check`：通过。nested production 的 `go mod verify` 曾因两个本地 v0.0.0 replace 无缓存 ziphash 报错，未伪称全模块验证通过；本地源路径、编译与测试另行验证。
- Linux/amd64、Darwin/amd64 `CGO_ENABLED=0 -trimpath -ldflags='-s -w'` 实际编译通过。最终观测隔离后 Linux 再构建为 12,361,890 字节；此前 Darwin 构建为 12,567,952 字节。本批 root 不引入 libp2p，尺寸不是所有平台的长期地板。
- 主线程重复三轮物理多源 E2E race 通过；同一 A/B 持有文件所有块，C 为共同目标。预算夹具双方真实本地限速，源失败必须经新租约重绑，回执丢失 verify 不重传。

多源 E2E 验证并发租约持有、按块多源分工和异步派工；没有网络流重叠 barrier/吞吐对照，不声称实测并发加速或 WAN 吞吐提升。

## 验收命令

```sh
NO_PROXY='*' no_proxy='*' go test -race -p 1 ./... -count=1 -timeout=600s
NO_PROXY='*' no_proxy='*' go test -race -p 1 -tags fuse ./mount -count=1 -timeout=600s
NO_PROXY='*' no_proxy='*' go -C prototypes/peertransport test -race -p 1 ./... -count=1 -timeout=600s
NO_PROXY='*' no_proxy='*' go -C prototypes/peertransport-production test -race -p 1 -tags integration ./... -count=1 -timeout=600s
go vet -p 1 ./...
go -C prototypes/peertransport vet -p 1 ./...
go -C prototypes/peertransport-production vet -p 1 -tags integration ./...
go mod verify
git diff --check
```

根模块与独立 nested modules 必须分开运行；`go test ./...` 不自动包含嵌套模块。`-p 1` 必须放包路径之前，不使用掩盖退出码的 head/tail/grep 管道。

## 明确未完成

- 无 overlay 的 27119↔28425 公网直连打洞与可靠双向基准，本地结果不作为 WAN 速度保证。
- Atoll CLI 自动建立 libp2p host、PeerID 与受邀设备身份绑定、地址发布和撤销同步。当前生产传输抽象可接 resolver，真实接线经受控测试验证。
- 单个对象内 Range 多源拼装、EC/COW 编码和任意长度转发图。
- 原写入计划内实时改路由，以及公平限速器的按优先级/测得好吞吐动态重分配。当前预算是有界启发式不是完整带宽学习器。
- 节点上报连接可达性仍是带来源身份的观测，不是第三方签名证明；它不改变内容完整性或保存确认条件。
- 正式部署替换、迁移和合并 main 不在本次授权范围。
