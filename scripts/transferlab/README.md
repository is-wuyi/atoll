# transferlab —— f9b7a73 闭环隔离实机测试 runner

非正式部署工具：在 EasyTier 隔离 mesh 内，用**生产** `master.Server`/`meta.Store`、
`node.Node`、`client.Client` 跑拓扑感知上传与多源补副本的真实闭环。核心
master/node/client 零改动；本目录只新增 `cmd/transferlab`。

边界声明（务必遵守）：

- 所有配置经 `-config <私有JSON>` 传入，含**随机共享 Bearer token**（≥24 字符，
  `atoll auth gen` 生成）。token 不入 repo、不进日志、错误信息不回显。
- 监听必须显式绑定 mesh 域名/IP（配置校验拒绝 `0.0.0.0`/通配），防止匿名
  `/healthz` 与 lab 端点暴露公网。
- 样本为确定性生成的随机 plain 数据；本工具**不声称 AEAD/安全模式授权验证**。
- 可选 `dns_server`（数值 `IP:port`，如 mesh 中心 DNS）：本测试进程解析经
  **loopback 随机端口 DNS 代理**（`applyDNSOverride` 返回 cleanup，main defer）→
  上游。相同 (name/type/class/rd) 的常规 Go 查询（A/AAAA、IN、Z/AD/CD=0、
  EDNS 仅默认 OPT DO=0 无 option）的缓存命中不再查询上游；首次并发缺失仍可能
  分别转发。命中回包 TTL 置为剩余秒数（只改 ANSWER 区、不延长、封顶 30s）；SERVFAIL/NX/
  timeout/空答案不缓存；上游仅 UDP（53/tcp 已实测拒绝，TC 场景显式快速失败），
  每次尝试等应答 read deadline 4s、最多 3 次，全败回合成 SERVFAIL；pending≤32、
  cache≤512。只问这一台、无系统/公共 DNS 回退，不改系统解析/hosts/EasyTier。
  非生产网络修复，仅供隔离 lab 复用。节点 advertise/master 仍全用域名。
- 不改生产 `types.ChunkSize`（64MiB）；多块由 >64MiB 样本自然形成。
- fault 场景不杀生产进程：只对样本对象 GET 注入 延迟/中断，对 PUT replicate
  注入“确认失败”（数据入库、201 翻 503，重试幂等收敛）。

## 角色

```
go build -o transferlab ./cmd/transferlab
chmod 600 /私有路径/*.lab.json        # 含共享随机 Bearer，LoadConfig 拒绝非 0600；符号链接一律拒绝
./transferlab -config /私有路径/master.lab.json    # role=master
./transferlab -config /私有路径/node-a.lab.json    # role=node  (label A)
./transferlab -config /私有路径/drive.lab.json     # role=drive (本地 Darwin 或任一机)
```

三个 role 都是前台进程，SIGINT/SIGTERM 触发有界 HTTP shutdown，Master 等自身扫描器退出再关库；不声称节点的全部后台任务都由测试工具等待。
drive 的一切临时文件走 `os.CreateTemp`（唯一名、用后即删），不落固定路径；
`report_path`/`events.ndjson` 按主线程指定的新目录写入。

## 私有配置字段（冻结）

时长一律字符串（`"30s"`）。按 `role` 取用对应字段。

| 字段 | master | node | drive | 默认 |
| --- | --- | --- | --- | --- |
| `role` | ✓ | ✓ | ✓ | — |
| `token` | ✓ | ✓ | ✓ | — |
| `dns_server`（可选） | ✓ | ✓ | ✓ | — |
| `listen` | ✓ mesh域名:29460 | ✓ mesh域名:29461 | — | — |
| `db` | ✓ | — | — | — |
| `master` | — | ✓ http://mesh:29460 | ✓ | — |
| `advertise` / `data_dir` / `label` / `total_bytes` | — | ✓ | — | 100GiB |
| `upload_bps` / `download_bps` / `transfer_concurrency` | — | ✓（本地执行闸） | — | 4MiB / 16MiB / 4 |
| `node_max_age` `write_max_replicas` `autonomy_interval` `autonomy_retry` `autonomy_bytes_per_round` `autonomy_dispatch_per_step` `repair_interval` `gc_interval` | 可选 | — | — | 30s/8/1h/30s/256MiB/2/**1h**/10m |

注意：master role **不启动自治后台循环**（`autonomy` 仅装配，派工只由 `/lab/step`
显式触发），修复扫描默认拉长到 1h——缺块必须由显式 `/lab/reserve`+`/lab/step`
补齐，不允许后台修复提前把“第三副本”掩掉；GC（两轮确认）与死亡监视保持常态。
| `nodes[]` {label,addr,upload_bps,download_bps,max_concurrent} | — | — | ✓（与各 node cfg 同值） | — |
| `ingress` | — | — | ✓ 单入口场景唯一可达 label | — |
| `sample_bytes` | — | — | ✓ >64MiB | 192MiB（可先 80MiB=64+16） |
| `client_upload_bps` / `client_download_bps` / `client_concurrent` | — | — | ✓ | 4MiB / 16MiB / 2 |
| `remote_dir` `scenarios` `report_path` `join_wait` `step_interval` `observe_wait` `scenario_deadline` | — | — | ✓ | /transferlab、[one-ingress,protection]、—、10m、3s、12s、6m |

drive 预检（硬校验，超界 exit 2）：样本必须 >64MiB；`64MiB/(client_up/2) < 140s`
（150s ioTimeout）；`样本/client_up + 样本/最小节点up < 270s`（传输计划 300s TTL）。
即 192MiB 样本需节点/客户端 up ≥2MiB/s（4MiB/s 为默认）；80MiB 样本 1MiB/s 可行。

## lab API（全部经共享随机 Bearer，错误不回显 token）

master（29460）：

- `GET /lab/status` → `{now_utc, nodes, profiles, plans, objects, capacity,
  profile_revision}`。`plans[].targets[]` 含 `source_id/source_addr/next_attempt
  (lease expiry)/attempts/done/last_error` —— 主线程验证共享字段。
- `POST /lab/profiles` `{"profiles":[NodePlacementProfile]}` → 逐节点
  `store.SetNodePlacementProfile`（failure_domains 建议 `{"site":label}`）。drive
  侧 `applyProfiles` 与现值逐字段深比较（含空/nil 故障域），只写有差异的节点；
  全部一致则跳过 POST（不 bump revision，保护既有 pending 计划）。有差异时
  revision 前移会使 pending 计划 stale，drive 会在 stderr 显式警告。
- `POST /lab/reserve` `{"path":"/transferlab/one-ingress.bin","target_id":C}`
  → **admission**：逐 chunk `ObjectIntegrity` → 持久 `ReserveProtection`
  （真实容量/心跳/profile revision 校验）。**不是请求级幂等**：plan id 每次请求
  随机生成，重复 reserve 同一对象会被 meta 层以“已存在 pending plan”拒绝；
  调用方（drive/主线程）重取 `/lab/status` 采纳既有 pending 计划（adopt-pending，
  当前 lab 语义）。逐对象返回 `{object_id, plan_id, state, error}`，已覆盖返回
  `already_present`。**绝不模拟 Done。**
- `POST /lab/step` → **dispatch**：生产 `autonomy.Step`（claim 源绑定 → 目标
  `/pull` → 节点真 verify 回执）。可反复调用直至 plans completed。

node（29461）：

- `GET /lab/status` → `{label, node_id, active_gets(原子), totals{gets,puts,
  replicates}, dropped, fault, now_utc}`。
- `GET /lab/events` → NDJSON 事件：`start_utc/end_utc(UTC)、duration_ms
  (monotonic)、body_bytes、node_id、label、method、path、range、fault`。
  **绝无 Authorization 头或对象内容。** 录制 `GET /objects/{id}`（含 master
  1 字节 Range 探测，`range` 字段可区分）、`PUT /objects/{id}`（client 入口）、
  `PUT /replicate/{id}`（A→B 腿接收）。
- `POST /lab/fault` `{"kind":"read_delay|drop|ack_error","target":"get|
  replicate|all","object_id":N(0=全局),"delay_ms":N(1..60000,≤60s)}`；
  `DELETE /lab/fault` 清除。read_delay/drop 只命中**完整对象 GET**（master Range
  探测不受影响）；read_delay 随客户端取消提前结束；ack_error 只作用于 PUT
  replicate/all。主线程可经 SSH 手控故障时序。

## 场景与退出码

- `one-ingress`：drive 客户端 RoundTripper 拒绝非入口地址（仅 client 策略）→
  security 档（只调权重不降保护）→ 真实 `PutChunked` 分块上传 → 断言每块
  `Done≥2`（不足则 **skip**，不降档重试）、非入口节点无客户端 PUT 但有等字节
  `PUT /replicate`、整文件 sha256 读回一致。
- `protection`：同路径样本，`/lab/reserve`(target C) → `/lab/step` 轮询 → C 上
  逐块 sha256+CRC32C、整文件 sha256、Done 集复查；源分布仅报告不硬断言。
  A/B 固定布局的既定部署次序：先起 A/B → drive `one-ingress` → main 起 C →
  drive `protection`（同一 remote 路径，分场景调用不重复上传）。

退出码：`0` 全过；`1` 基建错误；`2` 配置/预检失败；`3` 诚实跳过（planner 未选
≥2 确认、无缺块目标等）；`4` 断言失败。报告写 `report_path`（JSON）与
`report_path+".events.ndjson"`（全节点事件）。

## 主线程交接

- 私有 cfg 与 binary 分发由主线程管理；drive 只需可达 master 与各节点 lab 端口。
- 部署次序、C 的启动时机、fault 手控时序由主线程掌握；drive 忠实报告，不伪装。
- 节点事件 ring buffer 4096 条（溢出计 `dropped`），进程重启即清空——在场景
  结束后尽快收集。
