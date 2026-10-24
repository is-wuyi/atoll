# 调度器计划写入（write-plan-v1）

这是边缘主存储重构的一个纵向批次：统一内容版本和对象描述，并让 Master 调度器决定新写入的复制布局、具体确认集合和是否接受保存。**默认关闭，尚未部署真实集群。** 不改变已有用户数据，不迁移 EasyTier。

## 启用与保护偏好

在独立测试数据库上给 Master 增加：

```bash
./atoll master -db ./lab.db -write-planning -write-max-replicas 8
```

安全模式继续保留 `-secure`、TLS、私有控制凭据及已初始化账号库的要求；`-write-planning` 与安全模式是独立开关。开启会把状态写入数据库和 WAL，随后重启必须保留此开关。配置损坏、配置与初始化标记不一致、启用过但本次未配置 planner 都会拒绝服务，不会恢复旧写入入口。尚未实现可逆的降级迁移，不要用旧二进制打开已启用的新库。

`-write-max-replicas` 是搜索上限，不是目标副本数，也不是确认数。

```bash
./atoll protection /docs security
./atoll protection /docs/subdir performance
./atoll protection /docs/subdir inherit
./atoll protection /docs/file
```

保护偏好为 `performance`、`normal`、`security`；`inherit` 删除本地覆盖、恢复祖先继承。偏好只改变优化评分权重，不对应固定的 1/2/3 副本表。继承在当前用户空间根停止，不穿越到其他个人或团队空间。平台管理员可访问全空间，但一次上传仍绑定发起者和选定空间。

Begin 时冻结有效策略、目标文件身份及 generation；改变目录策略不改变已经开始的上传。文件自身的覆盖偏好优先于目录继承。当前只影响新内容写入，不自动重新布置旧内容；旧自治增加副本控制器仍有其独立策略，见 [AUTONOMY.md](AUTONOMY.md)。

## 最小模型

- `Inode.ID` 保持逻辑文件身份；覆盖普通文件时原子换内容、递增 `Generation`，不换 FileID。
- `ContentVersion.ID` 标识本次不可变内容，独立于 FileID 和 Generation。
- `ContentExtent` 描述逻辑区间与对象内偏移；本版只接受连续、固定分块的完整内容视图，不执行任意 COW 或稀疏 extent。
- `ContentObject` 独立保存对象 ID、对象版本、逻辑尺寸、存储尺寸、编码及已知 CRC。
- 写计划持久保存初始复制目标、具体确认节点及解释；`Chunks` 保持兼容读取所需的实际副本位置和 Done/Suspect 状态。

本批写入路径执行 **replicate 布局**，plain-v1 与 aead-record-v1 两种编码（逻辑尺寸与存储尺寸在 aead 下由记录布局决定，见 [安全说明](SECURITY.md)）。后续批次已接入客户端加密直传、密钥托管与密钥恢复包；未知编码、EC 布局和不一致的内容/块表仍会被拒绝。非空 CRC32C=0 有明确 known 标志，不被解释为“无需校验”。

## 写入闭环

1. 客户端通过 `GET /capabilities` 发现模式。只有 404/405 表示旧 Master；其他错误或不完整响应均拒绝继续。未启用结果短缓存 30 秒；一旦该 Client 看到启用，整个实例不再降级。挂载初始化先协商，避免每个小文件增加一次探测。
2. `POST /writes` 冻结路径、用户/空间、覆盖条件、目标 CAS、策略和操作 ID。已知大小为非负数，流式总长使用 `-1`。操作 ID 在 actor/space/kind 下隔离；重放不得换请求。
3. 每块上传前，`POST /writes/chunks` 把逻辑/存储尺寸和 CRC 提交给 Master。Master 根据当前容量、心跳、可达性、放置资料和历史，联合选择复制布局及确认子集，再通过独立 validator。
4. 元数据事务重验计划绑定、profile revision、节点有效性及容量，持久保存方案和预算。后续块插入不会修改上传 binding 的 `Revision=1`，允许有限流水线。
5. 默认客户端直传确认集合里的节点；启用后续 `-write-transfer-planning` 时，客户端只上传计划入口，由入口按冻结路线复制到其他目标，保持同一确认集合，见 [传输计划说明](TRANSFER_PLANNING.md)。两种路径都不经 Master 转发 payload。节点按 Master 权威描述校验完整长度和 CRC，临时文件同步、原子改名及目录同步后发送 verified 回执。其他目标通过既有节点复制/扫描修复补齐。
6. `POST /writes/commit` 在单个事务里重查当前 ACL、原目标 CAS、完整连续块表、总长度及**每个指定确认节点**的 Done、非 Suspect、在线/有效身份。通过才发布内容与幂等结果。成功和重放都经过 `EnsureDurable`，遵循已有 WAL 同步策略。

空文件同样 Begin→Commit，但不分配对象，也不要求虚构数据副本。FUSE 零块空文件读取直接 EOF。

### 确认与拒绝

`RequiredConfirmations` 等于具体确认集合的大小，不是“任取 q 个节点”。额外节点完成不能替代缺失的指定节点。默认新写策略没有隐藏的“必须容忍一次节点故障”硬下限；结构上非空内容至少要有一份有效落盘确认，具体保护要求由 planner 选择。独立 validator 同时检查最终目标与发布时确认状态；显式配置的硬约束不得为了成功而降低。

评分是有限候选、有限预测窗口的相对启发式，不是全局最优、全天在线或耐久性保证。`Search.MaxCandidates` 同时约束通过与被拒绝的候选对总数，`EvaluatedCandidates` 给出实际评估数；预算在不同布局规模间分配，有限搜索优先尝试故障域分散的候选。找不到方案表示本次有界搜索未找到可行解，并非数学上证明任何布局都不可行。当前性能观测在默认路径中来自 Master 到节点的探测，不代表客户端到节点或节点间带宽；传输计划开关增加方向性端点观测与配置预算，测量/保证边界见 [传输计划说明](TRANSFER_PLANNING.md)。没有完成多日/周周期预测校准。

旧 `replicas`、`min-copies` 参数仅作用于兼容模式。计划模式不把这些客户端数值当作确认规则，也不支持同一计划 reassign；失败只能重试原方案或返回错误。FUSE 同一写句柄发生计划错误后，后续 Flush 保留错误，不悄悄创建新操作降低要求。因用户修改了已上传区间而重建完整内容属于新内容操作，不是失败后的保护降级。

## 协议与错误

| 接口 | 用途 |
| --- | --- |
| `GET /capabilities` | 协议能力与启用状态；安全模式仍要求 TLS |
| `POST /writes` | 新建或重放上传 |
| `POST /writes/chunks` | 冻结一个块的复制与确认计划 |
| `POST /writes/commit` | 确认条件检查与原子发布 |
| `POST /writes/abort` | 停止未发布上传 |
| `GET /protection?path=...` | 查询覆盖偏好和继承结果 |
| `POST /protection` | 设置偏好或清除覆盖 |

新接口要求 `X-Atoll-Features: write-plan-v1`，并可与 `object-id-v1` 同时声明。JSON 拒绝未知、重复、大小写歧义、缺失必需字段、null 和额外顶层值，不接受临时加入 `min_copies` 等字段。

启用后，旧 `POST /files`、`/files/small`、`/files/chunks`、`/files/commit`、`/auth/files/empty` 返回 426；读取、目录元数据以及内容绑定的 verified 回执仍使用现有接口。不要把 `/files/replicated/verified` 误当旧上传旁路。

- `write_not_ready`：指定确认条件未到齐，同 binding 重试。
- `write_plan_conflict`：目标或计划冲突，不换方案掩盖错误。
- `write_no_feasible`：没有找到满足约束的可执行方案。
- `write_budget`：事务内可用预算不足。
- `write_expired`：上传过期。
- `write_plan_required`：需要计划协议或启用状态不匹配。

网络断流或 503 可能发生在事务已落库、响应未送达之后，客户端只以原 operation ID/binding 做有界重试；不会把所有 409 一律当作“副本还没到齐”。

## 容量与取消

Master 容量核算共享既有自治预算入口：

`max(已报告用量, 跨启动代保留的用量下限, 已确认元数据占用) + 未证实已被用量覆盖的写计划预留 + 其他保护计划预留 + headroom`

节点回执可带启动 epoch、单调采样序号和用量，回执与用量绑定写入 WAL。较旧的同 epoch 心跳不能覆盖更新的用量。随机启动 epoch 本身不可排序；跨 epoch 或回到无序号协议时，保留已知用量下限，变化记入 WAL，设备重新认证也不清除此下限，迟到的旧启动样本不能据此释放空间。没有可核验覆盖关系时另行保留对象预留。仍未完成的目标不会因为文件已发布而消失于容量账。节点另外执行本地 `used + inflight + next <= total`，同对象重试在满容量时可验证已有对象和完整请求后重新确认，不假释放其他对象的空间。

上传 24 小时过期。Abort/过期停止新授权和发布；后续 [对象退隐批次](RETIREMENT.md) 将取消和退隐记录写入同一事务，移除 staging inode，但保留对应对象/节点的独立预留。节点持久封禁、删除、目录同步及在途临时写入清理完成后，匹配回执才允许释放该笔预留。空回执、404/409、离线或吊销节点不算释放证明；计划和操作身份不因过期而复用。

跨启动代用量下限只在回执与当前尝试的精确基线一致时作有界扣减，无法对齐时仍保守保留。已发布旧对象暂时 held，未知用量、旧节点缺少证明和 epoch 改变仍可能造成高估。**尚无通用计划历史裁剪和全部历史容量对账执行器**，不能通过删计划、删标记或手改数据库让空间凭空变空。

这不是已完成的通用回收站、任意有效读句柄保留或 EC/COW 源回收协议。现有删除仍立即移除命名空间；正式的数据迁移/EC 回收还需要后续引用生命周期工作。

## 验证与剩余范围

本批测试覆盖纯调度决策、bbolt/WAL 事务、并发容量、当前权限与设备身份、固定确认集合、失效回执、HTTP 故障/重放、直接节点传输、真实 CLI TLS/重启，以及 macFUSE 真实内核读写。最终验收命令、测试数量和已知限制见 [本批验收报告](WRITE_PLANNING_ACCEPTANCE.md)。

后续批次已完成客户端加密直传、密钥托管与密钥恢复包（aead-record-v1，见 [安全说明](SECURITY.md)），并经真机隔离集群验收。生产 P2P、EC/COW、30 天回收站和自动接管仍未完成。
