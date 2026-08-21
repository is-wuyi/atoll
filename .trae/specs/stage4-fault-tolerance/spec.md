# 阶段4：容错与自愈 Spec

## Why

当前集群只能在节点存活时保证副本数：节点宕机后其上副本永久缺失（副本数只减不增），删除/覆写失败残留的对象也无人清理。需要 master 具备节点死亡判定、副本自动修复、孤儿对象 GC 三项自愈能力，使集群在故障后自动收敛回健康状态。

本 spec 依据 `closeout-stage3-and-roadmap/spec.md` 的阶段4 Roadmap 章节展开，是该章节的实施规格。

## 环境事实与工作流约定

环境事实表（5 台机器、凭据、端口）与 8 条强制工作流约定见 `closeout-stage3-and-roadmap/spec.md`，本变更全文遵循，重申最关键的三条：

1. **版本一致性铁律**：实机测试前 5 台机器二进制必须全量更新且 md5 一致。
2. **测试方法论**：L1 单测（新函数必有测试）→ L2 e2e（httptest 真实 master+node，含故障注入）→ L4 实机验收（`scripts/` 脚本，全 PASS 才算阶段完成）。修 bug 必须能回答"哪个测试会在它复发时变红"。
3. **凭据严禁写入仓库**；实机验收脚本中机器地址用 et.net 域名，不写密码。

## What Changes

- **master 新增后台扫描器**（新文件 `master/scanner.go`，由 `runMaster` 随进程启动、随信号退出）：
  - 死亡判定 monitor：10s 周期，心跳超时节点记 dead 日志，恢复记 rejoin 日志
  - 副本修复扫描器：15s 周期（`-repair-interval` 可调），副本不足的文件自动重建副本
  - GC 周期比对：10min 周期（`-gc-interval` 可调）dry-run 比对并记日志（不删除）
- **master 新增 `POST /admin/gc`**：dry-run 输出孤儿报告；`execute=true` 时通知节点删除孤儿
- **node 新增两个 API**：`POST /pull`（从源节点拉取对象落盘并上报）、`GET /admin/objects`（列出本机对象清单）
- **meta 层新增**：`ListNodes`（全部节点含 dead）、`ForEachFile`（遍历文件 inode）、`ReplaceReplica`（副本槽位替换）
- **CLI 新增 `atoll gc [-execute]`**：dry-run 打印报告 / 执行清理
- **README.md**（新建）：简介、快速上手、节点重加入行为说明
- **实机验收脚本** `scripts/acceptance-fault.sh`（新建）

## Impact

- Affected code: `master/scanner.go`(新)、`master/server.go`、`master/meta/meta.go`、`node/node.go`、`client/client.go`、`cmd/atoll/main.go`、对应 `*_test.go`、`scripts/acceptance-fault.sh`(新)、`README.md`(新)
- Affected specs: 阶段2 的节点管理与副本分配（新增死亡判定日志与修复调度，过滤行为不变）；阶段3 Roadmap 的阶段4 章节落地
- 实机影响：5 台机器全量滚动更新；验收期间 master 不重启

## ADDED Requirements

### Requirement: 节点死亡判定（death monitor）

master SHALL 以 10s 周期扫描全部节点（含 dead），对心跳时间超过 `nodeMaxAge` 的节点判定 dead。alive→dead 与 dead→alive 的状态转变 SHALL 记日志。现有过滤行为（lookup/分配/推送目标过滤 dead 节点）保持不变。

#### Scenario: 停服务判定死亡
- **WHEN** 停止一台 node 的 atoll-node 服务并等待超过 nodeMaxAge
- **THEN** master 日志出现该节点 dead 判定；`/meta` 不再返回该节点；新建文件不被分配到它

#### Scenario: 恢复服务重新入池
- **WHEN** 该 node 重启服务并心跳恢复
- **THEN** master 日志出现心跳恢复（rejoin）记录

### Requirement: 副本修复（re-replication）

master SHALL 以 15s 周期（`-repair-interval` 可调）扫描全部文件 inode，对**健康副本数 < len(Replicas)** 的文件触发修复。健康副本定义：节点 ∈ Replicas ∧ 节点 ∈ DoneReplicas ∧ 节点 alive。

修复决策（对每个不健康槽位）：

| 槽位状态 | 动作 |
|---------|------|
| 节点 dead | 选新目标（alive ∧ 不在 Replicas ∧ 剩余容量 ≥ 文件大小），先 `ReplaceReplica(dead→new)` 更新元数据，再调用新节点 `POST /pull` |
| 节点 alive 但未 Done | 直接调用该节点 `POST /pull` 重新触发同步 |

- 源节点：任一 alive ∧ Done ∧ ∈ Replicas 的节点（随机选）
- **无源可用**（无 alive Done 副本）→ 记日志跳过，下轮重试
- **无合格新目标**（候选为空或容量不足）→ 记日志跳过，**dead 节点保留在 Replicas 中**（其重启回池后旧副本立即恢复健康）
- 单文件修复失败 SHALL 只记日志，不影响其他文件与扫描器（不 panic、不阻塞）

#### Scenario: 副本自愈（有富余节点）
- **WHEN** 4 节点集群中 3 副本文件，杀掉 1 台持有副本的 node
- **THEN** 60 秒内 `/meta` 显示 done 副本恢复至 3（分布在其余节点），Replicas 不再含 dead 节点，内容不变

#### Scenario: 副本自愈（3 节点 2 副本）
- **WHEN** 3 节点集群中 2 副本文件，杀掉 1 台持有副本的 node
- **THEN** done 副本恢复至 2（换到未持有的第 3 台）

#### Scenario: 无源可用
- **WHEN** 文件无存活 Done 副本
- **THEN** 扫描器记日志跳过该文件，不报错不阻塞，下轮重试

#### Scenario: 无合格目标
- **WHEN** 全部 alive 节点都已在 Replicas 中或容量不足
- **THEN** 记日志跳过，dead 节点保留在 Replicas（重启后旧副本直接复用）

### Requirement: node 拉取 API（POST /pull）

node SHALL 提供 `POST /pull`，请求体 `{"inode_id": N, "source_addr": "host:port"}`：

- 收到请求立即返回 `202 Accepted`，拉取在后台 goroutine 执行
- 后台流程：`GET http://{source_addr}/objects/{inode_id}` 全量拉取 → 临时文件+原子改名落盘（复用 handleReplicate 路径，计费 used）→ 向 master 上报 `POST /files/replicated`
- 同一 inode 的并发 pull SHALL 去重（进行中集合），避免重复下载
- 幂等：重复 pull 同一对象安全（覆盖写）

#### Scenario: pull 落盘并上报
- **WHEN** master 对目标节点发起 pull
- **THEN** 目标节点磁盘出现该对象（内容与源一致），master 的 DoneReplicas 包含该节点

### Requirement: node 对象清单 API（GET /admin/objects）

node SHALL 提供 `GET /admin/objects`，返回本机全部对象 `[{"id": N, "size": M}]`（遍历 objects 分桶目录，跳过 `.tmp-*` 临时文件）。

#### Scenario: 列出对象
- **WHEN** node 持有对象 42（100 字节）
- **THEN** 响应包含 `{"id":42,"size":100}`

### Requirement: 垃圾回收（GC）

- master SHALL 提供 `POST /admin/gc`，请求体 `{"execute": bool}`（默认 false）：
  - 对每个 **alive** 节点拉取 `/admin/objects`，与元数据中**全部文件 inode ID 集合**比对
  - 孤儿定义：对象 ID 不在元数据文件 inode 集合中（文件已删除或已被覆写）
  - dry-run：返回逐节点孤儿报告（id、size、汇总），不删除
  - execute=true：报告基础上通知各节点删除孤儿（复用 `DELETE /objects/{id}`），返回删除结果
- master SHALL 以 `-gc-interval`（默认 10min）周期运行 dry-run 比对并记日志摘要（仅日志，不删除）
- **GC 只删元数据中不存在 inode 的对象；不裁剪超副本数的额外副本**（如被修复替换后 rejoin 节点上的旧副本，文件仍存活则不删）

#### Scenario: 孤儿回收
- **WHEN** 手动在某 node 磁盘放置假对象（inode ID 不存在于元数据）→ dry-run → execute
- **THEN** dry-run 报告列出该对象；执行后该对象从磁盘消失

#### Scenario: 正常副本不受影响
- **WHEN** GC 执行后读取全部既有文件
- **THEN** 全部可读，副本数不变

### Requirement: CLI gc 命令

`atoll gc [--execute]` SHALL 调用 master `/admin/gc` 并打印人类可读报告（逐节点孤儿数/字节数）。

#### Scenario: dry-run 与执行
- **WHEN** 执行 `atoll gc` 后执行 `atoll gc --execute`
- **THEN** 第一次仅输出报告，第二次执行清理并输出删除结果

### Requirement: 实机验收脚本

仓库 SHALL 包含 `scripts/acceptance-fault.sh`，在挂载客户端机器一键执行，逐项输出 PASS/FAIL：杀 node → 轮询副本恢复 → 修复期间读取无感知 → 重启该 node 验证回池 → 放置孤儿 → GC dry-run/execute 清除 → 有效文件不受影响。全程 master 不重启。

### Requirement: 节点重加入（文档化现状）

节点重启后幂等注册复用原 ID（阶段2已实现），心跳恢复即回池；其上旧对象不校验、不裁剪（若该节点曾被修复替换，其旧副本成为额外副本，GC 不删除）。此行为 SHALL 写入 `node/node.go` 代码注释与 `README.md`。

## MODIFIED Requirements

### Requirement: master 启动流程

`atoll master` SHALL 在 HTTP 服务启动的同时启动三个后台扫描器（死亡判定 / 副本修复 / GC 比对），通过 context 驱动，进程收到 SIGINT/SIGTERM 时随进程退出。新增 flag：`-repair-interval`（默认 15s）、`-gc-interval`（默认 10m）。

## 测试与验收（本变更的门槛）

| 层级 | 内容 |
|------|------|
| L1 单测 | meta 新三方法；修复决策纯函数（dead 槽替换 / not-done 重触发 / 无源 / 无目标四分支）；GC 孤儿判定纯函数；死亡状态转换 diff；node /pull 与 /admin/objects |
| L2 e2e | httptest 集群（可配 nodeMaxAge + 手动心跳）：杀 node → 副本自愈收敛；孤儿 → dry-run/execute 回收；正常文件不受影响 |
| L4 实机 | `scripts/acceptance-fault.sh` 全 PASS，输出留存 |
