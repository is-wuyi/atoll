# 阶段3收尾与全阶段路线图 Spec

## Why

阶段3（FUSE 挂载）的覆盖写修复仅通过 CI，未部署实机验证；深度审查发现覆盖写在 Flush 层仍存在 ErrExist 缺陷（`PutReader` 不支持覆写已存在文件）。同时实机集群残留测试数据、110 的 DNS 配置不可持久、mount 包写路径在 CI 中零测试覆盖。后续阶段（容错自愈、运维加固）需要一份可供其他模型严格接手的计划。

## 环境事实（接手模型必读）

| 机器 | 角色 | 地址 | 部署路径 | 说明 |
|------|------|------|---------|------|
| 26666.et.net | master | EasyTier 10.126.126.126，SSH 端口 78，用户 root | /opt/atoll/atoll，db /opt/atoll/atoll.db | systemd 服务 atoll-master (:9420)，防火墙已放行 9420 |
| 27119.et.net | node id=2 | SSH 22，用户 jimo（sudo） | 数据 /volume2/@atoll | 群晖 DSM，systemd 服务 atoll-node (:9421) |
| 27348.et.net | node id=3 | SSH 22，用户 jimo（sudo） | 数据 /volume1/@atoll | 同上 |
| 27472.et.net | node id=4 | SSH 22，用户 jimo（sudo） | 数据 /volume3/@atoll | 同上 |
| 192.168.0.107（原 .110，DHCP 会变） | 挂载客户端 | SSH 22，用户 root | /opt/atoll/atoll，挂载点 /mnt/atoll | Ubuntu 26.04 x86_64，/dev/fuse 可用，EasyTier tun0（IP 会变），systemd 服务 easytier |
| 开发 Mac | 开发机 | 本地 | dist*/ 下二进制 | Intel x86_64；必须 `export NO_PROXY="et.net,.et.net,10.126.0.0/16"` 绕过 Clash |

凭据由用户提供，**严禁写入仓库任何文件**。

## 接手工作流约定（强制）

1. **版本一致性铁律**：任何涉及跨机器新接口的改动，测试前必须先全量更新全部 5 台机器的二进制（md5 校验一致）。历史上曾因 master 未更新而误诊挂载层 bug。
2. **CI 流程**：push → Actions 跑 build/vet/test；go.sum 由 CI 机器人提交，push 前必须 `git pull --rebase`。
3. **内核 FUSE 测试**已拆至 build tag `fuse`（CI 的 GitHub runner 有 /dev/fuse 设备但挂载会永久阻塞，勿试图在 CI 启用）。
4. **实机验收**统一用仓库内 `scripts/` 脚本执行并留存输出，不靠手敲命令。
5. 二进制产物目录 `dist*/` 已 gitignore，**严禁提交**。

---

## What Changes（本变更实际交付）

- **master**：`POST /files` 支持 `overwrite` 参数——路径已存在时删除旧元数据并通知各副本节点回收旧对象，再建新记录（含单测）
- **client**：`PutReader` 支持 overwrite；CLI `put` 新增 `-f` 覆写参数（默认仍拒绝重复路径，保持 409）
- **mount**：写句柄 Flush 走覆写路径——这是 SETATTR 修复（已合入 0d15b80）之后的第二层缺陷修复
- **测试**：mount 写路径新增无内核直调单测（httptest 集群 + writeHandle 生命周期：write/flush/release/truncate/discard/rename 跟随/Unlink 写入中文件）
- **运维**：110 的 DNS 持久化（systemd-resolved 配置 10.126.126.126）；清理实机集群残留测试数据；清理 110 遗留的 debug mount 进程；清理本地 dist* 目录
- **验收**：`scripts/acceptance-mount.sh` 入库（覆盖写实机验收脚本，供任何模型复跑）
- **路线图**：阶段4/5 详细规格写入本文件（见下方 Roadmap 章节）

## Impact

- Affected code: `master/server.go`、`master/meta/meta.go`、`client/client.go`、`cmd/atoll/main.go`、`mount/mount.go`、新增 `mount/mount_write_test.go`、新增 `scripts/acceptance-mount.sh`
- Affected specs: 阶段1 的"文件创建"语义（新增 overwrite 分支）；阶段3 的"覆盖写"能力补全
- 实机影响：5 台机器全量滚动更新；110 重启一次验证 DNS 持久化

---

## ADDED Requirements

### Requirement: 文件覆写（端到端）

系统 SHALL 支持对已存在路径的写入覆盖旧内容：旧元数据被替换，旧对象在全部副本节点上被回收，新数据按当前副本数写入。

#### Scenario: FUSE 覆盖写
- **WHEN** 用户在挂载点对已存在文件执行 `echo new > file`（O_TRUNC 路径）
- **THEN** Flush 成功（无 EIO），读回内容为 `new`，size 正确，且旧 inode 的对象已从节点磁盘回收

#### Scenario: CLI 覆盖写
- **WHEN** 执行 `atoll put -f local remote` 且 remote 已存在
- **THEN** 覆盖成功，`atoll get` 读回内容与 local 一致
- **WHEN** 不带 `-f` 对已存在路径 put
- **THEN** 仍返回 409 already exists（保持向后兼容）

#### Scenario: 覆写后副本收敛
- **WHEN** 覆写发生后轮询 `/meta?path=`
- **THEN** done 副本数收敛至目标副本数，内容为新版本

### Requirement: mount 写路径无内核单测

CI SHALL 通过不依赖内核 FUSE 的直调单测覆盖写句柄状态机（writeHandle 生命周期），防回归。

#### Scenario: write→flush→release 生命周期
- **WHEN** 测试代码模拟 Create/writeHandle 写入数据并调用 Flush、Release
- **THEN** 集群侧可 Get 到写入内容，本地缓冲文件被删除，writes 注册表清空

#### Scenario: 覆写路径回归
- **WHEN** 同一远程路径先后两次 writeHandle 写入不同内容并 Flush
- **THEN** 第二次后集群侧内容为第二次内容（验证 overwrite 打通，回归 ErrExist bug）

#### Scenario: discard（写入中被 Unlink）
- **WHEN** writeHandle 存在时调用 discard
- **THEN** 不触发上传，本地缓冲被删，后续 Flush 为 no-op

#### Scenario: rename 跟随
- **WHEN** 写入中路径被 rename（同目录）
- **THEN** writes 注册表键更新，Flush 上传到新路径

### Requirement: 110 DNS 持久化

110 的 et.net 域名解析 SHALL 在重启后依然生效，且不影响普通域名解析。

#### Scenario: 重启后解析
- **WHEN** 110 重启后执行 `ping -c1 26666.et.net`
- **THEN** 解析到 10.126.126.126（EasyTier 内网可达）
- **WHEN** 解析普通公网域名（如 github.com）
- **THEN** 正常走原上游 DNS（未被破坏）

### Requirement: 实机验收脚本

仓库 SHALL 包含 `scripts/acceptance-mount.sh`，在 110 上一键执行挂载全量验收并输出逐项 PASS/FAIL。

#### Scenario: 脚本执行
- **WHEN** 在 110 上运行 `bash scripts/acceptance-mount.sh`
- **THEN** 覆盖以下检查项并全部 PASS：挂载成功、mkdir、写小文件、读回一致、写 10MB 大文件、分段 Range 读、覆盖写（旧 bug 回归项）、ls、stat、同目录 rename、跨目录 mv 降级、rm、rmdir、副本收敛至目标数、删除后节点磁盘对象清零

---

## MODIFIED Requirements

### Requirement: 文件创建（原阶段1）

`POST /files` 在请求携带 `overwrite: true` 且路径已存在时，SHALL 删除旧文件（元数据 + 异步通知副本节点回收对象，复用 notifyObjectDelete），随后创建新记录并分配副本节点；未携带该参数时维持原有 409 行为。

### Requirement: mount Setattr truncate（0d15b80 已合入，随本变更一并部署验证）

SETATTR 无句柄时按路径查活跃写缓冲——该修复已进 main 但未部署实机，本变更部署后必须实机验证覆盖写整体链路。

---

## Roadmap：阶段4（容错与自愈）——下一变更的详细规格

> 目标：集群在节点宕机、重启、残留垃圾等故障下自动恢复到健康状态。接手模型按本节新建独立 spec 后实施。

### Requirement: 节点死亡判定
master SHALL 周期扫描（建议 10s）节点心跳，超过 nodeMaxAge 的节点判定 dead 并记日志。lookup/分配已在阶段2过滤 dead 节点（现状保持）。

- **Scenario**: 停一台 node 的服务 → master 日志出现 dead 判定；`/meta` 不再返回该节点；新建文件不被分配到它。

### Requirement: 副本修复（re-replication）
master SHALL 周期扫描文件副本健康度：对 `存活副本数 < len(Replicas)` 的文件，从 Done 副本中选源节点，选一个 alive 且不在 Replicas 中的新目标，调用目标节点新增的 `POST /pull {inode_id, source_addr}`（目标从源拉取对象、落盘、上报 replicated），master 将目标加入 Replicas 与 DoneReplicas。

- **Scenario: 副本自愈**：3 副本文件，杀 1 台 node → 60 秒内 `/meta` 显示 done 副本恢复至 3（分布在其余节点）。
- **Scenario: 无源可用**：文件无存活 Done 副本 → 跳过并记日志，下轮重试（不 panic、不阻塞扫描器）。
- **Scenario: 容量不足**：无合适新目标 → 记日志跳过。

### Requirement: 垃圾回收（GC）
node SHALL 提供 `GET /admin/objects`（返回对象 id+size 列表）；master SHALL 提供周期比对任务：node 上存在但元数据已不引用的对象，通知该 node 删除。**必须先 dry-run 输出报告、确认后执行**；GC 只删元数据中不存在的对象，不做副本裁剪（超副本数不删）。

- **Scenario: 孤儿回收**：手动在 node 磁盘放置假对象 → dry-run 报告列出 → 执行后消失。
- **Scenario: 正常副本不受影响**：GC 后所有有效文件仍可读，副本数不变。

### Requirement: 节点重加入（文档化现状）
节点重启后幂等注册复用原 ID（阶段2已实现），心跳恢复即回池；其上旧对象不校验、不裁剪。此行为写入代码注释与 README。

### 阶段4 验收标准
1. 单测：死亡判定、修复调度、GC 比对逻辑各有单测；e2e：杀 node→自愈、孤儿→回收。
2. 实机脚本 `scripts/acceptance-fault.sh`：杀一台 node → 轮询副本恢复 → 重启该 node → 验证回池且集群无异常；放置孤儿文件 → GC 清除。
3. 全程 master 不重启、不丢元数据；挂载客户端读取无感知中断（Range 读故障切换兜底）。

---

## Roadmap：阶段5（运维加固，优先级 P2）

> 按需启动，逐项独立成 spec。

1. **atoll status**：master 新增汇总接口 + CLI 命令——节点列表（alive/dead/容量/用量）、副本健康分布、总文件数/总字节。
2. **mount 开机自启**：110 上 systemd 单元（After=network-online，Restart=on-failure，ExecStop 优雅卸载）。
3. **组件间认证**：当前所有端口零认证（内网可接受）；任何公网暴露前必须加共享 token（master/node 互信 + 客户端请求头）。
4. **性能调优**：FUSE EntryTimeout/AttrTimeout 调优、写缓冲上传并发、node 端 io.Copy 缓冲。
5. **EC 纠删码**：明确不做（原始设计决策，多副本已满足需求）。

---

## 测试与验收方法论（全阶段通用，接手模型强制遵循）

| 层级 | 环境 | 内容 | 门槛 |
|------|------|------|------|
| L1 单测 | CI | meta/master/client/node/mount 纯逻辑 | 每个新函数有测试；bug 修复必须附回归测试 |
| L2 集成 | CI | httptest 起真实 master+node 的 e2e | 全链路场景（含故障注入：关 server 模拟宕机） |
| L3 内核挂载 | 仅实机 | `-tags fuse` 的 TestKernelMount | 阶段3收尾后每次 mount 改动跑一次 |
| L4 实机验收 | 5 机集群 | scripts/acceptance-*.sh | 全 PASS 才算阶段完成；输出留存到对话/issue |

**规则**：新功能先写失败测试或验收脚本再实现；实机测试前全量对齐 5 台二进制版本（md5 一致）；修 bug 必须能回答"哪个测试会在它复发时变红"。
