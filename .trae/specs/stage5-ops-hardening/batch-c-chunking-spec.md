# 批次 C：分片上传（chunking）— spec

## 背景

当前模型是"1 文件 = 1 对象 = 1 inode ID"，三台机器整存整取。审计遗留的 P0/P1 问题全部源于这个模型：

- **#1 覆盖写非原子**：`handleCreateFile` overwrite 时先删旧元数据+旧对象，再写新数据。客户端中途崩溃 → 文件既不是旧的也不是新的
- **#8 并发写**：两个写者同一路径各自建 inode，元数据层面删一个，但两边对象都落了盘 → 孤儿
- **#4 反向孤儿**：元数据承诺副本在某节点、实际没有（只有正向 GC，无对账）；覆盖写/崩溃残留同样产生节点侧垃圾
- **大文件放不下**：副本分配要求单节点空闲 ≥ 整个文件大小；inode 114 那种 3GB 文件对节点容量是硬门槛

批次 C 把存储模型改为 **64MB 固定块**，以上四个问题在同一个模型里消解。

## 设计共识（此前已与用户对齐）

1. 64MB 固定块，小文件单块（3MB 文件就是 3MB 块，无空间浪费）；不做 CDC/动态切分
2. 每块独立分配副本（块可以落在不同节点组合上，副本默认 2）
3. 客户端流水线：写满一块就异步上传，滞后最多一块，Flush/commit 强制等全部块完成
4. 块级 API 生来带认证（复用批次 B 框架）

## 核心模型

### 块 ID 编码（无 schema 新增）

```
chunkID = (inodeID << 8) | index
```

- index ∈ [0,256) → 单文件最大 256 块 = 16GB（当前最大文件 3GB，够用；写死上限并在 assign 校验）
- node 完全无感知：chunkID 就是一个 uint64 对象 ID，照旧存 `objects/<桶>/<id>`
- master 从 chunkID 反解 `inodeID = id>>8`、`index = id&0xFF`，一切块语义都活在 master+client
- **node 二进制零改动、可不重新部署**（这是本设计最重要的简化）

### Inode 扩展（types.Inode）

```go
type ChunkInfo struct {
    Index   int     `json:"index"`
    Size    int64   `json:"size"`
    Replicas []uint64 `json:"replicas"`      // 第一个为主副本
    Done    []uint64 `json:"done,omitempty"` // 已落盘节点
}
type Inode struct {
    ...现有字段...
    Staging bool        `json:"staging,omitempty"` // 写入中（无 children 指针，路径不可见）
    Chunks  []ChunkInfo `json:"chunks,omitempty"`  // ChunkCount==0 且非 chunked = 旧整文件
    Chunked bool        `json:"chunked,omitempty"` // true = 新模型；false = 旧整文件
}
```

- **旧文件（Chunked=false）永久可读**：读/修复/GC 走现有整对象路径，不迁移（下次覆盖写时自然变新模型）
- staging inode 只存在于 inodes bucket，**不写 children**：Lookup/ls 天然看不见，无需任何过滤逻辑

### 元数据操作（meta 包新增）

| 操作 | 语义 |
|---|---|
| `CreateStagingFile(parent, replicas)` | 分配 inode，Staging=true，不挂 children；返回 inode |
| `AssignChunk(inodeID, index, size)` | 单事务内幂等分配块副本（已分配 → 原样返回）；从 alive 节点挑 N 个（容量按块大小检查） |
| `MarkChunkDone(chunkID, nodeID)` | 块级 AddReplicaDone |
| `CommitStaging(inodeID, name, size, chunkCount)` | **单 bbolt 事务原子换名**：校验每块主副本 Done 且 Σ块大小=size → 删旧 inode+children → staging 改名挂 children |
| `AbortStaging(inodeID)` | 删除 staging inode + 已分配块（通知节点回收） |

### 覆盖写原子性（#1）

旧流程：先删旧 → 写新（有崩溃窗口）。
新流程：**新版本写到隐藏 staging inode，commit 时单事务换名**：

```
commit 事务: 删 old inode + children[old] → staging.Name=name, Staging=false → 写 children
```

- 事务前：读者看到旧版本（完好）
- 事务后：读者看到新版本（已确认全部块落盘）
- **任何时刻崩溃：要么旧要么新，没有中间态**
- 换名成功后再异步通知节点回收旧版本的块（回收失败由 GC 兜底——旧 inode 已不在元数据，其块成为可回收孤儿）

### 并发写（#8）

两个写者各持一个 staging inode，各传各的块，先后 commit：

- 每次 commit 都是原子换名 → 读者任意时刻看到的是某一个完整版本，**last-writer-wins**（与两次 `cp` 竞争语义一致，文档化）
- 先 commit 者的数据被后 commit 者换掉，其块自动沦为孤儿 → GC 回收
- 不做写锁/租约（MVP 出界，见"不做的事"）

## API 变更（全部在 master；node 不动）

| 端点 | 变更 |
|---|---|
| `POST /files` | 改为创建 staging inode（**不再先删旧文件**）；请求 `{path, replicas, overwrite}`，响应 `{inode_id}` |
| `POST /files/chunks` | 新增：`{inode_id, index, size}` → `{nodes}`（幂等分配） |
| `POST /files/commit` | 改为 `{inode_id, size, chunk_count}`（校验+原子换名） |
| `DELETE /files/staging/{id}` | 新增：客户端中断时显式放弃 |
| `GET /files/replica-targets` | 不变签名，master 内部解释：inode 是 chunked → 按 chunkID 反解出块级目标；legacy → 现行为 |
| `POST /files/replicated` | body 的 inode_id 字段实际传 chunkID（node 本就传原始对象 ID），master 按 Chunked 分流 |
| `GET /meta` | inode 自带 Chunks，读端直接拿到块表 |

**滚动升级兼容性（关键）**：node 对外说的始终是"uint64 对象 ID"，chunk 语义由 master 单方解释 → 升级顺序 **master 先 → 节点随意（可不升）→ 客户端最后**，新旧版本任意混跑不炸。旧客户端对新 master：`POST /files` 得到 staging inode → 整体 PUT → commit（老格式带 size 不带 chunk_count，master 识别 legacy 提交路径，保持旧行为兼容）。

## 写路径（client）

### 流水线（之前共识）

```
读 r ──填充──> 块缓冲[64MB] ──满即传──> 并发上传(深度2)
                    │  滞后最多 1 块
                    └─ Flush: 等全部在途块完成 → commit
```

- `PutChunked(remotePath, size, r, replicas)`：CLI put 与 mount Flush 共用同一实现
- 块 i 满 → `POST /files/chunks` 分配 → PUT 到主副本（主副本节点照旧自动推送从副本）
- 单块 PUT 失败：重试同目标 ×2，仍失败请求 reassign（master 换一组节点）
- commit 前 master 校验每块主副本 Done；末块大小 = size − 64MB×(count−1)，Σ 校验防撕裂

### 读路径

- CLI get：按块表并发拉取（深度 2-3），顺序写本地文件；Range 读按偏移换算 (块, 块内偏移)
- mount readHandle：Range 请求改打对应块的副本集合（内核单次 Read ≤1MB，天然不会跨大区间）
- legacy 文件（Chunked=false）：两条读路径都保留现有整对象分支

## 修复 / GC / 生命周期

### 修复扫描（scanner 改造）

- chunked 文件按块粒度跑现有 `planRepairs` 逻辑：健康 = alive ∧ Done；退避 key 直接用 chunkID（批次 A 的退避/404 探测/上报重试**原样复用**）
- staging inode 跳过修复（正在写，从副本未 Done 是正常态，修它等于捣乱）
- legacy 文件走现有 per-inode 路径不动

### GC 双扫确认（#4 闭环 + 防 GC 误杀）

上传中的块（staging 已 assign 但未 commit）与 GC 快照存在竞态：GC 快照没含某新块、节点清单里已有 → 会被误判孤儿。解法：**孤儿必须连续两轮扫描都在才允许删**（scanner 持久化上轮孤儿集合，`RunGC(execute)` 只删 ∩ 上轮 dry-run 结果）。

### staging TTL 回收

- GC 循环顺带扫描：staging 且 mtime 超过 24h → 视为崩溃残留，删 inode + 通知节点回收已分配块
- 客户端正常中断（mount Release 未 Flush）走显式 `DELETE /files/staging`，不等 TTL

### 有效性集合

- validIDs = 全部存活 inode 的块 ID ∪ 活跃 staging inode 的块 ID ∪ legacy inode 自身 ID
- 换名后旧版本的块不在集合内 → 两轮后被 GC 清走（这就是 #8 败者、覆盖写旧版的最终归宿）

## 失败矩阵

| 故障 | 后果 | 兜底 |
|---|---|---|
| 上传中断途（客户端崩溃/断网） | staging 残留，旧文件完好 | 显式 abort 或 24h TTL 回收 |
| commit 前主副本节点宕机 | 块未 Done，commit 拒绝 | 客户端 reassign 到新节点 |
| commit 后从副本未同步 | 读降级（只主副本可读） | 块级修复扫描自动补 |
| 换名后旧块回收通知失败 | 节点残留旧块 | GC 两轮确认后清 |
| 并发写双 commit | last-writer-wins | 败者块 GC 清扫 |

## 测试计划

1. **meta 单测**：staging 不可见性（Lookup 必须失败）、AssignChunk 幂等、Commit 原子换名（旧名字瞬间消失新名字出现）、Σ大小校验、Abort
2. **master handler 单测**：legacy 客户端走新 master（整文件 PUT + 旧 commit 格式）全通——滚动升级的命门
3. **client 单测**：3 块文件（150MB）流水线上传 + 重组下载逐字节比对；块边界偏移 Range 读
4. **scanner 单测**：块级修复退避复用、staging TTL 回收、GC 两轮确认（第一轮报孤儿不删、第二轮才删、上传竞态块不被误杀）
5. **e2e**：覆盖写中途杀客户端 → 旧文件完好可读（#1 验收）；双写者竞争 → 胜者完整（#8）；legacy 文件在升级后可读可修
6. **实机（4 台）**：master 先滚动 → 3GB 文件 chunked put/get 全链路 → 挂载读写 → kill -9 上传中进程验证 #1 → 等 GC 清败者块

## 部署顺序

1. master 滚动升级（单实例，停机秒级）
2. 节点：**可不升级**（零改动）；顺手同版本部署保持一致
3. mac 客户端（CLI + mount）
4. 验收：新写文件 `ls` 看大小正常、读回比对；旧文件（含 inode 114）读路径不回归

## 顺带发现的重构建议（阅读代码时记下的，不在本批次强制做）

- `client.lookup` 是 `Lookup` 的冗余别名，删掉
- mount `Getattr/Lookup` 任何错误都返回 ENOENT（网络错误会让文件"消失"），应分流 EIO
- `notifyObjectDelete` 每次调用新建 http.Client，连接不复用；应挂到 scanner 复用
- `handleGet` 206 响应缺 Content-Length，部分客户端（curl 断点续传）行为不标准

## 不做的事（明确出界）

- 不做 CDC/动态块、纠删码
- 不做断点续传（客户端重启后重传整个文件；staging TTL 负责清扫）
- 不做写锁/租约/FUSE 直写流（mount 保持本地缓冲+Flush 模型，仅 Flush 改走分块流水线）
- 不迁移存量旧文件（懒迁移：下次覆盖写自然升级为新模型）
- 不做跨目录 rename（维持 EXDEV）
