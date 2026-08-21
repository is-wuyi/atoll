# Tasks

- [x] Task 1: meta 层扩展：ListNodes / ForEachFile / ReplaceReplica
  - [x] 1.1 `ListNodes()` 返回全部节点（含 dead），供死亡判定与修复扫描使用
  - [x] 1.2 `ForEachFile(fn func(types.Inode) error)` 遍历全部文件 inode（供修复扫描与 GC 元数据集合）
  - [x] 1.3 `ReplaceReplica(inodeID, oldNodeID, newNodeID)`：Replicas 中 old→new 替换，DoneReplicas 移除 old；inode 不存在返回 ErrNotExist
  - [x] 1.4 meta_test.go 补齐三个方法的单测（含 DoneReplicas 清理、不存在 inode）

- [x] Task 2: node 新增 POST /pull 与 GET /admin/objects
  - [x] 2.1 `POST /pull {"inode_id","source_addr"}`：返回 202，后台 goroutine 从源 `GET /objects/{id}` 拉取 → 临时文件+rename 落盘 → 计费 used → 上报 master replicated；同 inode 并发 pull 用进行中集合去重
  - [x] 2.2 `GET /admin/objects`：遍历 objects 分桶目录返回 `[{"id","size"}]`，跳过 `.tmp-*`
  - [x] 2.3 node_test.go 单测：httptest 起源节点验证 pull 落盘内容一致与上报调用；对象清单含 id/size 且跳过 tmp

- [x] Task 3: master 扫描器框架 + runMaster 接线
  - [x] 3.1 新建 `master/scanner.go`：三个 ctx 驱动循环（death 10s / repair / gc），每个循环的核心逻辑抽成可同步调用的 `xxxScanOnce()` 便于测试
  - [x] 3.2 `cmd/atoll/main.go` runMaster：`signal.NotifyContext` 启动扫描器；新增 `-repair-interval`（默认 15s）、`-gc-interval`（默认 10m）flag

- [x] Task 4: 死亡判定 monitor
  - [x] 4.1 周期扫描 ListNodes，内存记录上轮 alive 集合；alive→dead 记 "node %d (%s) 判定死亡"，dead→alive 记 "node %d 心跳恢复，重新入池"
  - [x] 4.2 单测：状态转换 diff（新死亡、恢复、持续 dead 不重复记日志）

- [x] Task 5: 副本修复扫描器
  - [x] 5.1 纯决策函数 `planRepairs(inode, nodes, maxAge)`：健康副本数 < len(Replicas) 时，对每个不健康槽位产出 {替换 dead 槽 / 重触发 pull / 跳过(无源|无目标)}；四分支单测
  - [x] 5.2 执行器：dead 槽先 `ReplaceReplica` 再 `POST /pull`；alive 未 Done 槽直接 `POST /pull`；源选 alive∧Done∧∈Replicas 随机一个；目标选 alive∧∉Replicas∧剩余容量≥文件大小；任何失败记日志继续下一文件
  - [x] 5.3 集成：修复扫描接入 ForEachFile 遍历；文件被并发删除（ErrNotExist）时静默跳过

- [x] Task 6: GC 比对 + POST /admin/gc + 周期 dry-run
  - [x] 6.1 纯函数：node 对象列表 + 元数据文件 inode 集合 → 孤儿列表；单测（孤儿识别、正常对象与额外副本不误判）
  - [x] 6.2 `POST /admin/gc {"execute"}`：仅查 alive 节点；dry-run 返回逐节点孤儿报告；execute 复用 `DELETE /objects/{id}` 删除并返回删除统计
  - [x] 6.3 周期任务（`-gc-interval`）：dry-run 比对，每节点记一行日志摘要，不删除
  - [x] 6.4 master 侧单测（httptest node 模拟对象清单与删除）

- [x] Task 7: CLI atoll gc
  - [x] 7.1 client 新增 `GC(execute bool)` 方法（调 master /admin/gc，解析报告）
  - [x] 7.2 main.go 新增 `atoll gc [-execute]` 子命令，打印逐节点报告

- [x] Task 8: e2e 集成测试（client/e2e_test.go 或新增 master 侧 e2e）
  - [x] 8.1 测试辅助：可配 nodeMaxAge 的集群构造 + 对指定 node 手动 POST /nodes/heartbeat 维持活跃
  - [x] 8.2 TestRepairAfterNodeDeath：4 节点 3 副本杀 1 → 轮询 /meta done 恢复 3、Replicas 不含 dead 节点、内容一致；3 节点 2 副本杀 1 → done 恢复 2
  - [x] 8.3 TestGCOrphanReclaim：node 磁盘放假对象 → /admin/gc dry-run 报告含假对象 → execute 后磁盘消失；既有文件仍可读、副本数不变

- [ ] Task 9: CI + 构建 + 5 机部署
  - [x] 9.1 push → CI 全绿（vet/test）；触发 build-binaries 拿 4 平台产物
  - [ ] 9.2 5 台机器滚动更新二进制（md5 一致）并重启服务；验证节点注册/心跳正常、master 扫描器日志出现

- [ ] Task 10: 实机验收 scripts/acceptance-fault.sh
  - [x] 10.1 脚本入库：写测试文件（默认 2 副本适配 3 节点集群）→ 杀 1 台 node → 轮询副本恢复 → 修复期间读文件无感知 → 重启 node 验证回池（healthz + 新写入成功）→ node 磁盘放假孤儿 → atoll gc dry-run/execute → 有效文件不受影响 → 清理测试数据；逐项 PASS/FAIL
  - [ ] 10.2 在客户端机器（192.168.0.107）执行，全 PASS，输出留存到对话

- [x] Task 11: 节点重加入文档化
  - [x] 11.1 node.go 注册/心跳处注释：幂等复用原 ID、回池即恢复、旧对象不校验不裁剪（被替换后成为额外副本，GC 不删）
  - [x] 11.2 新建 README.md：简介、快速上手（master/node/mount）、节点重加入行为说明

# Task Dependencies

- Task 1、Task 2、Task 3 相互独立，可并行
- Task 4 依赖 Task 3
- Task 5 依赖 Task 1、2、3
- Task 6 依赖 Task 1、2、3
- Task 7 依赖 Task 6
- Task 8 依赖 Task 4、5、6
- Task 9 依赖 Task 8
- Task 10 依赖 Task 9
- Task 11 依赖 Task 5（行为注释需与实现一致），可与 Task 9/10 并行
