# 阶段4检查清单

## 实现

- [ ] meta：`ListNodes` 返回全部节点（含 dead），有单测
- [ ] meta：`ForEachFile` 遍历全部文件 inode，有单测
- [ ] meta：`ReplaceReplica` 替换 Replicas 槽位并从 DoneReplicas 移除 old，有单测
- [ ] node：`POST /pull` 返回 202 后台拉取落盘并上报 replicated，同 inode 并发去重，有单测
- [ ] node：`GET /admin/objects` 返回 id+size 清单且跳过 `.tmp-*`，有单测
- [ ] master：死亡判定 monitor 周期扫描，alive→dead / dead→alive 转换记日志，单测覆盖状态 diff
- [ ] master：修复决策纯函数四分支（dead 槽替换 / alive 未 Done 重触发 / 无源跳过 / 无目标跳过）均有单测
- [ ] master：修复执行器先 ReplaceReplica 再触发 /pull；单文件失败仅记日志不中断扫描
- [ ] master：无修复目标时 dead 节点保留在 Replicas（重启回池即恢复健康）
- [ ] master：`POST /admin/gc` dry-run 输出逐节点孤儿报告；execute 删除孤儿并返回统计；仅查 alive 节点
- [ ] master：GC 周期 dry-run（`-gc-interval`）只记日志不删除
- [ ] master：GC 只删元数据不存在的 inode 对象，不裁剪额外副本
- [ ] CLI：`atoll gc [-execute]` 打印逐节点报告
- [ ] runMaster：三个扫描器随进程启动、SIGINT/SIGTERM 退出；`-repair-interval`/`-gc-interval` flag 生效
- [ ] node.go 注释与 README.md 记录节点重加入行为（幂等复用 ID、旧对象不校验不裁剪）

## 测试

- [ ] L1：死亡判定、修复调度、GC 比对逻辑各有单测
- [ ] L2 e2e：杀 node → 副本自愈收敛（done 恢复目标数、Replicas 不含 dead 节点、内容不变）
- [ ] L2 e2e：孤儿对象 dry-run 报告列出 → execute 后消失；既有文件仍可读、副本数不变
- [ ] CI 全绿；build-binaries 产出 4 平台二进制

## 实机验收（scripts/acceptance-fault.sh）

- [ ] 5 台机器二进制全量更新且 md5 一致
- [ ] 杀 1 台 node → master 日志出现 dead 判定，副本在时限内恢复至目标数（分布在其余节点）
- [ ] 修复期间挂载客户端读取无感知中断（内容一致）
- [ ] 重启该 node → 回池正常（healthz OK、新写入成功），集群无异常
- [ ] 放置孤儿对象 → `atoll gc` dry-run 报告列出 → `--execute` 后磁盘消失
- [ ] GC 后全部有效文件仍可读、副本数不变
- [ ] 全程 master 不重启、元数据无损
- [ ] 验收输出留存，全部 PASS
