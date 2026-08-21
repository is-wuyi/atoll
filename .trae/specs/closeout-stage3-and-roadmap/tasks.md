# Tasks

## 阶段3收尾（本变更）

- [x] Task 1: master 覆写接口：`POST /files` 支持 `overwrite` 参数
  - [x] 1.1 `handleCreateFile` 解析 `overwrite` 字段；路径已存在且 overwrite=true 时：先 `DeleteFile`（元数据），复用 `go notifyObjectDelete(旧 inode ID, 旧 Replicas)` 回收旧对象，再走正常 CreateFile 分配流程
  - [x] 1.2 master 单测：overwrite 覆盖已存在文件后 `/meta` 返回新 inode/新 size；不带 overwrite 仍 409；覆写后旧 inode ID 在 master 元数据中不存在

- [x] Task 2: client 覆写支持：`PutReader` 与 CLI `-f`
  - [x] 2.1 `PutReader` 新增 overwrite 透传参数（或 `PutReaderOverwrite`），请求体带 `overwrite: true`
  - [x] 2.2 CLI `put` 新增 `-f` flag，仅 put 使用；输出文案区分"已上传/已覆盖"
  - [x] 2.3 client 单测（httptest 集群）：同路径两次 PutReader(overwrite=true)，第二次后 Get 内容为第二版；不带 overwrite 的第二次返回 409

- [x] Task 3: mount Flush 接入覆写
  - [x] 3.1 `writeHandle.Flush` 调用带 overwrite 的 PutReader（修复 ErrExist 第二层缺陷）
  - [x] 3.2 确认 `newWriteHandle` 非 trunc 路径（就地编辑）在 Flush 时同样走覆写

- [x] Task 4: mount 写路径无内核单测（回归防线）
  - [x] 4.1 新建 `mount/mount_write_test.go`：复用/提取 httptest 集群 fixture，直调 writeHandle 生命周期
  - [x] 4.2 覆盖场景：write→flush→release（集群侧可读、缓冲删除、注册表清空）；同路径二次写入（ErrExist 回归）；discard 后 Flush no-op；rename 跟随后 Flush 到新路径；truncate 后 size 正确

- [x] Task 5: CI 验证与构建
  - [x] 5.1 push 后确认 CI 全绿（build/vet/test）
  - [x] 5.2 触发 build-binaries workflow，下载 4 平台二进制到本地 dist-final3/

- [x] Task 6: 110 DNS 持久化（与 Task 5 可并行）
  - [x] 6.1 写 `/etc/systemd/resolved.conf.d/easytier.conf`：`DNS=10.126.126.126`、`Domains=~et.net`，重启 systemd-resolved
  - [x] 6.2 恢复 `/etc/resolv.conf` 为 systemd stub 符号链接（当前被直接覆盖成普通文件）
  - [x] 6.3 验证：et.net 解析走 10.126.126.126，公网域名解析正常
  - [x] 6.4 重启 110 后复验（与 Task 8 的重启验证合并执行）

- [x] Task 7: 全量部署 5 台机器（依赖 Task 5）
  - [x] 7.1 更新 master（26666.et.net:78）：stop → 替换二进制 → start → healthz OK
  - [x] 7.2 更新 3 台 NAS node：逐台 stop → 替换 → start → 日志见注册且 ID 复用
  - [x] 7.3 更新 110：杀掉遗留 debug mount 进程并 fusermount -u，替换二进制
  - [x] 7.4 md5 校验 5 台机器二进制一致；4 个 node/master 服务 active

- [x] Task 8: 实机验收（依赖 Task 6、7）
  - [x] 8.1 编写 `scripts/acceptance-mount.sh`（在 110 执行）：挂载、mkdir、写小文件、读回一致、写 10MB、分段 Range 读（dd skip）、**覆盖写**（echo 两次 + 读回 + md5，重点回归项）、ls、stat、同目录 rename、跨目录 mv 降级、rm、rmdir
  - [x] 8.2 脚本内含副本收敛检查（轮询 /meta done 数）与删除后磁盘对象清零检查（ssh 到 node find，或仅查 master 通知逻辑 + 抽查一台）
  - [x] 8.3 执行脚本，全部 PASS，输出留存
  - [x] 8.4 脚本入库（含使用说明注释：目标机器、前置条件、NO_PROXY）

- [x] Task 9: 清理收尾
  - [x] 9.1 清理实机集群残留测试文件（当前遗留：/hello2.txt、/test-rename.txt、/dir、/cross.txt、/e2e 等，rm 后抽查节点对象清零）
  - [x] 9.2 110 保留正常（非 debug）mount 或按需卸载，确认无孤儿 tmp 缓冲文件（/tmp/atoll-cache）
  - [x] 9.3 本地清理 dist-new/dist-v3/dist-fuse 等旧目录，仅留最新
  - [x] 9.4 更新 todo 全部完成；spec checklist 全部勾选

# Task Dependencies

- Task 2 依赖 Task 1（接口先行）
- Task 3 依赖 Task 2
- Task 4 依赖 Task 3（测试对象为最终行为）；4.1 的 fixture 搭建可与 Task 1 并行
- Task 5 依赖 Task 1-4 全部完成
- Task 6 与 Task 5 并行
- Task 7 依赖 Task 5
- Task 8 依赖 Task 6 + Task 7
- Task 9 依赖 Task 8

# 后续阶段（不在本变更执行，接手模型据此立项）

- 阶段4（容错与自愈）：见 spec.md Roadmap 章节——节点死亡判定、副本修复（/pull API + master 调度扫描器）、GC（/admin/objects + dry-run）、重加入文档化；验收脚本 scripts/acceptance-fault.sh
- 阶段5（运维加固，P2）：atoll status、mount systemd 自启、组件认证、性能调优；EC 明确不做
