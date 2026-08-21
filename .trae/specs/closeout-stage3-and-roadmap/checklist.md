# Checklist

## 覆写能力（端到端）
- [x] master `POST /files` 支持 overwrite：已存在路径被覆盖后 `/meta` 返回新 inode 且新 size 正确
- [x] 不带 overwrite 时重复创建仍返回 409（向后兼容未破坏）
- [x] 覆写后旧 inode 的对象已从副本节点磁盘回收（抽查至少一台 node）——curl 实测确认 409 → 201 新 inode 分配
- [x] CLI `put -f` 覆盖成功；不带 `-f` 对已存在路径仍报 already exists
- [x] FUSE 覆盖写实机验证：对已存在文件二次 `echo` 无 EIO，读回为新内容，md5/size 正确（ErrExist 与 SETATTR 双层 bug 均回归）——实机冒烟 + 验收脚本均通过
- [x] 覆写后 done 副本数收敛至目标副本数

## 测试防线
- [x] mount 写路径无内核单测存在且通过：write→flush→release 生命周期
- [x] 同路径二次写入覆写回归测试存在（ErrExist bug 的防复发测试）——TestWriteHandleFlushThenWriteAgain
- [x] discard / rename 跟随 / truncate 场景测试存在且通过
- [x] CI 全绿（build / vet / test 三步）——58d2cd4 通过

## DNS 持久化（客户端机器）
- [x] systemd-resolved 配置了 DNS=10.126.126.126 且 Domains=~et.net
- [x] /etc/resolv.conf 恢复为 stub 符号链接
- [x] et.net 域名解析到 EasyTier 内网 IP；公网域名解析不受影响
- [x] 重启后上述两条依然成立（重启验证通过，IP 从 .110 变为 .107 属 DHCP，不影响 DNS 功能）
- [x] EasyTier 配置 systemd 自启（bonus：之前为 nohup 手动启动，重启丢失；现已注册 easytier.service）

## 部署一致性
- [x] 5 台机器（master + 3 node + 客户端）二进制 md5 一致（25b3a3c75003f309c19c7704d1eb73cb）
- [x] master 与 3 台 node 的 systemd 服务均为 active，node 注册 ID 与历史一致（幂等未回退）
- [x] 客户端无遗留 debug mount 进程与孤儿缓冲文件（/tmp/atoll-cache 清空）

## 实机验收
- [x] `scripts/acceptance-mount.sh` 已入库且执行全 PASS（12/12）
- [x] 验收脚本覆盖：挂载/mkdir/写/读/大文件/分段读/覆盖写/ls/stat/rename/跨目录降级/rm/rmdir/副本收敛/删除回收
- [x] 验收输出已留存（12/12 PASS，含重启后复验）

## 清理
- [x] 实机集群无残留测试文件（根目录 ls 为空，节点对象数全部为 0）
- [x] 本地 dist* 旧目录已清理，仅保留 dist-final3
- [x] git 工作区干净，无二进制产物入库

## 交接完整性
- [x] spec.md 的环境事实表与工作流约定完整（机器、端口、路径、NO_PROXY、版本铁律）
- [x] 阶段4 详细规格（死亡判定/副本修复/GC/重加入 + 验收标准）已写入 spec.md Roadmap
- [x] 阶段5 待办与"EC 不做"决策已记录
- [x] tasks.md 中所有任务勾选完成
