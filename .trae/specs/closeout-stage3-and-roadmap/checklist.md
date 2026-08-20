# Checklist

## 覆写能力（端到端）
- [ ] master `POST /files` 支持 overwrite：已存在路径被覆盖后 `/meta` 返回新 inode 且新 size 正确
- [ ] 不带 overwrite 时重复创建仍返回 409（向后兼容未破坏）
- [ ] 覆写后旧 inode 的对象已从副本节点磁盘回收（抽查至少一台 node）
- [ ] CLI `put -f` 覆盖成功；不带 `-f` 对已存在路径仍报 already exists
- [ ] FUSE 覆盖写实机验证：对已存在文件二次 `echo` 无 EIO，读回为新内容，md5/size 正确（ErrExist 与 SETATTR 双层 bug 均回归）
- [ ] 覆写后 done 副本数收敛至目标副本数

## 测试防线
- [ ] mount 写路径无内核单测存在且通过：write→flush→release 生命周期
- [ ] 同路径二次写入覆写回归测试存在（ErrExist bug 的防复发测试）
- [ ] discard / rename 跟随 / truncate 场景测试存在且通过
- [ ] CI 全绿（build / vet / test 三步）

## DNS 持久化（110）
- [ ] systemd-resolved 配置了 DNS=10.126.126.126 且 Domains=~et.net
- [ ] /etc/resolv.conf 恢复为 stub 符号链接
- [ ] et.net 域名解析到 EasyTier 内网 IP；公网域名解析不受影响
- [ ] 110 重启后上述两条依然成立

## 部署一致性
- [ ] 5 台机器（master + 3 node + 110）二进制 md5 一致
- [ ] master 与 3 台 node 的 systemd 服务均为 active，node 注册 ID 与历史一致（幂等未回退）
- [ ] 110 无遗留 debug mount 进程与孤儿缓冲文件

## 实机验收
- [ ] `scripts/acceptance-mount.sh` 已入库且在 110 执行全 PASS
- [ ] 验收脚本覆盖：挂载/mkdir/写/读/大文件/分段读/覆盖写/ls/stat/rename/跨目录降级/rm/rmdir/副本收敛/删除回收
- [ ] 验收输出已留存（贴回对话或记录）

## 清理
- [ ] 实机集群无残留测试文件（根目录仅预期内容）
- [ ] 本地 dist* 旧目录已清理，仅保留最新一份
- [ ] git 工作区干净，无二进制产物入库

## 交接完整性
- [ ] spec.md 的环境事实表与工作流约定完整（机器、端口、路径、NO_PROXY、版本铁律）
- [ ] 阶段4 详细规格（死亡判定/副本修复/GC/重加入 + 验收标准）已写入 spec.md Roadmap
- [ ] 阶段5 待办与"EC 不做"决策已记录
- [ ] tasks.md 中所有任务勾选完成
