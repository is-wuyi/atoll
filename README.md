# Atoll — 分布式文件存储系统

Atoll（环礁）是一个轻量级分布式文件存储系统，支持多副本存储、FUSE 本地挂载、自动故障修复。

## 架构

- **master**：中心服务器，管理元数据（bbolt 持久化）、副本分配、心跳监控、死亡判定、副本修复、GC
- **node**：存储节点，接收客户端直连的对象读写，向 master 注册与心跳
- **client**：CLI 客户端 + FUSE 挂载，元数据操作走 master，数据读写直连存储节点

## 快速上手

```bash
# 编译
go build -o atoll ./cmd/atoll

# 启动 master
./atoll master -listen :9420 -db atoll.db

# 启动 node（每个节点执行，-advertise 指定本机对外地址）
./atoll node -master http://<master-ip>:9420 -advertise <本机ip>:9421 -data-dir /data/atoll

# CLI 操作
./atoll put local.txt /remote.txt           # 上传
./atoll get /remote.txt local.txt           # 下载
./atoll ls /                                # 列目录
./atoll mkdir /docs                         # 建目录
./atoll rm /remote.txt                      # 删除
./atoll gc                                  # GC dry-run
./atoll gc --execute                        # 执行 GC 删除孤儿

# FUSE 挂载
./atoll mount -master http://<master-ip>:9420 /mnt/atoll
```

## 限制

- **单文件上限 16 GiB**：分块模型固定 64 MiB/块、每文件最多 256 块（`ChunkSize × MaxChunksPerFile`）。超过上限的 `put` 会直接报错。
- **传输明文**：组件间为静态 Bearer Token 认证，无 TLS——仅适用于可信内网。
- **master 单点**：单个 bbolt 文件，无 HA/自动备份；请自行定期备份该 db 文件。

## 节点重加入行为

节点重启后的恢复机制：

1. **幂等注册**：同一地址重复注册时，master 复用原节点 ID（不产生新记录）
2. **心跳恢复即回池**：节点心跳恢复后，自动重新参与副本分配和读取
3. **旧对象不校验不裁剪**：节点上的旧对象保持原样，不做一致性校验
4. **额外副本保留**：若该节点曾被修复扫描替换（Replicas 中被新节点替代），其旧副本成为额外副本，GC 不删除仍在元数据中的对象

## 副本修复

master 后台周期扫描文件副本健康度：
- 节点死亡 → 从存活副本复制到新节点
- 副本未同步完成 → 重新触发 pull
- 60 秒内自动收敛至目标副本数

## 垃圾回收

master 周期比对节点磁盘对象与元数据：
- 孤儿对象（元数据中不存在的 inode）可被清理
- 支持 dry-run 报告和 execute 删除
- 只删除元数据中不存在的对象，不裁剪额外副本
