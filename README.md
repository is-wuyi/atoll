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

## 数据完整性与安全

- **端到端校验和（CRC32C）**：上传时每块/整对象算 CRC32C 存入元数据；节点落盘时按 PUT 头即时校验，读取时逐块比对，损坏副本自动跳过并故障转移。检测磁盘静默位翻转与传输撕裂。
- **认证 + 读/管分离**：`-token` 为集群读写钥匙；`-admin-token`（master 侧 `-admin-token`，客户端 `atoll gc -admin-token`）单独保护 `/admin/gc` 这类破坏性操作，单钥匙泄露不至于连带删除权限。空 token = 兼容模式（不校验）。
- **可选 TLS**：master/node 加 `-tls-cert -tls-key` 即走 https；客户端/挂载/节点用 `-tls-ca <CA文件>` 信任自签名 CA，或 `-tls-skip-verify` 跳过校验（仅限可信内网）。master 地址用 `https://` 时，直连节点也自动走 https。不配则明文 HTTP（向后兼容）。

## Web 管理后台（atoll console）

独立进程的只读为主管理后台，Go 服务端渲染，通过集群 token 调 master 的只读 `/admin/*` API，自带控制台账号与会话（与集群文件用户无关）。

```bash
# 1. 建控制台账号（密码经环境变量传入，避免进 shell 历史）
ATOLL_CONSOLE_PASSWORD='你的密码' ./atoll console useradd -data-dir ./console-data admin

# 2. 启动（默认 :9430）
./atoll console -listen :9430 -master http://127.0.0.1:9420 -token <集群token> -data-dir ./console-data
# 浏览器打开 http://127.0.0.1:9430
```

- **端口**：默认 `:9430`（`-listen` 改）。
- **账号与角色**：`console useradd <名> -role admin|readonly`（默认 admin）。`admin` 可执行破坏性操作（GC 删除）；`readonly` 只读，界面隐藏危险按钮。账号 bcrypt 存 `-data-dir/users.json`；会话在内存，重启失效。
- **页面**：概览、节点、文件浏览、文件详情（块×副本放置健康矩阵）、完整性与修复（降级块 + 修复状态）、垃圾回收（孤儿 dry-run + admin 执行）。概览/节点/完整性页每 5 秒自动局部刷新。
- **破坏性操作 token**：`-admin-token` 单独用于 GC 执行（不设则回退集群 token）。
- **TLS**：`-tls-cert/-tls-key` 让 console 自身走 https；`-tls-ca/-tls-skip-verify` 用于校验 master 证书（master 走 https 时）。
- **一键 demo**：`bash scripts/demo-console.sh`（起 master+2节点+样例文件+console）；`degrade` 参数造降级看完整性页；`stop` 停止。

## 限制

- **单文件上限 16 GiB**：分块模型固定 64 MiB/块、每文件最多 256 块（`ChunkSize × MaxChunksPerFile`）。超过上限的 `put` 会直接报错。
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
