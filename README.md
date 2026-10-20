# Atoll — 分布式文件存储系统

Atoll（环礁）面向零配置、自治调度的跨地域边缘主存储。当前系统提供多副本存储、FUSE 本地挂载和故障修复；新增默认关闭的观测／旁路／仅增保护控制循环，已接入持久计划与预算，但尚未部署真集群。本批新增默认关闭的安全模式（受邀账号、个人/团队空间、节点独立身份与在线访问票据，见 [安全说明](SECURITY.md)）：**`-secure` 代码路径下节点已改用 `pkg/edgeidentity` 持久 Ed25519 独立身份入网**（尚未部署真集群）。内置 P2P（libp2p）与内容加密基础仍是独立库、未接入生产链路；现有部署的 EasyTier 地址通道仍在使用，本批不做网络迁移、不拆除 EasyTier。

运行方法与边界见 [计划写入说明](WRITE_PLANNING.md)、[对象退隐与容量释放](RETIREMENT.md) 和 [自治多副本说明](AUTONOMY.md)；前一批协议、升级限制与原型记录见 [完整性基础说明](EDGE_FOUNDATION.md)。`-write-planning` 为默认关闭的新写入口：Master 调度器冻结复制布局与具体确认集合，满足后原子发布；保护档位只影响优化权重，不是固定副本数。

## 架构

- **master**：中心服务器，管理元数据（bbolt 持久化）、副本分配、心跳监控、死亡判定、副本修复、GC
- **node**：存储节点，接收客户端直连的对象读写，向 master 注册与心跳
- **client**：CLI 客户端 + FUSE 挂载，元数据操作走 master，数据读写直连存储节点。启用 `-write-planning` 后，小文件也直接上传计划节点；未启用时 CLI 的旧小文件通道仍经 master 代理。

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
./atoll gc --execute                        # 执行持久退隐记录；未知孤儿只报告

# FUSE 挂载
./atoll mount -master http://<master-ip>:9420 /mnt/atoll
```

以上为兼容模式（共享集群 token）。安全模式（受邀账号 + 空间 + 节点独立身份）默认关闭，启用需先 `auth init` 引导再以 `-secure` 启动 master/node，最小流程与全部前置条件见 [安全说明](SECURITY.md)：

```bash
# 引导（master 停止时；密码经环境变量，12..72 字节）
ATOLL_PASSWORD='<初始管理员密码>' ./atoll auth init -user admin -db atoll.db
# secure master（强制 TLS + ≥24 字符控制凭据；拒绝 -seeds）
ATOLL_CONTROL_TOKEN='<≥24字符>' ./atoll master -db atoll.db -secure -tls-cert ... -tls-key ... -tls-ca ...
# secure node（强制 TLS；首次入网带设备邀请码）
ATOLL_NODE_INVITE='<设备邀请码>' ./atoll node -secure -master https://<master>:9420 ...

# 用户侧：login 输出 JSON，不会改父 shell。私有 CA 需在各命令配置。
ATOLL_PASSWORD='<用户密码>' ./atoll login -user alice -master https://master.example:9420 -tls-ca ca.pem
export ATOLL_MASTER='https://master.example:9420' ATOLL_SESSION='<登录JSON的token>' ATOLL_SPACE='<user.personal_space_id>'
./atoll put -tls-ca ca.pem a.txt /a.txt
```

## 数据完整性与安全

- **CRC32C 完整性**：Master 保存权威内容描述，节点复制/修复按该描述校验，读端坏副本只标疑不立即删除。新回执绑定内容身份与可疑状态代际，旧无校验和数据保留兼容边界；具体读取范围见 [完整性说明](EDGE_FOUNDATION.md)。CRC 不提供对恶意节点的密码学保护。
- **认证 + 读/管分离**：`-token` 为集群读写钥匙；`-admin-token`（master 侧 `-admin-token`，客户端 `atoll gc -admin-token`）单独保护 `/admin/gc` 这类破坏性操作，单钥匙泄露不至于连带删除权限。空 token = 兼容模式（不校验）。**安全模式下静态集群 token 不再是用户面凭据**：用户走登录会话，节点走独立身份与在线票据，详见 [安全说明](SECURITY.md)。
- **可选 TLS**：master/node 加 `-tls-cert -tls-key` 即走 https；客户端/挂载/节点用 `-tls-ca <CA文件>` 信任自签名 CA，或 `-tls-skip-verify` 跳过校验（仅限可信内网）。master 地址用 `https://` 时，直连节点也自动走 https。不配则明文 HTTP（向后兼容）。安全模式强制 TLS 且拒绝跳过校验（`-allow-insecure` 仅限隔离测试）。

## Web 管理后台（atoll console）

独立进程的只读为主管理后台，Go 服务端渲染，通过集群 token 调 master 的只读 `/admin/*` API，自带控制台账号与会话（与集群文件用户无关）。**console 未接入本批安全账号/空间/会话体系**：安全模式下它对 master 的 `/admin/*` 请求需携带控制凭据（读）与 admin token（破坏性操作），账号与空间管理不经 console。注意元数据备份页在安全模式下会因 master 对 `/admin/metabackup*` 整体封禁而不可用（返回 409）。

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
- **master 单点**：目前仍为单主；已有元数据快照/WAL 备份和恢复能力（正确性由 `master/meta/wal_test.go` 的 metaWAL 快照+重放测试证明），但不提供自动接管。账号、文件密钥的加密灾备与独立恢复包尚未实现——**安全模式下远程（集群种子）元数据备份/恢复被主动禁用**，仅可用本地库备份；本地库正常重启读取的是同库持久化内容，不等于独立的集群灾备恢复（详见 [安全说明](SECURITY.md)）。
- **安全模式下的静态加密（aead-record-v1）**：secure Master 配置 `-content-key-file` 后，计划写入自动按 64KiB AES-256-GCM 记录加密后直传节点——节点磁盘只见密文，CRC 与容量按密文计，读取在客户端/FUSE 解密；未配置 KEK 的集群行为不变（明文）。已发布对象的历史数据不迁移，仍按 plain 读取。内容密钥可用 `atoll keypack export/import` 离线导出/导入（恢复包与 KEK 分开保管；完整灾备 = 元数据快照 + KEK 文件 + 密钥恢复包）。KEK 轮换与旧数据重加密尚未实现（见 [安全说明](SECURITY.md)）。
- **无回收站**：删除立即移除命名空间，但已发布内容的物理对象暂时保留，不用扫描次数或短宽限期证明“没有读者”。未发布的取消/过期上传可以在持久封禁和删除确认后释放容量；没有 30 天回收站或恢复接口，详见 [对象退隐说明](RETIREMENT.md)。

## 节点重加入行为

节点重启后的恢复机制：

1. **身份延续**：兼容模式按注册地址复用节点 ID；安全模式按持久 Ed25519 身份续期并保留节点 ID，不能凭同一地址接管旧身份。
2. **心跳与准入**：正常心跳使已准入节点重新参与调度；安全模式下吊销的设备即使恢复联网也不能回池。
3. **不做启动全盘 scrub**：重加入本身不扫描全部旧对象；读取、复制和显式校验可按已记录 CRC 验证内容，未知校验和旧数据保留兼容限制
4. **额外副本保留**：若该节点曾被修复扫描替换（Replicas 中被新节点替代），其旧副本成为额外副本，GC 不删除仍在元数据中的对象

## 副本修复

master 后台周期扫描文件副本健康度：
- 节点死亡 → 从存活副本复制到新节点
- 副本未同步完成 → 重新触发 pull
- 有存活完好源且资源足够时，按扫描周期与退避策略恢复；没有固定 60 秒完成保证

## 垃圾回收

master 周期比对节点磁盘对象与元数据：
- 未知孤儿提供 dry-run 报告；重复扫描本身不授权删除。
- `execute` 在启用 `-write-planning` 时执行已持久记录的、未发布上传退隐。节点先持久封禁，再删除并确认在途临时写入已清理，Master 才释放对应预留。
- 已发布旧版本和额外副本暂时保留，等待回收站、恢复点及有效读引用生命周期，不以容量紧张为理由提前删除。
- 已注册节点拒绝旧的无封禁 `DELETE /objects/{id}`；Master、节点需配套升级。旧模式不自动获得未知对象删除权限。
