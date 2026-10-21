# Atoll 账号、空间与节点安全模式

本批把受邀账号、空间权限、节点独立身份和对象访问票据接入现有存储代码。**尚未部署真实集群。** 安全模式默认关闭；只有未执行过 `auth init` 的库、未启用过安全模式的节点目录，才可继续使用原有共享 token 模式。已初始化后漏带 `-secure` 会拒绝启动或拒绝请求，不会自动降级。

## 能力与当前限制

已接入：

- 受邀注册、bcrypt 密码校验、登录、登出、改密及账号禁用。密码长度为 12～72 字节，用户会话有效期 24 小时。
- 每人独立个人空间；可创建多个团队空间，由创建者管理 read/write 成员。平台管理员可读写全部空间。
- 节点持久 Ed25519 身份、一次性设备邀请、签名挑战、30 分钟设备会话、续期和吊销。
- 用户会话只发 Master；节点只接收绑定对象操作的短期票据，并逐请求回 Master 在线核验。节点间复制、修复与自治增加副本也走此授权链路。

本批**没有**完成下列能力：

- **节点侧内容机密性（aead-record-v1 已接入计划写入）。** secure Master 配置 `-content-key-file`（`atoll content-key-init` 创建，0600、原子发布、不进数据库/WAL）后，计划上传的每块在客户端按 64KiB AES-256-GCM 记录加密（`pkg/contentcrypto`），节点只接收、校验、落盘密文；CRC 与容量预算按密文计。块 DEK 由 Master 生成并只保存 wrapped DEK（`keyID + base64 包裹`），经 `POST /auth/content-key/prepare`（上传）与 `GET /auth/content-key`（读取）按空间 ACL 发放；KEK 与明文 DEK 不落库。记录 AAD 绑定对象 ID、内容身份（ContentVersion.ID = Begin 冻结的 staging ID）与记录序号。未配置 KEK 的集群与已有 plain 数据完全不受影响；master 未配 KEK 时客户端自动按 plain 上传，不报错。**加密对象发布后密钥随空间共享**：团队 read/write 成员与平台管理员可读（与明文对象 ACL 一致）；上传在途时密钥仍属上传者私有。加密探测因 master 故障失败时默认记录日志后按 plain 继续；`put -require-encryption` 可改为硬停，不静默明文落盘。
- **内容密钥恢复包（keypack）。** `atoll keypack export -db <库> -key-file <KEK> -out <包>` 在 Master 停止时把全部 wrapped DEK 导出为单个自描述文件（ATKP 格式，HMAC 绑定 KEK keyID，0600、拒绝覆盖）；`atoll keypack import -db <库> -in <包> -key-file <KEK>` 校验后回放到新库（同对象已有不同包裹时整包拒绝，幂等重放逐字段一致才接受；记录 keyID 与本机 KEK 不一致整包拒绝——防"拿错 KEK 文件"导入成功而内容不可解）。**恢复包与 KEK 文件必须分开离线保管**——只有元数据库时丢任一件都解不开内容：完整灾备 = 元数据快照 + KEK 文件 + 密钥恢复包，三者缺一不可。keypack 的 HMAC 只由公开 keyID 派生：**能防意外损坏与手滑，不防有意伪造**（敌手可重算 MAC），敌手模型依赖"包与 KEK 分开保管、导入端与 master 同源"。无 KEK 也能 import（跳过 HMAC 与 keyID 护栏并明示），但不排除包被篡改或来自其他集群。
- **安全模式的集群元数据灾备（加密后已解禁）。** 配置 `-content-key-file` 的 secure Master 现在允许 `-seeds`：快照/WAL/manifest 出中心前全部以独立信封加密（每 blob 独立随机 DEK、KEK 域隔离派生、密文含完整性认证），节点只见密文；`/admin/metabackup*` 同步解禁。未配 KEK 的 secure Master 仍拒绝远程备份——账号元数据（bcrypt 哈希/会话/内容密钥包裹）不能明文进陌生节点。**中心全损恢复**：master 启动时把恢复公钥（同 KEK 派生的 Ed25519 只读身份）pin 到全部存活节点；管理员持 KEK 文件在新机重建 master 时，凭恢复签名离线验签读取节点密文备份（签名绑定节点地址/方法/路径，只读、2 分钟有效；写删仍需在线控制票据，恢复通道不可伪造 pin）。完整灾备四件套：元数据密文备份（集群内）+ KEK 文件 + 内容密钥恢复包 + 离线本地库备份。
- **回收站、桌面登录界面、正式 EC 或内置 P2P 接线。** 删除仍立即从命名空间移除，物理对象另行回收，没有 30 天回收站。现有 console 未接入本批用户会话体系。
- **去 EasyTier 的现网迁移。** 应用按 HTTP(S) 地址访问节点，现有部署仍使用 EasyTier 地址通道；`prototypes/peertransport` 是独立原型，尚未替换生产传输。本批不拆除或重启 EasyTier。

## 启用与使用

以下命令中的地址、证书和凭据须替换为自己的值。参数必须放在文件路径等位置参数之前。生产使用可验证的 TLS 证书；`-allow-insecure` 仅供隔离测试，不应用于真实用户数据。

### 1. 离线初始化并启动 Master

先停止该数据库的 Master 并保管离线备份，再初始化：

```bash
ATOLL_PASSWORD='<初始管理员密码>' ./atoll auth init -db atoll.db -user admin
```

初始化在同一事务中创建 `/.atoll-spaces`、首位平台管理员及个人空间。已初始化的库、或原根中已有同名 `.atoll-spaces` 条目都会被拒绝。旧根中的文件不会自动迁入任何用户空间。

在 Master 所在机器生成并保管私有控制凭据：

```bash
export ATOLL_CONTROL_TOKEN="$(./atoll auth gen)"
./atoll master -db atoll.db -secure \
  -tls-cert master.pem -tls-key master.key -tls-ca ca.pem
```

控制凭据至少 24 字符，必须保持私有，**不要分发给存储节点或普通用户**。自签 CA 需在 Master、节点及客户端分别配置。证书的主机名必须覆盖实际访问地址。

### 2. 管理员登录，签发用户与设备邀请

在管理客户端设置 Master 地址，登录得到 JSON：

```bash
export ATOLL_MASTER='https://master.example:9420'
ATOLL_PASSWORD='<管理员密码>' ./atoll login -user admin -tls-ca ca.pem
```

`login` 只输出会话信息，不修改父 shell，也不自动存入钥匙串。将输出中的 `token` 和 `user.personal_space_id` 设置到当前 shell；不要把会话 JSON 或密码写入公开日志：

```bash
export ATOLL_SESSION='<登录响应的 token>'
export ATOLL_SPACE='<登录响应的 user.personal_space_id>'
```

下例生成一小时后过期的邀请。设备邀请最多 7 天，用户邀请最多 30 天；均为随机、一次性凭据：

```bash
EXPIRY=$(python3 -c 'from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())')

curl --fail-with-body --noproxy '*' --cacert ca.pem \
  "$ATOLL_MASTER/auth/devices/invites" \
  -H "Authorization: Bearer $ATOLL_SESSION" -H 'Content-Type: application/json' \
  --data "{\"expires_at\":\"$EXPIRY\"}"

curl --fail-with-body --noproxy '*' --cacert ca.pem \
  "$ATOLL_MASTER/auth/invites" \
  -H "Authorization: Bearer $ATOLL_SESSION" -H 'Content-Type: application/json' \
  --data "{\"expires_at\":\"$EXPIRY\"}"
```

新用户用 `POST /auth/register` 提交 JSON `{invite, username, password}` 注册，然后使用 `atoll login` 登录。邀请响应和会话都是凭据，应私下交付。用户名统一小写，允许 1～64 字节的 ASCII 字母、数字、点、下划线和短横线，不允许单独的 `.` 或 `..`。

### 3. 启动受邀节点

在每台节点机器上，只配置该节点的一次性设备邀请、证书和存储预算：

```bash
ATOLL_NODE_INVITE='<设备邀请响应中的 invite>' ./atoll node \
  -secure -master 'https://master.example:9420' \
  -advertise 'node.example:9421' -data-dir /data/atoll \
  -total-bytes 107374182400 \
  -tls-cert node.pem -tls-key node.key -tls-ca ca.pem
```

默认身份文件为 `data-dir/identity.key`，可用 `-identity` 指定。身份与数据目录的安全标记必须持久保留，损坏或身份不匹配不能通过重生成来掩盖。身份文件与数据目录标记都通过硬链接实现原子不覆盖发布；相应目录必须位于支持该操作及文件、目录同步的文件系统上。不支持硬链接时拒绝启用，不回退为可能覆盖旧身份的写法。

节点首次通过 `POST /security/devices/challenge` 和 `/security/devices/session` 完成签名挑战；以后以同一身份续期，无需重复邀请码。收到失效设备会话的 401 后按被拒令牌条件续期，迟到的旧请求不能反复作废新会话。已吊销身份不能续期。

### 4. 文件操作、团队与挂载

在用户客户端登录并设置本人的 `ATOLL_MASTER`、`ATOLL_SESSION`、`ATOLL_SPACE`。使用私有 CA 时，每条命令都要提供 `-tls-ca`；由系统信任的证书无需额外 CA 文件：

```bash
./atoll spaces -tls-ca ca.pem
./atoll mkdir -tls-ca ca.pem /docs
./atoll put -tls-ca ca.pem ./a.txt /docs/a.txt
./atoll get -tls-ca ca.pem /docs/a.txt ./downloaded.txt
./atoll mount -tls-ca ca.pem -cache ./write-cache ./mnt
```

团队创建和成员管理：

```bash
./atoll team-create -tls-ca ca.pem '项目资料'
./atoll team-member -tls-ca ca.pem -space <团队ID> <用户ID> write
./atoll team-member -tls-ca ca.pem -space <团队ID> <用户ID> read
./atoll team-member -tls-ca ca.pem -space <团队ID> <用户ID> remove
```

上面的数字占位符须替换后再执行。用 `-space` 或 `ATOLL_SPACE` 选择团队；团队名称可以重复，权限以独立空间 ID 为准。只有团队创建者能管理成员；平台管理员的全空间文件访问权不等于团队所有权转移。

```bash
./atoll logout -tls-ca ca.pem
unset ATOLL_SESSION ATOLL_SPACE
```

`logout` 在 Master 吊销会话。进程无法替父 shell 清环境变量；Master 不可达时客户端会清自身内存会话，但不能宣称服务端吊销已经成功。

## 凭据、直连与在线授权

- **用户会话**只发往配置的 Master 精确 origin。直连节点前以 `/security/tickets` 换取 `at1_` 票据，节点不接收用户会话。
- **设备会话**只发往 Master，用于心跳、限定回执、换票及 `/security/check`，不具有任意用户文件或管理权限。
- **访问票据**有效期 2 分钟，绑定受众节点身份与地址、方法、路径、查询参数、计划和适用的小控制体哈希。对象 payload 不发往 Master 做票据哈希，节点按权威长度与 CRC 校验。CRC 防意外损坏，不是抵抗恶意节点的认证加密或长期存储证明。
- **用户/设备票据**在核验时重查当前会话、ACL、对象归属及内容身份（包含 InodeID 和 Generation）；不把所有布局变动都视为内容修改。**控制票据**由 Master 本地发放，按独立方法白名单核验，不使用相同的用户对象快照规则。
- **控制凭据**本体只用于受限静态管理入口，不发往节点。Master 的复制、修复、探测和自治请求在本地调用 `IssueControlTicket` 换票。配置了 `-admin-token` 时，静态控制凭据不能越过破坏性管理入口；未配置时控制凭据兼任该管理权限。
- **平台管理员用户会话**可访问管理接口和全部用户空间，包括已有的破坏性管理操作；不再要求附加静态 admin token。`/admin/metabackup*` 在安全模式仍对所有凭据禁用。

所有节点对象请求逐次在线回 Master 核验，不缓存授权结果。Master 不可达时拒绝，不降级到旧 token 或未认证访问。真实 TLS 监听器会在握手/协议层拒绝明文 HTTP，`/healthz` 仅豁免应用鉴权。

**直连范围要分清：**分块上传、节点读取、节点间复制和修复直传节点；安全 FUSE 的非空写入统一走分块路径。未启用计划写入时，CLI 的非空小文件仍使用旧 `PutSmall` 代理通道（≤256 KiB）。开启后续批次的 `-write-planning` 后，CLI 小文件也按持久计划直接上传节点，空文件、普通和流式上传统一使用 `write-plan-v1`，详见 [计划写入说明](WRITE_PLANNING.md)。内容仍为明文，本变更不代表加密上传已经完成。

## 隔离、吊销与回滚边界

用户路径映射到选定空间根，拒绝 `..`、反斜杠、NUL 和异常长度。按 ID 操作还会检查父链与空间归属；staging 上传绑定创建者、空间、原目标及代际，发布和幂等结果同事务保存。相对符号链接的目标在创建时做词法越界检查，不改写目标来掩盖越界。

登出、改密、禁用、移除团队成员、权限降级和节点吊销会影响**后续在线请求**。只读成员仍可上报校验失败，但不能修改或删除文件。节点重复吊销可重试；即使本地变更已落库，仍须按配置完成持久化确认才报告成功。

不能撤回已经交付的字节或已经开始的传输。FUSE 还有内核页缓存、entry/attr 缓存和应用短期属性缓存；安全模式禁用应用的已校验块缓存，但不是远程擦除客户端缓存。已进入内核或应用的明文字节不受后续吊销控制。

安全配置损坏、初始化状态缺失但残留账号记录、节点安全标记与配置不一致，必须拒绝而不是回到开放模式。旧根数据不会自动归入新空间，没有迁移工具。启用后的数据库不能直接交给不了解安全模式的旧二进制使用；不要以删除标记或抹掉配置的方式“回滚”。

## 临时安全记录与资源边界

Master 每分钟清扫过期的设备挑战、设备会话、用户会话及票据，并回收已用或过期邀请。每类前缀每轮最多检查 4096 条，游标由该数据库实例独立维护，后续轮次续扫；不会删除账号、空间、成员、设备身份或上传归属记录。损坏记录保留并报告，不凭解析失败猜测它已过期。

用户与设备凭据的删除记入 WAL；短期在线票据不记 WAL，避免备份授权造成递归提交。票据清扫与发放不会取消对当前会话和权限的逐请求检查。

待完成设备挑战上限为每身份 8 个、全库 512 个，单次统计最多扫描 4096 条挑战记录；相同公钥、地址、容量及邀请的未过期请求可复用同一挑战。达到上限会拒绝新挑战，不扩大授权。这是有限资源保护，不是完备的公网抗滥用系统；当前仅有有限认证并发闸，没有按账户或来源的完整登录限速。

## macFUSE 依赖修复

完整内核回归复现了 go-fuse v2.11.0 的 Darwin 通知处理缺陷：`MONITOR` 本应不回包，却被分发器回写响应；启动探针 `.go-fuse-epoll-hack` 的该类通知会误回 `ERANGE`，与后续请求编号复用交错，造成首次创建文件或目录间歇失败。

根 `go.mod` 通过 `replace` 使用 [third_party/go-fuse](third_party/go-fuse/ATOLL_PATCHES.md) 中的原版本副本。唯一上游生产代码变更为 Darwin 操作码注册增加 `SuppressReply: true`，另附协议级回归测试；版本号不变、`go.sum` 未改，不修改用户的 Go 模块缓存。该修复同时覆盖普通 inode 与启动探针，未关闭请求并发，也未加入延迟重试。

## 验收状态

2026-10-15 最终主线程验收通过：根模块 race 为 614 个顶层测试通过；完整 FUSE 套件 94 个顶层测试通过，其中安全内核测试 20 项，无 Skip；真实 TLS CLI 13 个子测试、独立 P2P 21 个顶层测试、Darwin MONITOR 协议回归及静态检查均通过。测试期间源码未变化。

完整范围、失败与修复经过、原始证据和可重跑命令见 [SECURITY_ACCEPTANCE.md](SECURITY_ACCEPTANCE.md)。本批未提交、未部署真实 NAS，也未执行集群灾备恢复演练。

前批完整性、自治和独立 P2P 原型的历史验收分别见 [EDGE_FOUNDATION.md](EDGE_FOUNDATION.md) 与 [AUTONOMY.md](AUTONOMY.md)。
