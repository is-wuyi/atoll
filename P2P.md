# 内置 P2P 数据面

## 当前边界

内置 P2P 是显式启用的安全数据面，不替代文件模型、内容加密或保存确认规则。未配置 `-p2p` 的旧 HTTPS/HTTP 使用方式保持原样；已初始化 P2P 的 Master 数据库重启时必须继续启用 P2P，不允许静默降级。

本地验收由 `integration/peer` 的真实 Master、设备、客户端、TLS 与 peer runtime 组合覆盖；测试名称和执行结果见 [分阶段验收记录](P2P_ACCEPTANCE.md)。普通 `direct` 仅表示没有经过 CircuitRelay，不能据此判断连接是否经过 EasyTier、Tailscale 或其它 overlay。2026-11-02 隔离 NAS 已取得自动公网候选、一次双侧 QUIC DCUtR 成功及后续同连接 stream、小块/1 MiB 双副本完整读写和读中断故障转移；8 MiB 多副本稳定性仍未通过，不能将本批描述为完整公网验收完成。没有替换其它测试部署、拆除 EasyTier 或迁移数据。

## 身份、地址与授权

三类密钥互相独立：设备身份负责存储节点入网，peer 身份负责传输连接认证，内容密钥负责 AEAD 静态加密。设备 NodeID 和 libp2p PeerID 使用不同的派生规则，不能互相替换。

- 存储节点通过既有设备挑战与独立 peer 签名证明同时持有两把私钥。P2P 挑战受众是确切的 Master HTTPS origin，绑定逻辑地址、容量、peer 公钥与预期绑定修订号。
- Master 在安全事务与 WAL 中保存设备与 peer 的绑定。更换 peer 身份需要合法设备认证和修订比较；同一 peer 私钥不能被另一设备认领。撤销设备后，发现、票据签发和在线验票均拒绝该设备。
- 普通用户客户端只登记短期 client peer，受当前用户会话与空间权限约束，不获取设备权限。登记具有比较并交换修订号，网络重试复用同一签名请求，切换会话或空间不能用迟到请求回滚新登记。
- 每个用户最多持有四个有效 client peer。正常退出时，客户端有界发送签名释放请求；Master 接受后立即移出有效目录并失效旧授权，失败则由两分钟登记有效期兜底。短期回放记录保留，旧登记或释放签名不能作用到新修订。持有 peer 私钥的客户端可以按当前修订重新签名登记，授权代次递增，旧票据不会复活。
- 比较并交换修订号与授权代次分开：同一会话、同一空间的正常续租只推进修订号，不中断在途票据；切换会话或空间、登记过期、退出后重激活才推进授权代次。
- 设备绑定预留目录名额，与有效 client peer 合计最多 512 项；满额拒绝新登记，不以产生不可读取的超大目录来接受请求。

`NodeInfo.Addr` 继续是 HTTPS、Host 和票据受众使用的逻辑 `host:port`。peer multiaddr 另行发布、续期与更新；家宽端口或外网地址变化不改对象 ID、文件代次或设备身份。

节点地址发布签名绑定 Master origin、数字 NodeID、PeerID、绑定修订号、预期地址修订号、操作 ID、完整地址集合与 `NotAfter`。租期最多两分钟，同操作回放不延长原有效期。目录只从受信任的 HTTPS Master 获取，不使用公开 DHT 作为授权来源。

### 第三方边缘节点的自动连接

节点可能随时离线，加入系统不要求节点主人修改路由器 NAT、端口映射或 DNS。控制面连接一个固定、公网可达且证书匹配的 Master origin；内置 peer 连接自行观察公网候选、协调 DCUtR，不能直连时使用已授权 relay。并非所有 NAT 组合都可打洞，relay 是有界兜底而非绕过认证。

TCP 也可以通过同时打开进行 NAT 打洞，当前 libp2p DCUtR 支持 TCP 和 QUIC；成功率取决于双方 NAT、地址映射及防火墙，不能从一次失败断言协议不可用。TCP 中继的既有对照明显更快，但尚未单独证明 UDP 接收缓冲警告就是 QUIC 停顿的全部原因。目标是**优先利用实际可用的直连，可靠中继只作兜底**，而不是关闭 QUIC 候选来迫使所有流量经中心。

普通节点和客户端不需要填写 `-p2p-announce`。当前基础设施的真实连接和 Identify 观测经 PeerID/公钥、授权租期、监听端口与传输类型校验后形成候选。观测不等于公网可达性确认：AutoNAT 验证回拨 nonce 和地址，DCUtR 可使用尚不能接受普通入站拨号的映射。候选随连接断开、授权失效或基础设施绑定变化失效；地址更新不更换设备/内容身份。

可达性探测采用已登记身份，但有独立的 dial-only 连接池，不发布空 Identify 地址/协议记录，不提供对象服务；完成探测关闭连接不能中断其它数据流。未经登记的 peer 不因此获准连接，探测仍有请求方授权、nonce、速率、资源和放大防护。

**不要把 EasyTier 虚拟 IP、固定家宽公网 IP 或 NAS 私网地址手填成自动连接配置。** 私网地址只在显式 local/LAN 模式中使用，同为 `192.168.0.x` 不证明同局域网。管理时用 EasyTier CLI 或 SSH 发现在线机器，与正式对象流的传输路径是两回事。

## 实际请求路径

控制面仍使用固定 Master HTTPS origin。用户会话和设备凭据只发往 Master；发往存储节点的请求换取短期、目标与操作绑定的访问票据。Master 自身的探测、verify、pull、retirement 和加密备份传输也装配 peer resolver，而不是只给客户端上传接线。

数据面保留两层认证：libp2p 的加密连接认证远端 PeerID，真实外层 TLS 认证逻辑 HTTPS 地址。不能关闭证书验证，也不能手工构造 `r.TLS` 冒充握手。节点从连接上下文取得真实 SourcePeerID，不相信同名 HTTP 头；票据在线检查同时验证源登记和目标当前 peer 绑定。

默认策略优先直连，失败后尝试中心 CircuitRelay。普通直拨只使用同一请求剩余期限的一部分，避免沉默候选耗尽中继兜底时间；原请求的期限与取消显式穿过 `net/http` 的拨号上下文剥离，约束连接建立和外层 TLS，而不关闭已经建立的数据流。严格 `direct` 或 `circuit` 请求校验实际承载路径，不能把回退或旧连接复用伪装成指定路径。严格中继拨号使用隔离 host，保持同一 peer 密钥但不共用直连连接池；不能通过关闭其它上传的连接来切换路径。已经打开的流不会迁移，断流交由现有整块重试和写入恢复处理。

本批不改变这些保存条件：

- 传输进度不是完整副本回执。
- 已有完整副本和确认数下限不得因切换路径而降低。
- 同次计划写入恢复继续使用原 UploadID、内容对象和已生成密文字节。
- 暂时目录或中继失败不能静默转为未经 peer 授权的普通节点 TCP 请求。

## 命令行

所有角色都显式配置 `-p2p`。示例使用自有证书及域名，不包含可用凭据；实际会话、设备邀请码与控制 token 继续通过既有环境变量注入。

### Master

先按 `SECURITY.md` 引导安全数据库和证书，再运行：

```sh
atoll master -secure -write-planning -p2p \
  -db /path/to/master.db \
  -listen :9420 \
  -p2p-origin https://master.example:9420 \
  -tls-cert /path/to/master.crt -tls-key /path/to/master.key \
  -tls-ca /path/to/ca.crt \
  -p2p-listen /ip4/0.0.0.0/tcp/9422
```

中心持有持久 peer 身份并提供有限、经授权的 relay。默认 peer 身份路径为数据库路径加 `.peer.key`；需要改路径时使用 `-p2p-identity`，不要把它指向设备身份文件或内容 KEK。

`-p2p-origin` 必须是客户端实际访问的确切 HTTPS origin，不是 peer multiaddr，也不能携带路径、查询、用户信息或片段。已有库不能通过换 origin 或 peer 密钥静默接管信任关系。

### 存储节点

```sh
atoll node -secure -p2p \
  -master https://master.example:9420 \
  -data-dir /path/to/node-data \
  -listen :9421 -advertise node.example:9421 \
  -tls-cert /path/to/node.crt -tls-key /path/to/node.key \
  -tls-ca /path/to/ca.crt \
  -p2p-listen /ip4/0.0.0.0/tcp/9422
```

首次入网仍需合法设备邀请码。设备身份和 peer 身份默认分别保存为数据目录中的 `identity.key` 与 `peer.key`。保留这两个文件后重启，才能延续原身份；损坏密钥文件必须报错，不能自动生成新身份覆盖。

普通存储节点只预留中心 relay，不自动成为开放中继。逻辑 HTTPS 地址应保持稳定；NAT 地址变化通过 peer 地址发布处理。

### 用户客户端和挂载

```sh
atoll put -master https://master.example:9420 -p2p \
  -tls-ca /path/to/ca.crt -space 1 local.bin /remote.bin

atoll get -master https://master.example:9420 -p2p \
  -tls-ca /path/to/ca.crt -space 1 /remote.bin downloaded.bin

atoll mount -master https://master.example:9420 -p2p \
  -tls-ca /path/to/ca.crt -space 1 /path/to/mountpoint
```

客户端使用既有 `ATOLL_SESSION` 或 `-session-env` 指定的会话。默认每个进程生成临时 peer 身份；显式 `-p2p-identity` 可以使用独立持久身份。挂载复用同一个客户端 `ObjectTransport()`，没有第二套绕过票据或 TLS 的数据通道。构造和协议层测试不代表已完成内核 FUSE 验收。

### 公布地址与中继传输

- **中心、节点和客户端默认均保留 TCP 与 QUIC**：中心连接准备先建立实际 TCP 控制/中继基线，QUIC 候选观测使用同身份、独立连接池并借用主 host 的 UDP 监听套接字；只有实测本地地址匹配主 UDP 监听端口才记录候选。辅助 host 不提供对象或 Identify 服务，不把空地址/协议快照覆盖到主身份上。
- 中继预约、caller→center hop 和 center→target hop 按实际连接选择 TCP，并校验真实 transport；仅过滤拨号地址不足以阻止旧 QUIC 连接复用。QUIC-only 中心不能作为 TCP relay，明确报错，不静默回退。节点间直连仍可选择 TCP/QUIC，并保留主 host 的原生 DCUtR；已有流不会迁移或为切路径被强制关闭。
- 主 host 只限制向基础设施的 QUIC 出站连接；基础设施的已授权 QUIC 回拨在 TCP 基线建立后允许。旧连接池若先存在非 TCP 直连，公开 libp2p API 无法无损追加同 PeerID 的注册 TCP 连接，本实现明确拒绝该中继准备而不关闭活跃连接。观测候选在连接、身份/地址变更、授权代次或租期中断后失效，普通连续续租不反复清空。
- `-p2p-listen` 支持重复或逗号分隔的 TCP、QUIC multiaddr，监听可以使用端口 0；所有角色默认同时监听 TCP 与 QUIC，显式填写时覆盖默认集合。
- `-p2p-announce` 显式覆盖公布地址，适用于操作者确定的基础设施公网地址；普通 NAS/客户端通常不设置。发布地址不能使用端口 0，该覆盖不等于自动发现。
- `-p2p-public-only` 默认开启，排除私网、回环、CGNAT 和未经解析验证的 DNS peer 地址。明确的隔离本地/LAN 测试使用 `-p2p-public-only=false`；它不是对网络运营商路径或所有 overlay 的普遍证明。
- 每个地址集合最多 16 项、每项最多 512 字节；目录最多 512 个端点，响应读取上限 8 MiB。登记、发布和释放请求仍为独立的 64 KiB 上限。
- 发现缓存和后台续期有界，连接失败触发有限重新发现；节点定期刷新中继预约，不仅等原预约的到期时间。首次中心连接和预约暂时失败有有限重试，授权或配置错误立即拒绝；请求期限和关停取消也约束已打开的预约流。

### 私有诊断

`-p2p-diagnostics FILE` 显式启用私有诊断，目标必须是尚不存在的新文件，父目录由操作者准备。程序收尾只新建 0600 JSON，不覆盖现有文件，最多保留 8192 个事件和 4 MiB，超限计入 `dropped`；写出失败会使命令返回失败。默认不开启诊断。

记录分为 runtime、HTTP 和 CLI 三层：候选/AutoNAT/DCUtR、具体请求使用的 PeerID 与连接/stream/地址/路径、最后的文件操作结果。实际 `path`、`fallback`、`fallback_upgraded` 和内容成功不得合并。HTTP 正文 EOF 不是 CRC、AEAD 或 Master Done 的证明；仅 CLI 最终成功加完整回读/权威记录才能证明内容验收。控制请求不会继承对象路径要求或对象 reporter，不记录 query、正文、认证材料或原始错误文本。

## 元数据与升级

Master 将 P2P 标记和基础设施配置写入安全存储与 WAL，并把计划写入配置升级到版本 4。旧 Master 遇到该版本必须停止服务而不是用旧语义继续写。新 Master 也拒绝丢失标记、损坏配置或省略启动开关的状态。

设备绑定、节点端点和撤销信息随 WAL 恢复。用户 client peer 登记与短期访问票据不进入 WAL；恢复后由当前有效用户会话重新登记，不把历史连接授权当作永久身份。

## 验收命令

根模块包含生产 runtime 和本地真实组件测试：

```sh
GOMAXPROCS=2 go test -race -p 1 ./... -count=1 -timeout=20m
go vet ./...
```

独立原型模块不被根 `./...` 自动包含，应分别运行：

```sh
go -C prototypes/peertransport test ./...
go -C prototypes/peertransport-production test -tags integration ./...
```

需要单独标注未执行的真实公网、NAS 故障注入和内核 FUSE 场景。路径观察、是否尝试回退、最终完整内容校验是三个不同证据，不能合并为一次“成功”。
