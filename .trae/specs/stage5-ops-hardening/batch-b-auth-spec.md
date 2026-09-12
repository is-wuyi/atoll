# 批次 B：组件间认证 — spec

## 背景

审计 P0-#3：master 13 个路由、node 7 个路由全部裸奔。EasyTier 私网降低了暴露面，但同网段任何进程（包括 NAS 上的其他服务）都能调用 `DELETE /objects/{id}`、`/admin/gc execute`、`POST /pull` 等破坏性接口。批次 C（分片）将新增一批块级 API，必须先有认证框架。

## 目标

1. 所有 atoll 角色（master/node/client/mount）间的 HTTP 通信带上认证
2. 单一共享密钥（cluster token），所有组件同一把钥匙（不做 per-principal 身份区分——单家庭集群，MVP 够用）
3. 零外部依赖：不引入 JWT 库/OIDC，标准库实现
4. 升级兼容：滚动更新期间新旧二进制共存不能中断服务

## 方案：静态 Bearer Token

每个请求带 `Authorization: Bearer <token>`；服务端中间件校验，不匹配返回 401。

**为什么不选 mTLS / HMAC 签名**：
- mTLS：证书签发/轮换/分发对家庭集群过重，Go 侧还要生成 CA
- HMAC（每请求签名防重放）：私网内无中间人，token 泄露面小；MVP 用 Bearer，若后续需要再升级 HMAC，接口位置不变
- Bearer 简单、curl 可调试、滚动升级零状态

**token 管理**：
- 生成：`atoll auth gen` 输出随机 32 字节 base64（不做常驻存储）
- 分发：运维手动放到各机器的启动参数/环境变量 `ATOLL_TOKEN`
- 存放：systemd unit 的 `Environment=`（root 可读），不落仓库

## 接口契约

### 角色 → 请求方

| 服务 | 谁调用它 | 校验策略 |
|---|---|---|
| master :9420 | node（注册/心跳/replicated）、client/mount（元数据）、运维 CLI | 全部路由要求 token，`/healthz` 豁免（探活无敏感信息） |
| node :9421 | client/mount（读写对象）、master（pull 触发/删除通知）、peer node（replicate 推送）、GC（对象清单/孤儿删除） | 全部路由要求 token，`/healthz` 豁免 |

### 客户端注入点

- node：`Register()` 心跳循环、`replicateToPeers`、`reportReplicated`、`pullObject`、master 的 `triggerPull`/`notifyObjectDelete`/GC 请求（master 侧发起的）
- client 包：所有 `postJSON`/`getJSON`/`Get`/`putObject`
- mount：经 client 包，自动继承；FUSE 挂载进程读 `ATOLL_TOKEN` 环境变量
- CLI：`-token` flag 或 `ATOLL_TOKEN` 环境变量

### 实现要点

1. `pkg/auth`：`Wrap(handler, token)` 中间件 + `Sign(req, token)` 注入 header
   - 常数时间比较（`subtle.ConstantTimeCompare`）防时序侧信道
   - token 为空 = 服务端禁用认证（升级兼容窗口：滚动更新期间先双栈共存）
2. 服务端空 token 模式：旧客户端无 token 也能连（滚动更新窗口）；部署完成后统一配置 token 并再滚动一次
   - 日志告警：空 token 模式下每个未认证请求记 WARN（便于确认收尾）
3. 401 响应体：`{"error":"unauthorized"}`，node 收到 401 时提示检查 token

## 升级与部署流程（防自锁）

1. 第一轮：部署"支持 token 但未配置"的新二进制到 4 机（空 token 模式，全兼容）
2. 生成 token，分发 systemd unit 环境变量到 master + 3 节点，**master 先配**（master 收请求 + 发请求双向都要带）
3. 节点逐台配 token 重启；观察心跳/healthz
4. 验证：无 token 的 curl → 401；带 token → 正常
5. 客户端（mac）后续 CLI/mount 都带 `ATOLL_TOKEN`

## 测试计划

- 单测：中间件 401/放行/healthz 豁免/常数时间比较；client 注入 header
- e2e：配 token 集群的 put/get/修复/GC 全链路；空 token 集群向后兼容
- 实机：4 机按升级流程走一遍，验收清单见 checklist

## 不做的事（明确出界）

- 不做 per-node 身份/授权分级（都持同一 token）
- 不做 token 轮换自动化、TTL、吊销（需要时手动改 systemd 重启）
- 不做 TLS（私网内明文可接受；EasyTier 链路自身有加密）
- 不给 107 群晖客户端解封（不在本批次范围）
