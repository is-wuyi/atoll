# 批次 B：组件间认证 — 任务清单

## Task 1: pkg/auth 包（中间件 + 注入）
- [ ] `Wrap(handler, token)`：常数时间比较，401 JSON 错误体
- [ ] `healthz` 豁免路径白名单
- [ ] 空 token = 不启用认证（兼容模式），此模式记 WARN
- [ ] `Sign(req, token)` / 传输层统一注入（http.RoundTripper）
- [ ] `atoll auth gen` 子命令：crypto/rand 32B → base64

## Task 2: master 接入
- [ ] Handler() 用 auth.Wrap 包装（token 来自 flag/ATOLL_TOKEN）
- [ ] master 主动请求（notifyObjectDelete、scanner 的 triggerPull/GC 请求）注入 token
- [ ] 单测：401/放行/豁免

## Task 3: node 接入
- [ ] Handler() 用 auth.Wrap 包装
- [ ] node 主动请求（注册/心跳/replicated/推送/pull）注入 token
- [ ] 单测

## Task 4: client/mount/CLI 接入
- [ ] client 包 http.Client 挂 RoundTripper（构造时传入 token）
- [ ] CLI：-token flag + ATOLL_TOKEN 环境变量
- [ ] mount 继承 client token
- [ ] e2e：带 token 全链路（put/get/修复/GC）

## Task 5: 实机部署与验收
- [ ] 第一轮滚动：4 机新二进制，空 token（兼容窗口验证）
- [ ] 生成 token，master 先配，节点逐台配
- [ ] 验收：无 token curl → 401；带 token → 全通
- [ ] mac 客户端 export ATOLL_TOKEN
- [ ] 验收清单见 checklist.md
