# pkg/edgeidentity

边缘节点持久 Ed25519 身份库。只依赖 Go 标准库。**当前未接入任何生产链路**，属自治多副本执行闭环的基础件。

## API 一览

```go
id, err := edgeidentity.LoadOrCreate(path)   // 加载或原子创建持久身份
// 显式 opt-in 的非原子退化发布（仅限明确评估过的场景）：
id, err := edgeidentity.LoadOrCreate(path, edgeidentity.WithAllowNonAtomicFallback())
id.NodeID()                                  // 稳定节点标识（从公钥派生）
id.PublicKey()                               // Ed25519 公钥副本
sig, err := id.Sign(challenge)               // 对 typed Challenge 签名
err := edgeidentity.Verify(pub, ch, sig)     // 真实当前时间、零偏移校验
err := edgeidentity.VerifyAt(pub, ch, sig, now, skew) // 显式 now 与显式 skew
```

## NodeID：版本化身份，明确不是 libp2p PeerID

- 格式：`nid1-` + base32 **RFC 4648 标准字母表（大写 A-Z/2-7）** 无填充（SHA-256(pubkey)，256bit 全长不截断）。
- **大小写敏感**：小写变体是不同的字符串，比较 NodeID 一律精确字节比较（`TestNodeIDEncodingPinned` 钉死编码）。
- `nid1` 前缀是派生体系的版本号；换派生算法必须换前缀。
- **不是 libp2p PeerID**：PeerID 是公钥 protobuf 编码的 multihash，两者不可互换、不可互推。对接任何 libp2p 层时需要在边界做显式转换/映射，不能直接混用。

## 私钥文件格式与版本

```
offset 0 : magic "ATID"（4 字节）
offset 4 : 格式版本 = 1（1 字节）
offset 5 : ed25519 私钥 64 字节（seed 32 + 公钥 32）
总长 69 字节，权限 0600
```

读取时严格校验 magic、版本、定长，并且**用 `NewKeyFromSeed` 从 seed 重导出公钥与文件后半段比对**（注意：标准库 `PrivateKey.Public()` 只是原样返回 `priv[32:]`，不做重导出，不能用于该一致性校验）。任何不符一律拒绝。

## 发布与恢复约束

- 发布流程：唯一 temp（0600）写入 + 文件 fsync → `os.Link` 原子不替换发布 → 删 temp → 父目录 fsync。读取方只会看到完整文件或 ENOENT。
- **默认 fail-closed**：文件系统不支持 hard link（如部分 SMB/FUSE 挂载，本仓库所在卷即如此）时，`LoadOrCreate` 直接返回 `ErrNonAtomicFS`，绝不悄悄降级。应把身份放到本地文件系统。
- `WithAllowNonAtomicFallback()` 是显式 opt-in 的非原子退化发布（O_EXCL 独占直写）：**它不是原子发布**——崩溃可能把不完整文件留在最终路径；此后 `LoadOrCreate` 只会有界重试后报错待人处理，绝不重生成；窗口期并发读者可能失败，**不承诺并发调用全部成功**。生产正常拓扑不应使用该选项。该路径**失败时 fail-stop**：发布中写入/sync/close 失败一律保留 final 路径上的残片并报错待人处理，绝不 `os.Remove` final 路径（O_EXCL 只保证创建那一刻的独占，之后他方可能已合法替换同名文件，盲删会删掉陌生人的合法文件）。
- **崩溃残片（长度不足 69 字节）不会自动重生成**：重试超窗后返回错误，需要运维确认后手动删除该文件再重建。这是刻意设计——本库无法区分“残片”与“被截断的合法密钥”，宁可拒绝。
- **损坏文件绝不重生成**：magic/版本/长度/两半不一致的文件保持原样，`LoadOrCreate` 返回错误。绝不覆盖、绝不静默换身份。
- symlink（含指向合法密钥的别名）、目录、FIFO、权限含 group/other 位的文件一律拒绝，不做自动 chmod/自动修复。
- 并发 `LoadOrCreate`（同进程或跨进程）在原子发布路径下由不替换发布仲裁：恰好一个身份胜出，其余调用方读取胜者落盘的同一份文件。退化路径无此保证（见上）。

## 签名边界（Challenge）

- 只对 caller 明确定义的 `Challenge` 签名：`Nonce`（必填，建议 ≥16 字节）、`Audience`（必填）、`ExpiresAt`（必填，零值在 Sign 即拒绝）、可选 `NotBefore`/`Purpose`/`Extras`。签名输入 = 长度前缀规范编码（含 `IdentityProtocolVersion` 域分隔串与签名者 NodeID）。
- **不构造通用万能 token**：Challenge 与签名的传输由调用方协议完成，本库不做序列化信封、不做密钥协商。
- **防重放不在本库**：验证签名不阻止同一 (Challenge, sig) 被重复验证；一次性性由上层对 Nonce 做登记（已见即拒）。
- `Verify` 使用真实时间、零时钟偏移；需要容差必须显式调 `VerifyAt(now, skew)`，放宽窗口是调用方的决定。时间必须在 Unix 纳秒可表示范围内，不允许利用溢出别名修改签名的有效期；非零 NotBefore 必须早于 ExpiresAt。
- 稳定身份与可变地址分离：本库只产出 NodeID；节点地址（IP/端口/拨号信息）变化不影响身份，由上层协议负责地址发现与绑定。

## 其他

- 私钥材料绝不进日志、错误消息或任何 fmt 渲染：`Identity.String()` 只返回 NodeID；`Identity` 实现 `fmt.Formatter`/`GoStringer`，`%#v`、`%+v`、`%x` 等所有动词及嵌套结构体渲染都只输出 NodeID（`TestIdentityFormattingDoesNotLeakKey` 钉死）。
- **持久化边界**：创建方完成文件和目录同步；加载现有密钥同样同步文件及父目录，避免在并发创建者尚未同步目录时提前确认身份。同步失败会返回错误而不会重生成身份；保证依赖底层文件系统正确实现同步语义。
- 非 unix 平台无 `O_NOFOLLOW`：symlink 竞态防护退化为句柄 Stat 检查（本仓库目标平台为 darwin/linux，不受影响）。
