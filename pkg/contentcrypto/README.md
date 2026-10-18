# pkg/contentcrypto

版本化 AES-256-GCM 内容记录加密与 DEK 包装库。只依赖 Go 标准库。

**定位声明：面向后续“对象内随机读取”的记录化加密设计；当前生产上传链路并未接入，也没有“全产品已加密”这回事。** 返回的记录/包裹字节仅用于持久保存与恢复演练。

## API 一览

```go
dek, err := contentcrypto.NewDEK()                       // 每对象 32 字节随机 DEK
rec,  err := contentcrypto.SealRecord(dek, objID, gen, idx, plaintext)
pt,   err := contentcrypto.OpenRecord(dek, objID, gen, idx, rec)

kek, err := contentcrypto.NewKEK(keyID)                  // 随机主密钥
kek, err := contentcrypto.NewKEKFromSecret(keyID, 32字节) // 从调用方自持材料恢复
wrapped, err := contentcrypto.WrapDEK(kek, dek, objID)   // DEK 包裹（可持久保存）
dek,  err := contentcrypto.UnwrapDEK(kek, objID, wrapped)
```

## 线格式与版本

记录（`ATCR`）：

```
magic(4) | version(1)=1 | nonce(12) | ciphertext||tag(16)
```

DEK 包裹（`ATWK`）：

```
magic(4) | version(1)=1 | keyIDLen(2,BE) | keyID | nonce(12) | wrapped(32+16)
```

版本字节不匹配即拒绝；未来改格式必须升版本并保留旧版本解析路径或做显式迁移。

## 绑定（AAD）

- 记录 AAD = `ProtocolDomain("atoll-content-record-v1")` + `"record"` + 版本 + objectID + generation + record index + 明文长度。**任何绑定值不匹配都 tag 失败**：记录不能被挪到别的对象、别的代、别的记录位。
- 包裹 AAD = `ProtocolDomain` + `"dek-wrap"` + 包裹格式版本 + keyID + objectID。包裹与对象身份绑定；换 KEK（换 keyID）后旧包裹只能由旧 KEK 解开。
- objectID 按协议定义**禁止 0**；keyID 禁止为空。`Open`/`Unwrap` 在验证通过前绝不返回任何明文/密钥材料。

## 明文长度：无独立线格式字段

记录里**没有**存储明文长度字段：明文长度由密文段长度（含 16B tag）推导并进 AAD。因此：

- trailing bytes 会被并入密文参与 tag 校验 → 拒绝；超过上限的 trailing 直接按长度拒绝。
- 声称的“长度绑定”是 AAD 意义上的绑定，不是线格式字段。

## Nonce 预算（不是无限的）

每次 `SealRecord`/`WrapDEK` 独立生成随机 96bit nonce。随机 nonce 的唯一性是概率性的：同一 DEK 下 N 次封包出现碰撞的概率约为 `N²/2^97`。预算约束：

- 每对象记录上限 262144 条（16 GiB ÷ 64 KiB），全量写一遍的碰撞概率约 2^-61，可忽略。
- **重写/重封同一 (objectID, generation, index) 也消耗 nonce 预算**（每次 Seal 都是新的随机 nonce）。同一 DEK 的累计 Seal 次数建议控制在 2^32 以内（2^32 次时碰撞概率约 2^-33）；预期会高频重写的场景应改为引入新 generation 并换 DEK，或升级为确定性 nonce 方案（需重设计，不能只改 nonce 生成）。
- 不要在同一 DEK 上长期无限封包；本库不做计数器持久化，预算由使用方（未来的对象服务）监控。

## DEK / KEK 约束

- DEK 必须由 `NewDEK`（crypto/rand）生成；**口令/密码绝不能当 DEK**（本库不提供任何口令 KDF 接口）。
- KEK 的生成、存储、备份、轮换完全归调用方：本库不做账号体系、不做中心化配置。`NewKEKFromSecret` 仅用于把调用方自持的 32 字节材料装配成 KEK（演示“包存→恢复→解包”）。
- keyID 是 KEK 的身份：**非空且 ≤255 字节**（`NewKEK`/`NewKEKFromSecret`/`WrapDEK` 三处入口一致校验——超长 keyID 会造出“能包装、解包端必拒”的不可恢复包裹，`TestKeyIDLengthBound` 钉死）。包裹内嵌 keyID，解包时先比对（恒时比较）再解密；同密钥字节不同 keyID 一律拒绝。
- 解包在把任何字节喂给 GCM 之前先做**精确长度检查**（`header+keyID+32+16`，多一字节即拒），巨量 trailing bytes 不会进入 GCM 验证（`TestUnwrapExactLengthBeforeGCM`）。
- **Go 无法承诺内存零化**：DEK/KEK 是普通 Go 内存，值拷贝与 swap 都可能留下痕迹。`DEK` 是可显式读取的字节数组，调用方仍可用 `dek[:]` 导出材料；默认 `fmt` 对指针、值及嵌套字段都脱敏，这不是访问控制或内存擦除。KEK 的内部密钥字段不导出。

## 恢复演练

1. 生成/恢复 KEK（调用方自持 32 字节材料 + keyID）。
2. 每对象：`NewDEK` → `WrapDEK` 落盘（包裹与对象绑定）→ 数据按记录 `SealRecord` 落盘。
3. 恢复：重建 KEK → `UnwrapDEK(kek, objectID, wrapped)` → 按记录 `OpenRecord`。任一绑定值或密钥不对都会拒绝，不会返回错误数据。
