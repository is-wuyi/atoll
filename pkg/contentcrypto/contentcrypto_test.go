package contentcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustDEK(t *testing.T) *DEK {
	t.Helper()
	d, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustKEK(t *testing.T, keyID string) *KEK {
	t.Helper()
	k, err := NewKEK(keyID)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestConstantsSanity 把线格式常量钉死，防无意改动。
func TestConstantsSanity(t *testing.T) {
	if MaxRecordPlaintext != 64*1024 {
		t.Fatalf("MaxRecordPlaintext = %d", MaxRecordPlaintext)
	}
	if minRecordLen != 33 || maxRecordLen != 33+64*1024 {
		t.Fatalf("record bounds wrong: %d %d", minRecordLen, maxRecordLen)
	}
	if minWrapLen != 4+1+2+12+32+16 {
		t.Fatalf("minWrapLen = %d", minWrapLen)
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	dek := mustDEK(t)
	sizes := []int{0, 1, 15, 16, 17, 100, 4096, MaxRecordPlaintext - 1, MaxRecordPlaintext}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			pt := make([]byte, size)
			rand.Read(pt)
			rec, err := SealRecord(dek, 42, 7, 3, pt)
			if err != nil {
				t.Fatalf("SealRecord: %v", err)
			}
			if want := recordHeaderLen + size + TagSize; len(rec) != want {
				t.Fatalf("record len = %d, want %d", len(rec), want)
			}
			got, err := OpenRecord(dek, 42, 7, 3, rec)
			if err != nil {
				t.Fatalf("OpenRecord: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("roundtrip mismatch")
			}
		})
	}
}

func TestSealOverLimitRejected(t *testing.T) {
	dek := mustDEK(t)
	for _, size := range []int{MaxRecordPlaintext + 1, MaxRecordPlaintext * 2} {
		if _, err := SealRecord(dek, 1, 0, 0, make([]byte, size)); err == nil {
			t.Fatalf("size %d 被接受", size)
		}
	}
}

func TestOpenStrictParsing(t *testing.T) {
	dek := mustDEK(t)
	pt := []byte("known-good plaintext for parsing tests")
	rec, err := SealRecord(dek, 42, 1, 0, pt)
	if err != nil {
		t.Fatal(err)
	}

	// 截断：任何低于最小长度的记录都拒绝。
	for cut := 0; cut < minRecordLen; cut++ {
		if _, err := OpenRecord(dek, 42, 1, 0, rec[:cut]); err == nil {
			t.Fatalf("truncated to %d 被接受", cut)
		}
	}
	// 空记录、nil 记录。
	if _, err := OpenRecord(dek, 42, 1, 0, nil); err == nil {
		t.Fatalf("nil 记录被接受")
	}

	// trailing bytes：上限内 → 并入密文 tag 失败；超上限 → 长度拒绝。
	for _, extra := range []int{1, 16, 100} {
		bad := append(bytes.Clone(rec), make([]byte, extra)...)
		out, err := OpenRecord(dek, 42, 1, 0, bad)
		if err == nil {
			t.Fatalf("trailing %d 字节被接受", extra)
		}
		if out != nil {
			t.Fatalf("验证失败却返回了明文")
		}
	}
	oversize := append(bytes.Clone(rec), make([]byte, MaxRecordPlaintext)...)
	if _, err := OpenRecord(dek, 42, 1, 0, oversize); err == nil {
		t.Fatalf("超长 trailing 被接受")
	}

	// magic / 版本篡改。
	badMagic := bytes.Clone(rec)
	badMagic[0] = 'X'
	if _, err := OpenRecord(dek, 42, 1, 0, badMagic); err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("magic 篡改未被识别: %v", err)
	}
	badVer := bytes.Clone(rec)
	badVer[4] = RecordVersion + 1
	if _, err := OpenRecord(dek, 42, 1, 0, badVer); err == nil || !strings.Contains(err.Error(), "版本") {
		t.Fatalf("版本篡改未被识别: %v", err)
	}
	zeroVer := bytes.Clone(rec)
	zeroVer[4] = 0
	if _, err := OpenRecord(dek, 42, 1, 0, zeroVer); err == nil {
		t.Fatalf("版本 0 被接受")
	}

	// 密文/nonce/tag 单字节篡改全部拒绝，且绝不返回明文。
	for _, idx := range []int{5, 10, recordHeaderLen, len(rec) / 2, len(rec) - 1} {
		bad := bytes.Clone(rec)
		bad[idx] ^= 0x01
		out, err := OpenRecord(dek, 42, 1, 0, bad)
		if err == nil {
			t.Fatalf("字节 %d 篡改被接受", idx)
		}
		if out != nil {
			t.Fatalf("篡改记录返回了未验证明文")
		}
	}
}

func TestOpenWrongBindingRejected(t *testing.T) {
	dek := mustDEK(t)
	other := mustDEK(t)
	pt := []byte("binding test")
	rec, err := SealRecord(dek, 42, 7, 3, pt)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name                        string
		objectID, generation, index uint64
		dek                         *DEK
	}{
		{"object-id", 43, 7, 3, dek},
		{"generation", 42, 8, 3, dek},
		{"index", 42, 7, 4, dek},
		{"wrong-dek", 42, 7, 3, other},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := OpenRecord(tc.dek, tc.objectID, tc.generation, tc.index, rec)
			if err == nil {
				t.Fatalf("错误绑定参数被接受")
			}
			if out != nil {
				t.Fatalf("返回了未验证明文")
			}
		})
	}
}

func TestNonceUniquePerSeal(t *testing.T) {
	dek := mustDEK(t)
	pt := []byte("same plaintext every time")
	seen := make(map[string]bool)
	cts := make(map[string]bool)
	const n = 200
	for i := 0; i < n; i++ {
		rec, err := SealRecord(dek, 1, 0, 0, pt)
		if err != nil {
			t.Fatal(err)
		}
		nonce := string(rec[5 : 5+NonceSize])
		if seen[nonce] {
			t.Fatalf("nonce 重复（%d 次内）", n)
		}
		seen[nonce] = true
		if cts[string(rec[recordHeaderLen:])] {
			t.Fatalf("相同明文产生了相同密文")
		}
		cts[string(rec[recordHeaderLen:])] = true
	}
}

func TestSealOpenConcurrent(t *testing.T) {
	dek := mustDEK(t)
	const workers = 32
	const perWorker = 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(int64(w)))
			for i := 0; i < perWorker; i++ {
				size := rng.Intn(MaxRecordPlaintext + 1)
				pt := make([]byte, size)
				rng.Read(pt)
				objectID := uint64(w+1) * 1000
				generation := uint64(i)
				index := uint64(i)
				rec, err := SealRecord(dek, objectID, generation, index, pt)
				if err != nil {
					errs <- fmt.Errorf("worker %d seal: %w", w, err)
					continue
				}
				got, err := OpenRecord(dek, objectID, generation, index, rec)
				if err != nil {
					errs <- fmt.Errorf("worker %d open: %w", w, err)
					continue
				}
				if !bytes.Equal(got, pt) {
					errs <- fmt.Errorf("worker %d: roundtrip mismatch", w)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestZeroObjectIDAndNilKeysRejected(t *testing.T) {
	dek := mustDEK(t)
	kek := mustKEK(t, "kek-1")

	if _, err := SealRecord(dek, 0, 0, 0, []byte("x")); err == nil {
		t.Fatalf("objectID=0 的 Seal 被接受")
	}
	if _, err := OpenRecord(dek, 0, 0, 0, make([]byte, minRecordLen)); err == nil {
		t.Fatalf("objectID=0 的 Open 被接受")
	}
	if _, err := WrapDEK(kek, dek, 0); err == nil {
		t.Fatalf("objectID=0 的 Wrap 被接受")
	}
	if _, err := UnwrapDEK(kek, 0, make([]byte, minWrapLen)); err == nil {
		t.Fatalf("objectID=0 的 Unwrap 被接受")
	}
	if _, err := SealRecord(nil, 1, 0, 0, []byte("x")); err == nil {
		t.Fatalf("nil DEK Seal 被接受")
	}
	if _, err := OpenRecord(nil, 1, 0, 0, nil); err == nil {
		t.Fatalf("nil DEK Open 被接受")
	}
	if _, err := WrapDEK(nil, dek, 1); err == nil {
		t.Fatalf("nil KEK Wrap 被接受")
	}
	if _, err := WrapDEK(kek, nil, 1); err == nil {
		t.Fatalf("nil DEK Wrap 被接受")
	}
	if _, err := UnwrapDEK(nil, 1, nil); err == nil {
		t.Fatalf("nil KEK Unwrap 被接受")
	}
}

func TestWrapUnwrapRoundtripAndRestore(t *testing.T) {
	// 主密钥材料由调用方自持（此处模拟调用方把它包存到自己的存储里）。
	secret := make([]byte, KeySize)
	rand.Read(secret)
	const keyID = "master-kek-2026Q4"
	kek, err := NewKEKFromSecret(keyID, secret)
	if err != nil {
		t.Fatal(err)
	}

	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	const objectID = 99887766

	// 打包：wrapped DEK + 若干记录，都可以落盘持久保存。
	wrapped, err := WrapDEK(kek, dek, objectID)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	records := make([][]byte, 4)
	for i := range records {
		pt := make([]byte, 1000+i)
		rand.Read(pt)
		rec, err := SealRecord(dek, objectID, 1, uint64(i), pt)
		if err != nil {
			t.Fatal(err)
		}
		records[i] = rec
	}

	// “恢复”：进程重启等价——用自持密钥材料重建 KEK，解包后解密。
	restoredKEK, err := NewKEKFromSecret(keyID, secret)
	if err != nil {
		t.Fatal(err)
	}
	restoredDEK, err := UnwrapDEK(restoredKEK, objectID, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if *restoredDEK != *dek {
		t.Fatalf("恢复的 DEK 不一致")
	}
	for i, rec := range records {
		if _, err := OpenRecord(restoredDEK, objectID, 1, uint64(i), rec); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	// keyID 是 KEK 身份的一部分：同密钥材料不同 keyID 必须拒绝。
	renamed, err := NewKEKFromSecret("other-"+keyID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapDEK(renamed, objectID, wrapped); err == nil {
		t.Fatalf("keyID 不匹配被接受")
	}
}

func TestUnwrapRejects(t *testing.T) {
	kek := mustKEK(t, "kek-a")
	wrongKEK := mustKEK(t, "kek-b") // 不同密钥不同 keyID
	sameKeyOtherID, err := NewKEKFromSecret("kek-a-clone", func() []byte {
		s := make([]byte, KeySize)
		copy(s, kek.key[:]) // 测试内访问私有字段以构造“同字节异 keyID”
		return s
	}())
	if err != nil {
		t.Fatal(err)
	}

	dek := mustDEK(t)
	const objectID = 123
	wrapped, err := WrapDEK(kek, dek, objectID)
	if err != nil {
		t.Fatal(err)
	}

	// 截断。
	for cut := 0; cut < minWrapLen; cut++ {
		if _, err := UnwrapDEK(kek, objectID, wrapped[:cut]); err == nil {
			t.Fatalf("truncated to %d 被接受", cut)
		}
	}
	// trailing bytes。
	bad := append(bytes.Clone(wrapped), 0x00)
	if _, err := UnwrapDEK(kek, objectID, bad); err == nil {
		t.Fatalf("trailing 被接受")
	}
	// magic / 版本。
	badMagic := bytes.Clone(wrapped)
	badMagic[0] = 'X'
	if _, err := UnwrapDEK(kek, objectID, badMagic); err == nil {
		t.Fatalf("magic 篡改被接受")
	}
	badVer := bytes.Clone(wrapped)
	badVer[4] = wrapFormatVersion + 1
	if _, err := UnwrapDEK(kek, objectID, badVer); err == nil {
		t.Fatalf("版本篡改被接受")
	}
	// nonce 与密文单字节篡改。
	keyIDLen := int(wrapped[5])<<8 | int(wrapped[6])
	nonceIdx := wrapHeaderFixedLen + keyIDLen
	for _, idx := range []int{nonceIdx, nonceIdx + NonceSize, len(wrapped) - 1} {
		b := bytes.Clone(wrapped)
		b[idx] ^= 0x01
		if _, err := UnwrapDEK(kek, objectID, b); err == nil {
			t.Fatalf("字节 %d 篡改被接受", idx)
		}
	}
	// 错误 KEK / 同字节异 keyID / 错误 objectID。
	if _, err := UnwrapDEK(wrongKEK, objectID, wrapped); err == nil {
		t.Fatalf("错误 KEK 被接受")
	}
	if _, err := UnwrapDEK(sameKeyOtherID, objectID, wrapped); err == nil {
		t.Fatalf("同字节异 keyID 被接受")
	}
	if _, err := UnwrapDEK(kek, objectID+1, wrapped); err == nil {
		t.Fatalf("错误 objectID 被接受")
	}
}

func TestKEKValidation(t *testing.T) {
	if _, err := NewKEK(""); err == nil {
		t.Fatalf("空 keyID 被接受")
	}
	if _, err := NewKEKFromSecret("k", make([]byte, KeySize-1)); err == nil {
		t.Fatalf("短密钥材料被接受")
	}
	if _, err := NewKEKFromSecret("k", make([]byte, KeySize+1)); err == nil {
		t.Fatalf("长密钥材料被接受")
	}
	if _, err := NewKEKFromSecret("", make([]byte, KeySize)); err == nil {
		t.Fatalf("空 keyID 被接受")
	}
	var nilKEK *KEK
	if nilKEK.KeyID() != "" {
		t.Fatalf("nil KEK KeyID 应为空")
	}
	if k := mustKEK(t, "kid"); k.KeyID() != "kid" {
		t.Fatalf("KeyID roundtrip: %q", k.KeyID())
	}
}

// TestDEKRandomAndDistinct 确认 DEK 来自随机源且互不相同（不是口令派生，
// 本库根本不提供口令接口）。
func TestDEKRandomAndDistinct(t *testing.T) {
	seen := make(map[DEK]bool)
	for i := 0; i < 50; i++ {
		d := mustDEK(t)
		if seen[*d] {
			t.Fatalf("DEK 重复")
		}
		seen[*d] = true
		if d == nil || *d == (DEK{}) {
			t.Fatalf("DEK 为零值")
		}
	}
}

func TestErrorsDoNotLeakKeys(t *testing.T) {
	dek := mustDEK(t)
	kek := mustKEK(t, "secret-kek-id-1234567890")
	rec, _ := SealRecord(dek, 1, 0, 0, []byte("x"))
	wrapped, _ := WrapDEK(kek, dek, 1)

	bad := bytes.Clone(rec)
	bad[len(bad)-1] ^= 0xff
	_, err := OpenRecord(dek, 1, 0, 0, bad)
	if err != nil && containsKeyMaterial(err.Error(), dek[:]) {
		t.Fatalf("记录错误消息泄漏 DEK")
	}
	badW := bytes.Clone(wrapped)
	badW[len(badW)-1] ^= 0xff
	_, err = UnwrapDEK(kek, 1, badW)
	if err != nil && containsKeyMaterial(err.Error(), kek.key[:]) || err != nil && containsKeyMaterial(err.Error(), dek[:]) {
		t.Fatalf("包裹错误消息泄漏密钥材料")
	}
}

func containsKeyMaterial(msg string, key []byte) bool {
	if len(msg) == 0 || len(key) == 0 {
		return false
	}
	// 错误消息是静态中文串，正常不会含密钥；这里查常见 hex 编码兜底。
	lower := fmt.Sprintf("%x", key)
	upper := fmt.Sprintf("%X", key)
	return strings.Contains(msg, lower) || strings.Contains(msg, upper)
}

// TestKeyIDLengthBound 把 keyID 长度边界钉死：>maxKeyIDLen 的 keyID 必须在
// 所有构造入口与 WrapDEK 被拒——否则会产出“能包装、解包端必拒”的不可恢复
// 包裹（解包端因线格式歧义/上限校验永远拒绝它）。这正是本轮修复的缺陷：
// 修复前 NewKEK/NewKEKFromSecret 接受任意长度、WrapDEK 用 uint16 截断长度。
func TestKeyIDLengthBound(t *testing.T) {
	// 1、255 合法。
	for _, n := range []int{1, maxKeyIDLen} {
		id := strings.Repeat("k", n)
		if _, err := NewKEK(id); err != nil {
			t.Fatalf("keyID 长度 %d 应合法: %v", n, err)
		}
		if _, err := NewKEKFromSecret(id, make([]byte, KeySize)); err != nil {
			t.Fatalf("keyID 长度 %d 应合法(secret): %v", n, err)
		}
	}
	// 256、65536 非法：构造入口拒绝。
	for _, n := range []int{maxKeyIDLen + 1, 256, 4096, 65536} {
		id := strings.Repeat("k", n)
		if _, err := NewKEK(id); err == nil {
			t.Fatalf("NewKEK 接受了超长 keyID(%d)", n)
		}
		if _, err := NewKEKFromSecret(id, make([]byte, KeySize)); err == nil {
			t.Fatalf("NewKEKFromSecret 接受了超长 keyID(%d)", n)
		}
	}
	// 兜底：即使有包内旁路构造出超长 keyID 的 KEK，WrapDEK 也拒绝。
	dek := mustDEK(t)
	longID := &KEK{keyID: strings.Repeat("k", maxKeyIDLen+1)}
	if _, err := WrapDEK(longID, dek, 1); err == nil {
		t.Fatalf("WrapDEK 未兜底超长 keyID")
	}
	// 回归保证：合法 keyID 的包裹往返不受影响。
	kek, err := NewKEK(strings.Repeat("k", maxKeyIDLen))
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapDEK(kek, dek, 7)
	if err != nil {
		t.Fatalf("满长 keyID 包装失败: %v", err)
	}
	if _, err := UnwrapDEK(kek, 7, wrapped); err != nil {
		t.Fatalf("满长 keyID 解包失败: %v", err)
	}
}

// TestUnwrapExactLengthBeforeGCM 验证解包在把任何字节喂给 GCM 之前就完成
// 精确长度检查：合法包裹总长恰为 header+keyID+DEK+tag，多一字节（哪怕巨量
// trailing）都直接按长度拒绝，不进入 GCM 验证（防内存/时间放大）。
func TestUnwrapExactLengthBeforeGCM(t *testing.T) {
	kek := mustKEK(t, "kek-a")
	dek := mustDEK(t)
	const objectID = 5
	wrapped, err := WrapDEK(kek, dek, objectID)
	if err != nil {
		t.Fatal(err)
	}
	wantLen := wrapHeaderFixedLen + len("kek-a") + KeySize + TagSize
	if len(wrapped) != wantLen {
		t.Fatalf("wrapped len = %d, want %d", len(wrapped), wantLen)
	}
	// 少 1 字节 = 截断拒绝。
	if _, err := UnwrapDEK(kek, objectID, wrapped[:len(wrapped)-1]); err == nil {
		t.Fatalf("少 1 字节被接受")
	}
	// 巨量 trailing：64MiB 也必须立即拒绝（不进 GCM、不超时、不 panic）。
	huge := make([]byte, len(wrapped)+64<<20)
	copy(huge, wrapped)
	done := make(chan error, 1)
	go func() {
		_, err := UnwrapDEK(kek, objectID, huge)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("64MiB trailing 被接受")
		}
		if !strings.Contains(err.Error(), "trailing") {
			t.Fatalf("应按 trailing bytes 拒绝: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("巨量 trailing 未被立即拒绝（疑似进 GCM）")
	}
	// 中等 trailing（1、2、16、1MiB）也全部按长度拒绝。
	for _, extra := range []int{1, 2, 16, 1 << 20} {
		bad := append(bytes.Clone(wrapped), make([]byte, extra)...)
		if _, err := UnwrapDEK(kek, objectID, bad); err == nil {
			t.Fatalf("trailing %d 被接受", extra)
		}
	}
	// keyIDLen 字段本身超过 255：无论总长多少，直接拒绝。
	badLen := bytes.Clone(wrapped)
	binary.BigEndian.PutUint16(badLen[5:7], 300)
	if _, err := UnwrapDEK(kek, objectID, badLen); err == nil {
		t.Fatalf("超限 keyIDLen 字段被接受")
	}
}

// TestKeyFormattingDoesNotLeak 钉死 DEK/KEK 的全部 fmt 渲染路径（String、
// %#v/GoString、各动词、嵌套结构体）都不泄漏密钥字节——DEK/KEK 是密钥材料，
// fmt 反射底层数组会直接把 32 字节密钥打进日志。
func TestKeyFormattingDoesNotLeak(t *testing.T) {
	dek := mustDEK(t)
	kek := mustKEK(t, "fmt-kek")
	dekHex := fmt.Sprintf("%x", dek[:])
	kekHex := fmt.Sprintf("%x", kek.key[:])
	subjects := []struct {
		name string
		val  interface{ Format(fmt.State, rune) }
	}{
		{"dek", dek}, {"kek", kek},
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t"}
	for _, s := range subjects {
		for _, v := range verbs {
			got := fmt.Sprintf(v, s.val)
			if strings.Contains(got, dekHex) || strings.Contains(got, kekHex) {
				t.Fatalf("%s 动词 %q 泄漏密钥字节: %q", s.name, v, got)
			}
			// %x/%X 对密钥类型必须渲染占位而非 hex(密钥)。
			if (v == "%x" || v == "%X") && strings.ContainsAny(got, "0123456789abcdefABCDEF") && len(got) > 16 {
				t.Fatalf("%s 动词 %q 疑似渲染了密钥 hex: %q", s.name, v, got)
			}
		}
	}
	// 嵌套渲染（结构体字段）同样不泄漏。
	nested := fmt.Sprintf("%#v %v", struct {
		D *DEK
		K *KEK
	}{dek, kek}, dek)
	if strings.Contains(nested, dekHex) || strings.Contains(nested, kekHex) {
		t.Fatalf("嵌套渲染泄漏密钥: %q", nested)
	}
	// 指针与值拷贝均须脱敏；显式转换为原始字节不属于 fmt 的保护范围。
	ptr := fmt.Sprintf("%x %X", dek, dek)
	if strings.Contains(ptr, dekHex) {
		t.Fatalf("*DEK 的十六进制动词渲染泄漏了密钥: %q", ptr)
	}
}
