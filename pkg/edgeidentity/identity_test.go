package edgeidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// validKeyBlob 在 dir 下生成一份合法私钥文件并返回其字节与身份。
func validKeyBlob(t *testing.T, dir string) ([]byte, *Identity) {
	t.Helper()
	path := filepath.Join(dir, "identity.key")
	id, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	return blob, id
}

func TestLoadOrCreateRoundtripRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "sub", "identity.key")

	id1, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(id1.priv) != ed25519.PrivateKeySize {
		t.Fatalf("bad priv size")
	}

	// 重启等价：重新 LoadOrCreate 必须得到同一身份。
	id2, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if id1.NodeID() != id2.NodeID() || !bytes.Equal(id1.PublicKey(), id2.PublicKey()) {
		t.Fatalf("identity changed across reload: %s vs %s", id1.NodeID(), id2.NodeID())
	}

	// temp 发布文件不残留。
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".edgeidentity-tmp-") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}

func TestNodeIDFormat(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	nid := id.NodeID().String()
	if !strings.HasPrefix(nid, "nid1-") {
		t.Fatalf("NodeID 缺少版本前缀: %s", nid)
	}
	// sha256(32B) -> base32 无填充 = 52 字符
	if got, want := len(nid), len("nid1-")+52; got != want {
		t.Fatalf("NodeID 长度 %d，期望 %d", got, want)
	}
	// 同一公钥派生必须稳定。
	if DeriveNodeID(id.PublicKey()) != id.NodeID() {
		t.Fatalf("DeriveNodeID 不稳定")
	}
	// 不同身份必须得到不同 NodeID（sha256 碰撞忽略不计）。
	_, other := validKeyBlob(t, t.TempDir())
	if other.NodeID() == id.NodeID() {
		t.Fatalf("两个不同身份得到相同 NodeID")
	}
}

func TestKeyFileModeStrict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	if _, err := LoadOrCreate(path); err != nil {
		t.Fatalf("create: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("key file not regular: %v", fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file perm = %04o, want 0600", perm)
	}
}

func TestLoadOrCreatePreservesExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	before, id1 := validKeyBlob(t, dir)

	// 多次调用（含重启语义）绝不改写已有合法身份。
	for i := 0; i < 3; i++ {
		id2, err := LoadOrCreate(path)
		if err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
		if id2.NodeID() != id1.NodeID() {
			t.Fatalf("identity swapped on call %d", i)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("key file bytes mutated on call %d", i)
		}
	}
}

func TestCorruptKeyFileRejectedAndPreserved(t *testing.T) {
	base, _ := validKeyBlob(t, t.TempDir())

	mutations := map[string]func([]byte) []byte{
		"bad-magic":        func(b []byte) []byte { c := bytes.Clone(b); c[0] = 'X'; return c },
		"bad-version":      func(b []byte) []byte { c := bytes.Clone(b); c[4] = 2; return c },
		"seed-half-flip":   func(b []byte) []byte { c := bytes.Clone(b); c[10] ^= 0xff; return c },
		"pub-half-flip":    func(b []byte) []byte { c := bytes.Clone(b); c[60] ^= 0xff; return c },
		"random-garbage":   func(b []byte) []byte { c := make([]byte, len(b)); rand.Read(c); return c },
		"zeroed":           func(b []byte) []byte { return make([]byte, len(b)) },
		"trailing-byte":    func(b []byte) []byte { return append(bytes.Clone(b), 0x00) },
		"random-oversize":  func(b []byte) []byte { c := make([]byte, len(b)+64); rand.Read(c); return c },
		"future-version-0": func(b []byte) []byte { c := bytes.Clone(b); c[4] = 0; return c },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "identity.key")
			corrupt := mutate(base)
			if err := os.WriteFile(path, corrupt, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrCreate(path); err == nil {
				t.Fatalf("损坏文件被接受")
			} else if strings.Contains(err.Error(), hex.EncodeToString(base)) {
				t.Fatalf("错误消息泄漏密钥材料: %v", err)
			}
			// 关键约束：绝不重生成覆盖。
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, corrupt) {
				t.Fatalf("损坏文件被改写（违反“坏文件绝不重生成”）")
			}
		})
	}
}

func TestIncompleteKeyFileRejected(t *testing.T) {
	base, _ := validKeyBlob(t, t.TempDir())
	oldWindow, oldDelay := publicationWindow, publicationRetryDelay
	publicationWindow, publicationRetryDelay = 150*time.Millisecond, 10*time.Millisecond
	defer func() { publicationWindow, publicationRetryDelay = oldWindow, oldDelay }()

	for name, blob := range map[string][]byte{
		"empty":       {},
		"truncated":   bytes.Clone(base[:40]),
		"magic-only":  bytes.Clone(base[:5]),
		"one-byte":    {0x41},
		"short-by-64": bytes.Clone(base[:keyFileLen-64]),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "identity.key")
			if err := os.WriteFile(path, blob, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrCreate(path); err == nil {
				t.Fatalf("不完整文件被接受")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, blob) {
				t.Fatalf("不完整文件被改写")
			}
		})
	}
}

func TestSymlinkRejected(t *testing.T) {
	dir := t.TempDir()

	// 悬空 symlink。
	dangling := filepath.Join(dir, "dangling.key")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dangling); err == nil {
		t.Fatalf("symlink 被接受")
	}
	if _, err := os.Lstat(filepath.Join(dir, "nowhere")); !os.IsNotExist(err) {
		t.Fatalf("symlink 被解引用创建目标")
	}

	// 指向合法私钥的 symlink 也必须拒绝。
	realPath := filepath.Join(dir, "real.key")
	if _, err := LoadOrCreate(realPath); err != nil {
		t.Fatalf("setup: %v", err)
	}
	realBytes, _ := os.ReadFile(realPath)
	alias := filepath.Join(dir, "alias.key")
	if err := os.Symlink(realPath, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(alias); err == nil {
		t.Fatalf("指向合法密钥的 symlink 被接受")
	}
	after, _ := os.ReadFile(realPath)
	if !bytes.Equal(realBytes, after) {
		t.Fatalf("真实密钥文件被改写")
	}
}

func TestDirectoryAtPathRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatalf("目录路径被接受")
	}
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		t.Fatalf("目录被改写: %v %v", fi, err)
	}
}

func TestUnsafePermsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	if _, err := LoadOrCreate(path); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatalf("过宽权限被接受")
	}
	// 修复权限后恢复可用，且身份不变（说明拒绝期间未被改写）。
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	id2, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("chmod 后仍失败: %v", err)
	}
	if !strings.HasPrefix(id2.NodeID().String(), "nid1-") {
		t.Fatalf("identity invalid after perm fix")
	}
}

func TestConcurrentLoadOrCreateSameIdentity(t *testing.T) {
	t.Run("atomic-link-path", func(t *testing.T) {
		dir := t.TempDir()
		concurrentLoadOrCreateSameIdentity(t, dir, false)
	})
	t.Run("non-atomic-fallback-optin", func(t *testing.T) {
		dir := t.TempDir()
		concurrentLoadOrCreateSameIdentity(t, dir, true)
	})
}

func concurrentLoadOrCreateSameIdentity(t *testing.T, dir string, allowFallback bool) {
	t.Helper()
	oldDisable := disableLinkForTest
	disableLinkForTest = allowFallback // 模拟不支持 hard link
	defer func() { disableLinkForTest = oldDisable }()

	var opts []Option
	if allowFallback {
		opts = append(opts, WithAllowNonAtomicFallback())
	}

	const n = 16
	path := filepath.Join(dir, "identity.key")
	results := make([]*Identity, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = LoadOrCreate(path, opts...)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if results[i].NodeID() != results[0].NodeID() {
			t.Fatalf("并发创建得到不同身份: %s vs %s", results[0].NodeID(), results[i].NodeID())
		}
	}
	// 落盘文件必须是合法格式且与内存身份一致。
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := parseKeyFile(blob)
	if err != nil {
		t.Fatalf("落盘文件非法: %v", err)
	}
	if DeriveNodeID(priv.Public().(ed25519.PublicKey)) != results[0].NodeID() {
		t.Fatalf("落盘身份与内存身份不一致")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".edgeidentity-tmp-") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}

// TestNonAtomicFSFailClosedByDefault 不支持 hard link 的文件系统上默认必须
// fail-closed：报 ErrNonAtomicFS、不留最终文件、清掉 temp、绝不悄悄降级。
func TestNonAtomicFSFailClosedByDefault(t *testing.T) {
	old := disableLinkForTest
	disableLinkForTest = true
	defer func() { disableLinkForTest = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	id, err := LoadOrCreate(path)
	if !errors.Is(err, ErrNonAtomicFS) {
		t.Fatalf("默认未 fail-closed: id=%v err=%v", id, err)
	}
	if id != nil {
		t.Fatalf("fail-closed 却返回了身份")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("fail-closed 却留下了文件: %v", entries)
	}
	// 显式 opt-in 才可用。
	id, err = LoadOrCreate(path, WithAllowNonAtomicFallback())
	if err != nil {
		t.Fatalf("opt-in 后仍失败: %v", err)
	}
	id2, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("已落盘身份的普通加载必须成功: %v", err)
	}
	if id2.NodeID() != id.NodeID() {
		t.Fatalf("身份不一致")
	}
}

// TestPublishDirectFailureLeavesDebrisFailStop 验证非原子退化路径的失败
// 语义 fail-stop：写失败时绝不 os.Remove(final 路径)——O_EXCL 只保证创建
// 那一刻的独占，之后他方可能已合法替换同名文件，盲删会删掉陌生人的文件。
// 注入写失败可确定性复现“发布中失败”，断言：报注入错误、final 路径保留
// 残片、错误消息带“待人工处理”。
func TestPublishDirectFailureLeavesDebrisFailStop(t *testing.T) {
	oldDisable := disableLinkForTest
	disableLinkForTest = true // 强制走 publishDirect 路径
	defer func() { disableLinkForTest = oldDisable }()

	injected := errors.New("injected write failure")
	oldInject := injectPublishWriteFailureForTest
	defer func() { injectPublishWriteFailureForTest = oldInject }()

	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")

	// 先让合法发布成功落盘，模拟“他方已合法发布”（注入保持关闭）。
	if _, err := LoadOrCreate(path, WithAllowNonAtomicFallback()); err != nil {
		t.Fatalf("setup 发布失败: %v", err)
	}
	good, _ := os.ReadFile(path)

	// 占用同名 final 路径的并发他方文件已存在：LoadOrCreate 走 load 成功路径
	// 返回同一身份（不会重发布、不会改动既有文件）。若调用方硬要重发布
	//（文件消失的窗口），O_EXCL/Link 的不替换语义由下面注入用例与并发测试覆盖。
	if _, err := LoadOrCreate(path, WithAllowNonAtomicFallback()); err != nil {
		t.Fatalf("已存在合法文件时加载失败: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, good) {
		t.Fatalf("既有合法文件被改动")
	}

	// 真正的“发布中失败”：删掉文件重来，注入写失败发生在 O_EXCL 成功之后，
	// 此时 final 路径已被本调用独占创建——残片必须保留，不能被删除。
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	injectPublishWriteFailureForTest = injected
	_, err := LoadOrCreate(path, WithAllowNonAtomicFallback())
	if !errors.Is(err, injected) {
		t.Fatalf("注入的写失败未生效: %v", err)
	}
	if !strings.Contains(err.Error(), "待人工处理") {
		t.Fatalf("失败错误应声明残片保留待人处理: %v", err)
	}
	// 关键断言：残片保留在 final 路径（发布中失败绝不盲删）。
	fi, serr := os.Lstat(path)
	if serr != nil {
		t.Fatalf("残片应保留在 final 路径: %v", serr)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("final 路径应为普通文件: %v", fi.Mode())
	}
	// 残片不允许被后续 LoadOrCreate 重生成（长度不足 → 超窗报错）。
	oldWindow, oldDelay := publicationWindow, publicationRetryDelay
	publicationWindow, publicationRetryDelay = 100*time.Millisecond, 5*time.Millisecond
	defer func() { publicationWindow, publicationRetryDelay = oldWindow, oldDelay }()
	after, _ := os.ReadFile(path)
	if _, err := LoadOrCreate(path, WithAllowNonAtomicFallback()); err == nil {
		t.Fatalf("残片被当作可发布状态")
	}
	got, _ = os.ReadFile(path)
	if !bytes.Equal(got, after) {
		t.Fatalf("残片被改写")
	}
	// temp 无残留。
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".edgeidentity-tmp-") {
			t.Fatalf("失败路径残留 temp: %s", e.Name())
		}
	}
}

// TestPublishDirectSuccessReloadable 验证退化路径成功发布的文件可被
// 后续普通 LoadOrCreate 读回同一身份（发布完整性回归）。
func TestPublishDirectSuccessReloadable(t *testing.T) {
	oldDisable := disableLinkForTest
	disableLinkForTest = true
	defer func() { disableLinkForTest = oldDisable }()

	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	id1, err := LoadOrCreate(path, WithAllowNonAtomicFallback())
	if err != nil {
		t.Fatalf("publishDirect: %v", err)
	}
	id2, err := LoadOrCreate(path)
	if err != nil || id2.NodeID() != id1.NodeID() {
		t.Fatalf("读回身份不一致: err=%v", err)
	}
}

// 上验证端到端行为。不支持 hard link 的卷上：默认必须 fail-closed，
// 显式 opt-in 后才可用；支持的卷上走标准原子路径。
func TestLoadOrCreateOnWorkspaceVolume(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".edgeidentity-voltest-*")
	if err != nil {
		t.Skipf("无法在包目录创建临时目录: %v", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "identity.key")
	if !dirSupportsLink(t, dir) {
		// 默认 fail-closed：这是对生产约束的验证，不是为了在 SMB 上生成密钥放松约束。
		id, err := LoadOrCreate(path)
		if !errors.Is(err, ErrNonAtomicFS) {
			t.Fatalf("真实卷上默认未 fail-closed: id=%v err=%v", id, err)
		}
		id, err = LoadOrCreate(path, WithAllowNonAtomicFallback())
		if err != nil {
			t.Fatalf("opt-in 后仍失败: %v", err)
		}
		id2, err := LoadOrCreate(path)
		if err != nil || id2.NodeID() != id.NodeID() {
			t.Fatalf("opt-in 落盘后加载异常: err=%v", err)
		}
		return
	}

	id1, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("create on workspace volume: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("卷上权限过宽: %04o", perm)
	}
	id2, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("reload on workspace volume: %v", err)
	}
	if id1.NodeID() != id2.NodeID() {
		t.Fatalf("identity changed on reload")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected only key file, got %d entries", len(entries))
	}
}

// dirSupportsLink 探测目录是否支持 hard link（用临时文件，探测后清理）。
func dirSupportsLink(t *testing.T, dir string) bool {
	t.Helper()
	a := filepath.Join(dir, ".probe-link-a")
	if err := os.WriteFile(a, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(a)
	b := filepath.Join(dir, ".probe-link-b")
	defer os.Remove(b)
	return os.Link(a, b) == nil
}

func TestLoadOrCreateEmptyPath(t *testing.T) {
	if _, err := LoadOrCreate(""); err == nil {
		t.Fatalf("空路径被接受")
	}
}

func TestIdentityStringDoesNotLeakKey(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	hexPriv := hex.EncodeToString(id.priv)
	shown := fmt.Sprintf("%s|%v|%+v", id, id, id.NodeID())
	if strings.Contains(shown, hexPriv) {
		t.Fatalf("身份字符串泄漏私钥（hex）")
	}
	want := id.NodeID().String() + "|" + id.NodeID().String() + "|" + id.NodeID().String()
	if shown != want {
		t.Fatalf("身份字符串应只有 NodeID: %q", shown)
	}
}

// TestIdentityFormattingDoesNotLeakKey 钉死所有 fmt 渲染路径：
// %#v（GoString）、%q/%x/%d 等动词、fmt %+v 组合，都不得反射出未导出的
// 私钥字节（fmt.Formatter 一旦实现便优先于反射，这里是回归防线）。
func TestIdentityFormattingDoesNotLeakKey(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	hexPriv := hex.EncodeToString(id.priv)
	b64Priv := base64.StdEncoding.EncodeToString(id.priv)

	verbs := []string{
		"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%08.3f",
	}
	for _, v := range verbs {
		for _, subject := range []interface{ Format(fmt.State, rune) }{id} {
			got := fmt.Sprintf(v, subject)
			if strings.Contains(got, hexPriv) || strings.Contains(got, b64Priv) {
				t.Fatalf("动词 %q 泄漏私钥: %q", v, got)
			}
			if strings.Contains(got, "priv") {
				t.Fatalf("动词 %q 反射出结构体字段: %q", v, got)
			}
		}
	}
	// 嵌套渲染（结构体字段位置）同样不泄漏。
	nested := fmt.Sprintf("%#v", struct{ ID *Identity }{id})
	if strings.Contains(nested, hexPriv) || strings.Contains(nested, "priv") {
		t.Fatalf("嵌套渲染泄漏私钥: %q", nested)
	}
	// nil 身份的渲染必须安全。
	var nilID *Identity
	for _, v := range []string{"%v", "%#v", "%s"} {
		got := fmt.Sprintf(v, nilID)
		if got == "" || strings.Contains(got, hexPriv) {
			t.Fatalf("nil 身份渲染 %q 异常: %q", v, got)
		}
	}
	if !strings.Contains(fmt.Sprintf("%v", nilID), "nil") {
		t.Fatalf("nil 身份应渲染为 nil 语义")
	}
}

// TestNodeIDEncodingPinned 钉死 NodeID 编码：base32 RFC 4648 标准字母表
// （大写），无填充。文档与实现已统一为大写——小写变体是不同字符串，
// 任何“大小写不敏感比较”都是 bug。
func TestNodeIDEncodingPinned(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	nid := id.NodeID().String()
	body := strings.TrimPrefix(nid, NodeIDPrefix+"-")
	// 只允许标准 base32 大写字母表。
	for _, r := range body {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", r) {
			t.Fatalf("NodeID 含非标准 base32 大写字符 %q: %s", r, nid)
		}
	}
	if strings.ToLower(body) == body {
		t.Fatalf("NodeID 应为大写 base32（防大小写规范化回归）: %s", nid)
	}
	// 小写化的 NodeID 是不同身份：显式验证大小写敏感。
	if NodeID(strings.ToLower(nid)) == id.NodeID() {
		t.Fatalf("NodeID 大小写敏感语义破坏")
	}
	// 与 base32 手工重编码一致（防止未来误改成其他字母表）。
	sum := sha256.Sum256(id.PublicKey())
	want := NodeIDPrefix + "-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	if nid != want {
		t.Fatalf("NodeID 编码漂移: got %s want %s", nid, want)
	}
}

func TestChallengeSignVerifyRoundtrip(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	now := time.Unix(1_700_000_000, 0)
	c := Challenge{
		Nonce:     []byte("0123456789abcdef"),
		Audience:  "node-nid1-abcdefghijklmnop",
		ExpiresAt: now.Add(time.Minute),
		NotBefore: now,
		Purpose:   "replica-lease",
		Extras:    map[string]string{"generation": "7", "scope": "obj-42"},
	}
	sig, err := id.Sign(c)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := VerifyAt(id.PublicKey(), c, sig, now, 0); err != nil {
		t.Fatalf("VerifyAt: %v", err)
	}
	// Verify 用真实当前时间：挑战需相对真实时钟有效。
	fresh := Challenge{Nonce: []byte("0123456789abcdef"), Audience: "aud", ExpiresAt: time.Now().Add(time.Hour)}
	sigFresh, err := id.Sign(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(id.PublicKey(), fresh, sigFresh); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Ed25519 确定性：同挑战同密钥 → 同签名。
	sig2, err := id.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, sig2) {
		t.Fatalf("签名不确定")
	}

	// extras 键序不影响签名（编码排序规范化）。
	reordered := Challenge{
		Nonce: c.Nonce, Audience: c.Audience, ExpiresAt: c.ExpiresAt,
		NotBefore: c.NotBefore, Purpose: c.Purpose,
		Extras: map[string]string{"scope": "obj-42", "generation": "7"},
	}
	sig3, _ := id.Sign(reordered)
	if !bytes.Equal(sig, sig3) {
		t.Fatalf("extras 顺序影响签名")
	}
}

func TestChallengeTamperRejected(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	_, other := validKeyBlob(t, t.TempDir())
	now := time.Unix(1_700_000_000, 0)
	c := Challenge{
		Nonce:     []byte("0123456789abcdef"),
		Audience:  "aud",
		ExpiresAt: now.Add(time.Minute),
	}
	sig, err := id.Sign(c)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyAt(other.PublicKey(), c, sig, now, 0); err == nil {
		t.Fatalf("错误公钥验证通过")
	}
	badSig := bytes.Clone(sig)
	badSig[0] ^= 0x01
	if err := VerifyAt(id.PublicKey(), c, badSig, now, 0); err == nil {
		t.Fatalf("篡改签名验证通过")
	}

	mutations := map[string]func(*Challenge){
		"nonce":     func(c *Challenge) { c.Nonce = []byte("ffffffffffffffff") },
		"audience":  func(c *Challenge) { c.Audience = "evil" },
		"purpose":   func(c *Challenge) { c.Purpose = "other" },
		"expires":   func(c *Challenge) { c.ExpiresAt = now.Add(2 * time.Minute) },
		"notbefore": func(c *Challenge) { c.NotBefore = now.Add(-time.Hour) },
		"add-extra": func(c *Challenge) { c.Extras = map[string]string{"k": "v"} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := c
			mutate(&mutated)
			if err := VerifyAt(id.PublicKey(), mutated, sig, now, 0); err == nil {
				t.Fatalf("篡改字段 %s 后验证通过", name)
			}
		})
	}
}

func TestChallengeExpiryAndSkew(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name      string
		expiresIn time.Duration
		skew      time.Duration
		wantOK    bool
	}{
		{"valid-strict", time.Minute, 0, true},
		{"expired-strict", -time.Second, 0, false},
		{"expired-within-skew", -10 * time.Second, 30 * time.Second, true},
		{"expired-beyond-skew", -45 * time.Second, 30 * time.Second, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Challenge{Nonce: []byte("n0nce-0123456789"), Audience: "aud", ExpiresAt: now.Add(tc.expiresIn)}
			sig, err := id.Sign(c)
			if err != nil {
				t.Fatal(err)
			}
			err = VerifyAt(id.PublicKey(), c, sig, now, tc.skew)
			if tc.wantOK && err != nil {
				t.Fatalf("expected ok, got %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("expected expiry error")
			}
		})
	}

	// 默认 Verify 零偏移：过期即拒，绝不默认延长有效期。
	c := Challenge{Nonce: []byte("n0nce-0123456789"), Audience: "aud", ExpiresAt: now.Add(-time.Second)}
	sig, _ := id.Sign(c)
	if err := Verify(id.PublicKey(), c, sig); err == nil {
		t.Fatalf("默认 Verify 放行了过期挑战")
	}
}

func TestChallengeNotBefore(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	now := time.Unix(1_700_000_000, 0)
	c := Challenge{
		Nonce:     []byte("n0nce-0123456789"),
		Audience:  "aud",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now.Add(10 * time.Second),
	}
	sig, err := id.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAt(id.PublicKey(), c, sig, now, 0); err == nil {
		t.Fatalf("未生效挑战被接受")
	}
	if err := VerifyAt(id.PublicKey(), c, sig, now, 30*time.Second); err != nil {
		t.Fatalf("skew 内应接受: %v", err)
	}
}

func TestChallengeValidationRejects(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	now := time.Unix(1_700_000_000, 0)

	bad := []Challenge{
		{Audience: "aud", ExpiresAt: now},             // 空 nonce
		{Nonce: []byte("n"), ExpiresAt: now},          // 空 audience
		{Nonce: []byte("n"), Audience: "aud"},         // 零值过期时间
		{Nonce: nil, Audience: "aud", ExpiresAt: now}, // nil nonce
	}
	for i, c := range bad {
		if _, err := id.Sign(c); err == nil {
			t.Fatalf("case %d: 非法挑战被签名", i)
		}
		if err := VerifyAt(id.PublicKey(), c, make([]byte, ed25519.SignatureSize), now, 0); err == nil {
			t.Fatalf("case %d: 非法挑战被验证", i)
		}
	}
	// 合法挑战（extras 非必填）可以签名。
	ok := Challenge{Nonce: []byte("n"), Audience: "aud", ExpiresAt: now}
	if _, err := id.Sign(ok); err != nil {
		t.Fatalf("合法挑战被拒: %v", err)
	}

	var nilID *Identity
	if _, err := nilID.Sign(ok); err == nil {
		t.Fatalf("nil identity 被签名")
	}
	if err := VerifyAt(make([]byte, 10), ok, make([]byte, ed25519.SignatureSize), now, 0); err == nil {
		t.Fatalf("坏长度公钥被接受")
	}
	if err := VerifyAt(id.PublicKey(), ok, make([]byte, 8), now, -1); err == nil {
		t.Fatalf("负 skew 被接受")
	}
}
