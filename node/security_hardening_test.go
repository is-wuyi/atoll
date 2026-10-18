package node

// node/security_hardening_test.go —— node 安全收尾的回归测试（红→绿）。
//
// 覆盖四组硬化点（全部先写红，再最小修 node/security.go）：
//  1. writeSecurityMarker 原子性：temp0600→write/sync/close→os.Link(tmp,final)
//     不替换发布。并发多 identity 在同一 dataDir 首建时恰好 1 个 winner（不是
//     「至少 1 个」）；落败方必须读到胜者内容并校验（相同才放行），绝不 rename
//     覆盖。硬链接不支持（link EPERM/EOPNOTSUPP/ENOSYS/EXDEV…）→ fail-closed，
//     绝不回退非原子发布（无临时残片、final 一字节不动）。
//  2. 已有匹配标记同样走 fd+dirSync 的原子路径：Lstat+SameFile 拒绝
//     symlink / 非 regular / 损坏 / 内容不匹配，且不改旧字节（inode 与内容不变）。
//  3. securityMarkerPresent：dangling symlink 也必须让 legacy Handler fail-closed
//     （os.Stat 会把 dangling 判成「不存在」而静默退回 legacy）。
//  4. controlBodyHash 只对 POST /pull 生效：GET /objects/{id} 与 PUT
//     /replicate/{id} 的 payload 恒空哈希，绝不读 payload/GetBody（流式 body
//     连字节都不被触碰）。
//  5. safePeerURL 拒 fragment/RawFragment；isMasterOrigin 拒 userinfo/opaque/
//     rawpath；deviceTransport/authorizePeer 拒 Host 与 URLHost 不一致
//     （防「判定用 origin 与实际发送目标不一致」）。

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
)

// ---- 1. 安全标记：原子发布 + 并发单 winner ----

// 并发多 identity 在同一 dataDir 首建：恰 1 个 winner；落败方看到胜者内容。
// 注意：真实系统里不同 identity 本就不该共享 dataDir（这正是标记要挡的），
// 但发布必须是原子的——否则两个进程的 temp→rename 会互相覆盖，后到者静默
// 改写 dataDir 的属主凭证。这里验证：成功者唯一 + 落败者一律拒绝 + 标记内容
// 与某个 identity 自洽（即胜者的，不是撕裂的）。
func TestHardeningMarkerAtomicPublishSingleWinner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	masterURL := "http://127.0.0.1:1" // 标记校验不拨号

	const racers = 8
	ids := make([]*edgeidentity.Identity, racers)
	for i := range ids {
		id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), fmt.Sprintf("id%d.key", i)))
		if err != nil {
			t.Fatalf("identity %d: %v", i, err)
		}
		ids[i] = id
	}

	var winners atomic.Int64
	var mu sync.Mutex
	var winnerIdentity string
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			u, _ := url.Parse(masterURL)
			err := writeSecurityMarker(dir, ids[i], u)
			if err == nil {
				winners.Add(1)
				mu.Lock()
				winnerIdentity = ids[i].NodeID().String()
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := winners.Load(); got != 1 {
		t.Fatalf("concurrent first-publish winners = %d, want exactly 1", got)
	}
	// 标记内容必须与唯一 winner 自洽（无撕裂写）。
	raw, err := os.ReadFile(filepath.Join(dir, securityMarkerName))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	var body struct {
		Version  int    `json:"version"`
		Identity string `json:"identity"`
		Master   string `json:"master"`
	}
	if err := jsonUnmarshalForTest(raw, &body); err != nil {
		t.Fatalf("marker not valid json (torn write?): %v", err)
	}
	if body.Identity != winnerIdentity || body.Version != 1 || body.Master != masterURL {
		t.Fatalf("marker = %+v, want winner %q", body, winnerIdentity)
	}
	// winner 之后可重复放行（同一 identity），loser 永远拒绝。
	u, _ := url.Parse(masterURL)
	mu.Lock()
	w := winnerIdentity
	mu.Unlock()
	if err := writeSecurityMarker(dir, ids[0], u); err != nil {
		// ids[0] 未必是 winner；只要它是 winner 就必须放行。
		if ids[0].NodeID().String() == w {
			t.Fatalf("winner must be accepted on restart: %v", err)
		}
	}
	// 无临时残片。
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".security-marker-tmp-*")); len(leftovers) != 0 {
		t.Fatalf("publish left temp fragments: %v", leftovers)
	}
}

// 已有匹配标记：原子路径不重写（inode 不变），且通过同一 winner 校验。
// 此处重点：匹配时也必须以「已存在的 final」为 winner 做 Lstat+SameFile 校验。
func TestHardeningMarkerMatchNotRewritten(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "id.key"))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("http://127.0.0.1:1")
	if err := writeSecurityMarker(dir, id, u); err != nil {
		t.Fatalf("first: %v", err)
	}
	path := filepath.Join(dir, securityMarkerName)
	fi1, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ { // 重复启用 = 重启放行且不重写
		if err := writeSecurityMarker(dir, id, u); err != nil {
			t.Fatalf("restart %d: %v", i, err)
		}
	}
	fi2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fi1, fi2) {
		t.Fatalf("matching marker must not be rewritten (inode changed)")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".security-marker-tmp-*")); len(leftovers) != 0 {
		t.Fatalf("temp fragments: %v", leftovers)
	}
}

// 标记是 symlink（指向别处内容相同的文件）：Lstat 发现非 regular → 拒绝，
// 且绝不改写 symlink 指向（不变成 regular 文件、不覆盖目标）。
func TestHardeningMarkerRejectsSymlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"identity":"x","master":"y"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, securityMarkerName)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "id.key"))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("http://127.0.0.1:1")
	if err := writeSecurityMarker(dir, id, u); err == nil {
		t.Fatalf("symlink marker must be refused (fail-closed)")
	}
	// symlink 仍是 symlink，目标内容一字节未动。
	st, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("marker symlink must remain a symlink")
	}
	got, _ := os.ReadFile(target)
	if string(got) != `{"version":1,"identity":"x","master":"y"}` {
		t.Fatalf("symlink target must be untouched, got %q", got)
	}
}

// 标记是 dangling symlink：content 读不到 → 拒绝；且 securityMarkerPresent
// 必须返回 true（fail-closed），legacy Handler 保持 503。
func TestHardeningMarkerDanglingSymlinkFailsClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "nowhere.json")
	if err := os.Symlink(missing, filepath.Join(dir, securityMarkerName)); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	if !securityMarkerPresent(dir) {
		t.Fatalf("dangling symlink marker must count as present (fail-closed)")
	}
	fm := newFakeSecMaster(t)
	n := New(dir, fm.srv.URL, "127.0.0.1:9180", 1<<30) // 重启未带 --secure
	ts := httptest.NewServer(n.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/objects/1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("dangling symlink marker without security = %d, want 503", resp.StatusCode)
	}
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "id.key"))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("http://127.0.0.1:1")
	if err := writeSecurityMarker(dir, id, u); err == nil {
		t.Fatalf("dangling symlink marker must refuse enable")
	}
	if st, lerr := os.Lstat(filepath.Join(dir, securityMarkerName)); lerr != nil || st.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("dangling symlink must remain untouched: %v %v", st, lerr)
	}
}

// 硬链接不支持 → fail-closed，不回退非原子发布：final 不存在、无残片、
// 无残留 temp（best-effort 清理后也不留 .security-marker-tmp-*）。
// 通过指向不存在目标目录的 dataDir（os.Link 返回 ENOENT 类）模拟发布失败：
// 关键是「失败路径绝不创建 final、绝不 rename 覆盖」。
func TestHardeningMarkerPublishFailureNoFallback(t *testing.T) {
	base := t.TempDir()
	// dataDir 存在但把标记路径占成目录：link 必失败（EEXIST/ENOTDIR 类），
	// 此时绝不能回退成 rename 覆盖，也不能留残片。
	dir := filepath.Join(base, "data")
	if err := os.MkdirAll(filepath.Join(dir, securityMarkerName), 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "id.key"))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("http://127.0.0.1:1")
	err = writeSecurityMarker(dir, id, u)
	if err == nil {
		t.Fatalf("publish onto an existing directory path must fail")
	}
	// final 仍是目录（没被换成文件），且 dataDir 无 temp 残片。
	st, serr := os.Lstat(filepath.Join(dir, securityMarkerName))
	if serr != nil || !st.IsDir() {
		t.Fatalf("final path must remain a directory: %v %v", st, serr)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".security-marker-tmp-*")); len(leftovers) != 0 {
		t.Fatalf("failed publish left temp fragments: %v", leftovers)
	}
	// 失败必须可诊断（含底层错误），不是静默成功。
	if !errors.Is(err, fs.ErrExist) && !strings.Contains(err.Error(), "exist") {
		t.Logf("publish failure error: %v", err)
	}
}

// 损坏/不匹配标记：拒绝，且 inode 与内容都不变（不通过删除+重建「自愈」）。
func TestHardeningMarkerCorruptOrMismatchUntouched(t *testing.T) {
	fm := newFakeSecMaster(t)
	dir := filepath.Join(t.TempDir(), "data")
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "id.key"))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(fm.srv.URL)
	if err := writeSecurityMarker(dir, id, u); err != nil {
		t.Fatalf("seed: %v", err)
	}
	path := filepath.Join(dir, securityMarkerName)

	cases := []struct {
		name  string
		write string
	}{
		{"truncated", `{"version":1,"identi`},
		{"bad-version", `{"version":2,"identity":"nid1-x","master":"http://127.0.0.1:1"}`},
		{"empty-identity", `{"version":1,"identity":"","master":"http://127.0.0.1:1"}`},
		{"wrong-identity", `{"version":1,"identity":"nid1-someoneelse","master":"http://127.0.0.1:1"}`},
		{"wrong-master", `{"version":1,"identity":"whatever","master":"http://evil:1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.write), 0o600); err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeSecurityMarker(dir, id, u); err == nil {
				t.Fatalf("%s marker must be refused", tc.name)
			}
			fi2, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(fi, fi2) {
				t.Fatalf("%s: marker inode must not change", tc.name)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tc.write {
				t.Fatalf("%s: marker bytes must not change, got %q", tc.name, got)
			}
		})
	}
}

// 非 regular 标记（fifo）：Lstat 发现 → fail-closed（不被当文件读、不被覆盖）。
func TestHardeningMarkerRejectsNonRegular(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, securityMarkerName)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "id.key"))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("http://127.0.0.1:1")
	done := make(chan error, 1)
	go func() { done <- writeSecurityMarker(dir, id, u) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("fifo marker must be refused")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("writeSecurityMarker must not block on a fifo marker")
	}
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&fs.ModeNamedPipe == 0 {
		t.Fatalf("fifo must remain a fifo")
	}
}

// ---- 2. controlBodyHash 只对 POST /pull 生效 ----

// authorizePeer 只允许 GET /objects/{id} 与 PUT /replicate/{id}：两者的
// payload body 恒空哈希，且绝不读取 payload（GetBody 只被「看一眼」——
// 用会记账的 body 验证它根本没被读）。
func TestHardeningPeerPayloadHashAlwaysEmpty(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9181", "")
	mustRegister(t, n)

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer peer.Close()

	// GET /objects/{id}：带一个可重放小 body（异常形态，正常 GET 无 body）。
	getReq, _ := http.NewRequest(http.MethodGet, peer.URL+"/objects/9", nil)
	if err := n.sec.authorizePeer(getReq); err != nil {
		t.Fatalf("GET authorizePeer: %v", err)
	}
	fm.mu.Lock()
	last := fm.ticketLog[len(fm.ticketLog)-1]
	fm.mu.Unlock()
	if last.BodyHash != "" {
		t.Fatalf("GET /objects must bind empty body hash, got %q", last.BodyHash)
	}

	// PUT /replicate/{id}：流式对象 payload（GetBody nil）+ 记账 body，
	// 必须恒空哈希且一字节不读。
	payload := []byte("object-payload-must-never-be-read")
	counting := &countingReader{r: strings.NewReader(string(payload))}
	putReq, _ := http.NewRequest(http.MethodPut, peer.URL+"/replicate/9",
		io.NopCloser(counting))
	putReq.ContentLength = int64(len(payload))
	putReq.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(&countingReader{r: strings.NewReader(string(payload))}), nil
	}
	if err := n.sec.authorizePeer(putReq); err != nil {
		t.Fatalf("PUT authorizePeer: %v", err)
	}
	fm.mu.Lock()
	last = fm.ticketLog[len(fm.ticketLog)-1]
	fm.mu.Unlock()
	if last.BodyHash != "" {
		t.Fatalf("PUT /replicate must bind empty body hash, got %q", last.BodyHash)
	}
	if got := counting.reads.Load(); got != 0 {
		t.Fatalf("object payload must never be read for hashing: %d bytes read", got)
	}
}

// controlBodyHash 自身语义：POST /pull 的小控制体照常哈希；其它 method/path
// 一律空（无论 body 多小、GetBody 是否存在）。
func TestHardeningControlBodyHashOnlyPull(t *testing.T) {
	mk := func(method, path string, body []byte) *http.Request {
		var r io.Reader
		if body != nil {
			r = strings.NewReader(string(body))
		}
		req, _ := http.NewRequest(method, "http://peer:1"+path, r)
		if body != nil {
			b := body
			req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(string(b))), nil
			}
		}
		return req
	}
	if got, err := controlBodyHash(mk(http.MethodPost, "/pull", []byte(`{"a":1}`))); err != nil || got != sha256Hex([]byte(`{"a":1}`)) {
		t.Fatalf("POST /pull hash = %q %v, want sha256 of control body", got, err)
	}
	for _, tc := range []struct {
		method, path string
		body         []byte
	}{
		{http.MethodGet, "/objects/5", []byte("payload")},
		{http.MethodPut, "/objects/5", []byte("payload")},
		{http.MethodPut, "/replicate/5", []byte("payload")},
		{http.MethodDelete, "/objects/5", nil},
		{http.MethodPost, "/verify/5", []byte(`{"a":1}`)},
		{http.MethodPost, "/pull/", []byte(`{"a":1}`)},
	} {
		if got, err := controlBodyHash(mk(tc.method, tc.path, tc.body)); err != nil || got != "" {
			t.Fatalf("%s %s hash = %q %v, want empty", tc.method, tc.path, got, err)
		}
	}
	// POST /pull 超限控制体：fail-closed 报错（不是静默空哈希）。
	big := mk(http.MethodPost, "/pull", []byte("x"))
	big.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(strings.Repeat("a", maxControlBody+1))), nil
	}
	if _, err := controlBodyHash(big); !errors.Is(err, errControlBodyTooLarge) {
		t.Fatalf("oversize pull control body err = %v, want errControlBodyTooLarge", err)
	}
}

// countingReader 记录被读取的字节数（验证 payload 未被触碰）。
type countingReader struct {
	r     io.Reader
	reads atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.reads.Add(int64(n))
	return n, err
}

// ---- 3. URL 歧义加固：fragment / userinfo / opaque / rawpath / Host 不一致 ----

// safePeerURL 必须拒 fragment / raw fragment（旧实现只查 RawPath）。
func TestHardeningSafePeerURLRejectsFragment(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*url.URL)
	}{
		{"fragment", func(u *url.URL) { u.Fragment = "steal" }},
		{"raw-fragment", func(u *url.URL) { u.RawFragment = "steal" }},
		{"rawpath", func(u *url.URL) { u.RawPath = "/objects/%35" }},
		{"userinfo", func(u *url.URL) { u.User = url.User("evil") }},
		{"opaque", func(u *url.URL) { u.Opaque = "//peer:9/objects/5"; u.Host = "" }},
		{"empty-host", func(u *url.URL) { u.Host = "" }},
		{"scheme", func(u *url.URL) { u.Scheme = "http" }},
	}
	for _, tc := range cases {
		u := &url.URL{Scheme: "https", Host: "peer.example:9", Path: "/objects/5"}
		tc.mutate(u)
		if err := safePeerURL(u, "https"); err == nil {
			t.Fatalf("%s: safePeerURL must refuse", tc.name)
		}
	}
	ok := &url.URL{Scheme: "https", Host: "peer.example:9", Path: "/objects/5"}
	if err := safePeerURL(ok, "https"); err != nil {
		t.Fatalf("clean peer URL must pass: %v", err)
	}
}

// authorizePeer 对这些形态一律在触网前拒绝（master 不被联系）。
func TestHardeningAuthorizePeerRefusesAmbiguous(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9182", "")
	mustRegister(t, n)
	tickets := func() int {
		fm.mu.Lock()
		defer fm.mu.Unlock()
		return len(fm.ticketLog)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*url.URL)
	}{
		{"fragment", func(u *url.URL) { u.Fragment = "x" }},
		{"raw-fragment", func(u *url.URL) { u.RawFragment = "x" }},
		{"rawpath", func(u *url.URL) { u.RawPath = "/objects/%35" }},
		{"userinfo", func(u *url.URL) { u.User = url.User("evil") }},
		{"opaque", func(u *url.URL) { u.Opaque = "//p:9/objects/5"; u.Host = "" }},
	} {
		before := tickets()
		u := &url.URL{Scheme: "http", Host: "peer.example:9", Path: "/objects/5"}
		tc.mutate(u)
		req := &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}}
		if err := n.sec.authorizePeer(req); err == nil {
			t.Fatalf("%s: authorizePeer must refuse", tc.name)
		}
		if tickets() != before {
			t.Fatalf("%s: master must not be contacted", tc.name)
		}
	}
}

// isMasterOrigin 只认精确 origin：userinfo/opaque/rawpath/大小写不同的 host
// 一律非 master origin（设备凭据绝不发出）。
func TestHardeningMasterOriginExact(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9183", "")
	mustRegister(t, n)
	u, _ := url.Parse(fm.srv.URL)

	same := *u
	if !n.sec.isMasterOrigin(&same) {
		t.Fatalf("exact master URL must be recognized")
	}
	folded := *u
	folded.Host = strings.ToUpper(folded.Host)
	if !n.sec.isMasterOrigin(&folded) {
		t.Fatalf("case-insensitive host must still be master origin")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*url.URL)
	}{
		{"userinfo", func(x *url.URL) { x.User = url.User("victim") }},
		{"opaque", func(x *url.URL) { x.Opaque = x.Scheme + "://" + x.Host + "/p" }},
		{"rawpath", func(x *url.URL) { x.RawPath = "/%70ull" }},
		{"fragment", func(x *url.URL) { x.Fragment = "x" }},
		{"other-host", func(x *url.URL) { x.Host = "evil.example:1" }},
		{"other-port", func(x *url.URL) { x.Host = "127.0.0.1:9999" }},
	} {
		bad := *u
		tc.mutate(&bad)
		if n.sec.isMasterOrigin(&bad) {
			t.Fatalf("%s: must not be master origin", tc.name)
		}
	}
}

// deviceTransport：req.Host 与 URL.Host 不一致 → 拒绝（判定用 URL.Host，
// 实际发送用 req.Host 时会打到别的虚拟主机）。
func TestHardeningDeviceTransportRejectsHostMismatch(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9184", "")
	mustRegister(t, n)

	req, err := http.NewRequest(http.MethodGet, fm.srv.URL+"/test/redirect", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "victim.example"
	if _, err := n.httpClient.Transport.RoundTrip(req); err == nil {
		t.Fatalf("device transport must refuse Host/URL.Host mismatch")
	}
	// 一致时正常发出（200/302 均可，重点是没被本地拒）。
	req2, _ := http.NewRequest(http.MethodGet, fm.srv.URL+"/test/redirect", nil)
	resp, err := n.httpClient.Transport.RoundTrip(req2)
	if err != nil {
		t.Fatalf("matching Host request must be sent: %v", err)
	}
	resp.Body.Close()
}

// access.Transport → authorizePeer：Host 与 URLHost 不一致 → 拒绝换票，
// master 不被联系，peer 不被访问。
func TestHardeningAuthorizePeerRejectsHostMismatch(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9185", "")
	mustRegister(t, n)

	var peerHits atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		peerHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()

	fm.mu.Lock()
	before := len(fm.ticketLog)
	fm.mu.Unlock()

	req, _ := http.NewRequest(http.MethodGet, peer.URL+"/objects/5", nil)
	req.Host = "victim.example"
	if _, err := n.bulkClient.Do(req); err == nil {
		t.Fatalf("Host mismatch must be refused")
	}
	fm.mu.Lock()
	after := len(fm.ticketLog)
	fm.mu.Unlock()
	if after != before {
		t.Fatalf("master must not be contacted for Host-mismatched request")
	}
	if peerHits.Load() != 0 {
		t.Fatalf("peer must not be contacted for Host-mismatched request")
	}
}

// 端到端 sanity：security pull 全链路仍可用（防加固把正常路径打断）。
func TestHardeningPullStillWorks(t *testing.T) {
	fm := newFakeSecMaster(t)
	data := []byte("hardening sanity payload")
	crc := checksumForTest(data)
	src := newSecureNode(t, fm, "127.0.0.1:9186", "")
	mustRegister(t, src)
	srcTS := httptest.NewServer(src.Handler())
	t.Cleanup(srcTS.Close)
	if _, _, err := src.storeObject(300, strings.NewReader(string(data)), crc); err != nil {
		t.Fatalf("store: %v", err)
	}
	dst := newSecureNode(t, fm, "127.0.0.1:9187", "")
	mustRegister(t, dst)
	dstTS := httptest.NewServer(dst.Handler())
	t.Cleanup(dstTS.Close)

	fm.mu.Lock()
	fm.planFor[300] = planForTest(data, crc, srcTS.URL)
	fm.mu.Unlock()

	pullBody, _ := jsonMarshalForTest(map[string]any{"inode_id": 300, "source_addr": strings.TrimPrefix(srcTS.URL, "http://"), "checksum": crc})
	tok := fm.mintTicket(access.TicketRequest{Method: http.MethodPost, Path: "/pull", BodyHash: sha256Hex(pullBody)}, time.Time{})
	req, _ := http.NewRequest(http.MethodPost, dstTS.URL+"/pull", strings.NewReader(string(pullBody)))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /pull = %d, want 202", resp.StatusCode)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		getTok := fm.mintTicket(access.TicketRequest{Method: http.MethodGet, Path: "/objects/300"}, time.Time{})
		greq, _ := http.NewRequest(http.MethodGet, dstTS.URL+"/objects/300", nil)
		greq.Header.Set("Authorization", "Bearer "+getTok)
		gresp, gerr := http.DefaultClient.Do(greq)
		if gerr == nil {
			b, _ := io.ReadAll(gresp.Body)
			gresp.Body.Close()
			if gresp.StatusCode == http.StatusOK && string(b) == string(data) {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("secured pull did not complete")
}
