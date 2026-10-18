package main

// cmd/atoll 安全模式真实进程验收（独立审计，不修改生产代码）。
//
// 与 master/client/node 包内的 httptest 级安全测试互补：本文件构建真实 atoll
// 二进制，以子进程方式拉起 TLS master + 2 个受邀 node，并全部走真实 CLI 命令
// （auth init / login / logout / spaces / team-create / team-member /
// mkdir / put / get / ls），覆盖：
//
//	空文件、≤SmallFileMax 小文件、>SmallFileMax 分块文件的真实读写；
//	团队空间成员 read/write/撤销 的真实授权语义；
//	登出后会话即时失效；
//	明文 HTTP 被拒（TLS 层 400）、CLI 无 CA / -tls-skip-verify 负向；
//	secure 角色拒绝不安全启动（master 无证书/skip-verify、node skip-verify）；
//	安全库重启不带 -secure fail-closed；重启带 -secure 后旧会话仍有效（本地 DB persistence）；
//	节点安全标记 fail-closed（dataDir 带标记重启忘带 --secure 必须失败）；
//	设备吊销幂等（重复吊销不得误报失败）。
//
// 约束：子进程一律 SIGTERM + Wait（超时升级 SIGKILL）；运行态文件全部在
// t.TempDir；环境最小化并强制 NO_PROXY/no_proxy='*'；审计日志落
// $ATOLL_AUDIT_EVIDENCE_DIR/actual-cli（默认 t.TempDir 下随机子目录），
// 其中口令/会话/邀请码/控制令牌经注册表统一打码。仅本机端口，不用 FUSE/root。

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"atoll/pkg/types"
)

// ---- 证据目录与打码 ----

var (
	csecLogMu   sync.Mutex
	csecSecrets [][]byte // 注册过的机密：写证据文件前全部替换为 [REDACTED]
	csecLogFile *os.File
	csecProgF   *os.File
)

func csecEvidenceDir(t *testing.T) string {
	t.Helper()
	if base := os.Getenv("ATOLL_AUDIT_EVIDENCE_DIR"); base != "" {
		if err := os.MkdirAll(base, 0o700); err != nil {
			t.Fatal(err)
		}
		dir, err := os.MkdirTemp(base, "cli-")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("CLI evidence: %s", dir)
		return dir
	}
	return t.TempDir()
}

func csecInit(t *testing.T) {
	t.Helper()
	dir := csecEvidenceDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("evidence dir: %v", err)
	}
	var err error
	// 每轮运行截断重写，避免跨轮 O_APPEND 混入陈旧行。
	if csecLogFile, err = os.OpenFile(filepath.Join(dir, "cmd_security_audit.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err != nil {
		t.Fatalf("evidence log: %v", err)
	}
	if csecProgF, err = os.OpenFile(filepath.Join(dir, "cmd_security_progress.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err != nil {
		t.Fatalf("progress log: %v", err)
	}
	t.Cleanup(func() { csecLogFile.Close(); csecProgF.Close() })
}

// csecRegisterSecret 登记机密（口令/会话/令牌/邀请码），此后任何写入证据文件的
// 字节流中的出现都被打码。机密不进 t.Fatalf 消息与证据文件。
func csecRegisterSecret(v string) {
	csecLogMu.Lock()
	defer csecLogMu.Unlock()
	if v != "" {
		csecSecrets = append(csecSecrets, []byte(v))
	}
}

// csecScrubLocked 要求调用方已持有 csecLogMu（scrub 与日志写同锁，避免重入死锁）。
func csecScrubLocked(b []byte) []byte {
	for _, s := range csecSecrets {
		b = bytes.ReplaceAll(b, s, []byte("[REDACTED]"))
	}
	return b
}

func csecLogf(format string, args ...any) {
	csecLogMu.Lock()
	defer csecLogMu.Unlock()
	if csecLogFile == nil {
		return
	}
	line := csecScrubLocked([]byte(fmt.Sprintf(format, args...)))
	csecLogFile.Write(line)
	csecLogFile.Write([]byte("\n"))
}

// csecStage 关键进度主动同步到证据目录（主线程可 tail 跟踪）。
func csecStage(format string, args ...any) {
	csecLogMu.Lock()
	defer csecLogMu.Unlock()
	line := fmt.Sprintf(format, args...)
	if csecProgF != nil {
		csecProgF.WriteString(time.Now().Format("15:04:05.000") + " ")
		csecProgF.Write(csecScrubLocked([]byte(line)))
		csecProgF.Write([]byte("\n"))
	}
}

// ---- 二进制构建（一次构建，全部子进程复用） ----

var (
	csecBinOnce sync.Once
	csecBinDir  string
	csecBinPath string
	csecBinErr  error
)

func csecBuild(t *testing.T) string {
	t.Helper()
	csecBinOnce.Do(func() {
		csecBinDir, csecBinErr = os.MkdirTemp("", "atoll-csec-bin-*")
		if csecBinErr != nil {
			return
		}
		csecBinPath = filepath.Join(csecBinDir, "atoll")
		buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		build := exec.CommandContext(buildCtx, "go", "build", "-o", csecBinPath, ".")
		build.WaitDelay = 2 * time.Second
		build.Dir = "."
		var out bytes.Buffer
		build.Stderr = &out
		if csecBinErr = build.Run(); csecBinErr != nil {
			csecBinErr = fmt.Errorf("go build: %v: %s", csecBinErr, out.String())
		}
	})
	if csecBinErr != nil {
		t.Fatalf("构建 atoll binary: %v", csecBinErr)
	}
	return csecBinPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if csecBinDir != "" {
		os.RemoveAll(csecBinDir)
	}
	os.Exit(code)
}

// ---- 进程助手：SIGTERM + Wait，超时升级 SIGKILL ----

type csecProc struct {
	name       string
	cmd        *exec.Cmd
	done       chan struct{}
	mu         sync.Mutex
	terminated bool
	stop       func()
}

func csecStart(t *testing.T, name string, env []string, args ...string) *csecProc {
	t.Helper()
	bin := csecBuild(t)
	cmd := exec.Command(bin, args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = env
	stdout := csecStreamWriter(name + "|stdout")
	stderr := csecStreamWriter(name + "|stderr")
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动 %s: %v", name, err)
	}
	p := &csecProc{name: name, cmd: cmd, done: make(chan struct{})}
	term := func() {
		p.mu.Lock()
		if p.terminated {
			p.mu.Unlock()
			return
		}
		p.terminated = true
		p.mu.Unlock()
		begin := time.Now()
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(10 * time.Second):
			csecLogf("[proc] %s TERM 超时（%.1fs），升级 SIGKILL", name, time.Since(begin).Seconds())
			_ = p.cmd.Process.Kill()
			<-p.done
		}
		csecLogf("[proc] %s exited after %.1fs of TERM", name, time.Since(begin).Seconds())
	}
	p.stop = term
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(term)
	csecLogf("[proc] start %s pid=%d argv=%s", name, cmd.Process.Pid, strings.Join(args, " "))
	return p
}

// alive 非阻塞检查进程是否仍在运行；不消费 done channel。
func (p *csecProc) alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// csecStop 显式 TERM+Wait（重启场景需要先落定再拉新进程；cleanup 重复调用安全）。
func (p *csecProc) csecStop() {
	p.stop()
	csecLogf("[proc] stopped %s", p.name)
}

// csecStreamWriter 把子进程输出打码后写进证据文件。
func csecStreamWriter(tag string) io.Writer {
	return &csecTaggedWriter{tag: tag}
}

type csecTaggedWriter struct{ tag string }

func (w *csecTaggedWriter) Write(p []byte) (int, error) {
	csecLogf("%s: %s", w.tag, p)
	return len(p), nil
}

// ---- 短命 CLI 调用 ----

type csecResult struct {
	code   int
	stdout string
	stderr string
}

func csecExitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

// csecCLI 运行一次真实 CLI。logNow=false 用于输出含会话令牌的命令：调用方先
// 注册机密再 csecLogResult，保证令牌不落证据文件。
// 负向测试中 CLI 可能意外启动 server 挂死：30s context 超时 + WaitDelay 确保不漏 child。
func csecCLI(t *testing.T, env []string, logNow bool, args ...string) csecResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, csecBuild(t), args...)
	cmd.Env = env
	cmd.WaitDelay = 2 * time.Second // context 取消后等待子进程退出，超时则 Kill
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := csecResult{code: csecExitCode(err), stdout: out.String(), stderr: errb.String()}
	if err != nil && res.code == -1 {
		t.Fatalf("运行 atoll %v: %v", args, err)
	}
	if logNow {
		csecLogResult(args, res)
	}
	return res
}

func csecLogResult(args []string, res csecResult) {
	csecLogf("$ atoll %s\n  exit=%d\n  stdout: %s\n  stderr: %s",
		strings.Join(args, " "), res.code, res.stdout, res.stderr)
}

func csecMustCLI(t *testing.T, env []string, args ...string) string {
	t.Helper()
	res := csecCLI(t, env, true, args...)
	if res.code != 0 {
		t.Fatalf("atoll %s 应成功，exit=%d stderr=%s", strings.Join(args, " "), res.code, res.stderr)
	}
	return res.stdout
}

func csecFailCLI(t *testing.T, env []string, args ...string) csecResult {
	t.Helper()
	res := csecCLI(t, env, true, args...)
	if res.code == 0 {
		t.Fatalf("atoll %s 应失败，但 exit=0 stdout=%s", strings.Join(args, " "), csecScrubStr(res.stdout))
	}
	return res
}

// csecScrubStr 对字符串进行脱敏，用于 t.Fatalf 等不会自动 scrub 的场景。
func csecScrubStr(s string) string {
	csecLogMu.Lock()
	defer csecLogMu.Unlock()
	return string(csecScrubLocked([]byte(s)))
}

// ---- 环境与端口 ----

func csecEnv(extra ...string) []string {
	base := []string{"NO_PROXY=*", "no_proxy=*", "PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin/go/bin"}
	return append(base, extra...)
}

func csecFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func csecRandom(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	const hex = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, b := range buf {
		out[i*2], out[i*2+1] = hex[b>>4], hex[b&15]
	}
	return string(out)
}

// ---- TLS：测试自签 CA + localhost/127.0.0.1 SAN 叶子证书 ----

func csecGenTLS(t *testing.T, dir string) (caPath string, leafCert, leafKey func(name string) (string, string)) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("tls dir: %v", err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "atoll-csec-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath = filepath.Join(dir, "ca.pem")
	csecWritePEM(t, caPath, "CERTIFICATE", caDER)
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	csecWritePEM(t, filepath.Join(dir, "ca-key.pem"), "EC PRIVATE KEY", caKeyDER)

	leafCert = func(name string) (string, string) {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: "atoll-csec-" + name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(leafKey)
		if err != nil {
			t.Fatal(err)
		}
		certPath := filepath.Join(dir, name+".pem")
		keyPath := filepath.Join(dir, name+".key")
		csecWritePEM(t, certPath, "CERTIFICATE", der)
		csecWritePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
		return certPath, keyPath
	}
	return caPath, leafCert, leafKey
}

func csecWritePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// ---- HTTPS 管理面调用（HTTP 管理 API：公开端点 + 会话端点） ----

type csecHTTP struct {
	client *http.Client
}

func csecNewHTTP(t *testing.T, caPath string) *csecHTTP {
	t.Helper()
	pool := x509.NewCertPool()
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("CA pem 无法解析")
	}
	return &csecHTTP{client: &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			Proxy:           nil, // 直连本机，绝不经代理
		},
	}}
}

func (h *csecHTTP) do(t *testing.T, method, url, bearer string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}

func csecPoll(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("等待 %s 超时（%v）", what, timeout)
}

// ---- 主验收 ----

func TestCLISecurityAcceptance(t *testing.T) {
	csecInit(t)
	csecStage("TestCLISecurityAcceptance start")
	root := t.TempDir()
	caPath, leafCert, _ := csecGenTLS(t, filepath.Join(root, "tls"))

	// 每次运行随机口令/令牌（可重跑），注册进打码表，绝不进日志。
	adminPw := "Adm-" + csecRandom(t, 9)
	alicePw := "Ali-" + csecRandom(t, 9)
	bobPw := "Bob-" + csecRandom(t, 9)
	controlToken := "ctl-" + csecRandom(t, 16)
	for _, s := range []string{adminPw, alicePw, bobPw, controlToken} {
		csecRegisterSecret(s)
	}

	masterPort := csecFreePort(t)
	node1Port := csecFreePort(t)
	node2Port := csecFreePort(t)
	masterURL := fmt.Sprintf("https://127.0.0.1:%d", masterPort)
	dbPath := filepath.Join(root, "master.db")
	csecStage("tls ready, ports master=%d node1=%d node2=%d", masterPort, node1Port, node2Port)

	masterEnv := func() []string { return csecEnv("ATOLL_CONTROL_TOKEN=" + controlToken) }

	// 1) Master 停止时本地库 auth init（真实 CLI 子进程）。
	initOut := csecMustCLI(t, csecEnv("ATOLL_PASSWORD="+adminPw),
		"auth", "init", "-db", dbPath, "-user", "admin")
	var initJSON struct {
		User    map[string]any `json:"user"`
		SpaceID uint64         `json:"space_id"`
	}
	if err := json.Unmarshal([]byte(initOut), &initJSON); err != nil || initJSON.SpaceID == 0 {
		t.Fatalf("auth init 输出应含 space_id: %q err=%v", initOut, err)
	}
	csecStage("auth init ok (db bootstrapped)")

	// 2) 启动 TLS master。
	masterCert, masterKey := leafCert("master")
	master := csecStart(t, "master", masterEnv(),
		"master", "-secure",
		"-listen", fmt.Sprintf("127.0.0.1:%d", masterPort),
		"-db", dbPath,
		"-tls-cert", masterCert, "-tls-key", masterKey, "-tls-ca", caPath,
		"-node-max-age", "20s", "-repair-interval", "2s")
	httpc := csecNewHTTP(t, caPath)
	csecPoll(t, 20*time.Second, "master /healthz", func() bool {
		resp, err := httpc.client.Get(masterURL + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	csecStage("master up (TLS)")

	// 3) admin 登录（真实 CLI，输出含会话令牌：先解析注册再落证据）。
	adminLoginRes := csecCLI(t, csecEnv("ATOLL_PASSWORD="+adminPw), false,
		"login", "-master", masterURL, "-tls-ca", caPath, "-user", "admin")
	if adminLoginRes.code != 0 {
		t.Fatalf("admin login exit=%d stderr=%s", adminLoginRes.code, adminLoginRes.stderr)
	}
	var adminSess struct {
		Token string `json:"token"`
		User  struct {
			ID              uint64 `json:"id"`
			PersonalSpaceID uint64 `json:"personal_space_id"`
		} `json:"user"`
	}
	if err := json.Unmarshal([]byte(adminLoginRes.stdout), &adminSess); err != nil || adminSess.Token == "" {
		t.Fatalf("login 输出应含 token: err=%v", err)
	}
	csecRegisterSecret(adminSess.Token)
	csecLogResult([]string{"login -master ... -user admin"}, adminLoginRes)
	adminBearer := adminSess.Token

	// 4) 邀请与注册（HTTP 管理 API）：alice、bob 两名成员 + 2 个设备邀请。
	mint := func(path string) string {
		st, raw := httpc.do(t, "POST", masterURL+path, adminBearer,
			map[string]any{"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339Nano)})
		if st != 201 {
			t.Fatalf("POST %s 应 201，got %d: %s", path, st, raw)
		}
		var out struct {
			Invite string `json:"invite"`
		}
		if err := json.Unmarshal(raw, &out); err != nil || out.Invite == "" {
			t.Fatalf("%s 响应应含 invite: %s", path, raw)
		}
		csecRegisterSecret(out.Invite)
		return out.Invite
	}
	aliceInvite := mint("/auth/invites")
	bobInvite := mint("/auth/invites")
	devInvite1 := mint("/auth/devices/invites")
	devInvite2 := mint("/auth/devices/invites")

	register := func(invite, name, pw string) uint64 {
		csecRegisterSecret(invite)
		st, raw := httpc.do(t, "POST", masterURL+"/auth/register", "", map[string]any{
			"invite": invite, "username": name, "password": pw})
		if st != 201 {
			t.Fatalf("register %s 应 201，got %d: %s", name, st, raw)
		}
		var out struct {
			User struct {
				ID uint64 `json:"id"`
			} `json:"user"`
		}
		if err := json.Unmarshal(raw, &out); err != nil || out.User.ID == 0 {
			t.Fatalf("register 响应应含 user.id: %s", raw)
		}
		return out.User.ID
	}
	aliceID := register(aliceInvite, "alice", alicePw)
	bobID := register(bobInvite, "bob", bobPw)
	csecStage("users registered: alice=%d bob=%d", aliceID, bobID)

	// 5) 启动两个受邀安全节点（真实挑战流程）。
	startNode := func(idx, port int, invite string) *csecProc {
		cert, key := leafCert(fmt.Sprintf("node%d", idx))
		return csecStart(t, fmt.Sprintf("node%d", idx), csecEnv("ATOLL_NODE_INVITE="+invite),
			"node",
			"-master", masterURL,
			"-listen", fmt.Sprintf("127.0.0.1:%d", port),
			"-advertise", fmt.Sprintf("127.0.0.1:%d", port),
			"-data-dir", filepath.Join(root, fmt.Sprintf("node%d", idx)),
			"-secure", "-tls-cert", cert, "-tls-key", key, "-tls-ca", caPath,
			"-total-bytes", "1000000000")
	}
	node1 := startNode(1, node1Port, devInvite1)
	node2 := startNode(2, node2Port, devInvite2)

	// 设备注册完成 = /auth/devices 出现两台未吊销设备。
	var devices []struct {
		NodeID  uint64 `json:"node_id"`
		Addr    string `json:"addr"`
		Revoked bool   `json:"revoked"`
	}
	csecPoll(t, 30*time.Second, "两个节点完成设备挑战并注册", func() bool {
		st, raw := httpc.do(t, "GET", masterURL+"/auth/devices", adminBearer, nil)
		if st != 200 || json.Unmarshal(raw, &devices) != nil {
			return false
		}
		ok := 0
		for _, d := range devices {
			if !d.Revoked {
				ok++
			}
		}
		return ok == 2
	})
	node1ID := uint64(0)
	node1Addr := fmt.Sprintf("127.0.0.1:%d", node1Port)
	for _, d := range devices {
		if d.Addr == node1Addr {
			node1ID = d.NodeID
		}
	}
	if node1ID == 0 {
		t.Fatalf("设备列表应含 node1（addr=%s）: %+v", node1Addr, devices)
	}
	csecStage("nodes joined: %d devices", len(devices))

	// 会话 CLI 公共参数。
	cliBase := []string{"-master", masterURL, "-tls-ca", caPath}
	cliEnv := func(session string) []string {
		return csecEnv("ATOLL_SESSION=" + session)
	}
	sessionOf := func(user, pw string) (string, uint64) {
		res := csecCLI(t, csecEnv("ATOLL_PASSWORD="+pw), false,
			append([]string{"login"}, append(cliBase, "-user", user)...)...)
		if res.code != 0 {
			t.Fatalf("%s login exit=%d stderr=%s", user, res.code, res.stderr)
		}
		var sess struct {
			Token string `json:"token"`
			User  struct {
				PersonalSpaceID uint64 `json:"personal_space_id"`
			} `json:"user"`
		}
		if err := json.Unmarshal([]byte(res.stdout), &sess); err != nil || sess.Token == "" {
			t.Fatalf("%s login 输出应含 token: %v", user, err)
		}
		csecRegisterSecret(sess.Token)
		csecLogResult([]string{"login", "-master ...", "-user", user}, res)
		return sess.Token, sess.User.PersonalSpaceID
	}

	aliceSession, aliceSpace := sessionOf("alice", alicePw)
	bobSession, bobSpace := sessionOf("bob", bobPw)
	if aliceSpace == 0 || bobSpace == 0 {
		t.Fatalf("个人空间 ID 应非零: alice=%d bob=%d", aliceSpace, bobSpace)
	}

	t.Run("login and spaces", func(t *testing.T) {
		out := csecMustCLI(t, cliEnv(aliceSession), append([]string{"spaces"}, cliBase...)...)
		var spaces []struct {
			ID   uint64 `json:"id"`
			Name string `json:"name"`
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(out), &spaces); err != nil {
			t.Fatalf("spaces 输出应 JSON 数组: %v: %q", err, out)
		}
		found := false
		for _, spc := range spaces {
			if spc.Kind == "personal" && spc.Name == "alice" && spc.ID == aliceSpace {
				found = true
			}
		}
		if !found {
			t.Fatalf("alice spaces 应含个人空间 %d: %q", aliceSpace, out)
		}
		csecStage("login/spaces ok")
	})

	t.Run("mkdir and ls", func(t *testing.T) {
		csecMustCLI(t, cliEnv(aliceSession),
			append(append([]string{"mkdir"}, cliBase...), "-space", fmt.Sprint(aliceSpace), "/docs")...)
		out := csecMustCLI(t, cliEnv(aliceSession),
			append(append([]string{"ls"}, cliBase...), "-space", fmt.Sprint(aliceSpace), "/")...)
		if !strings.Contains(out, "docs") {
			t.Fatalf("ls / 应看到 docs: %q", out)
		}
		csecStage("mkdir/ls ok")
	})

	writeLocal := func(t *testing.T, name string, size int) string {
		t.Helper()
		p := filepath.Join(root, name)
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	getAndCompare := func(t *testing.T, remote, local, wantPath string, wantSize int64) {
		t.Helper()
		csecMustCLI(t, cliEnv(aliceSession),
			append(append([]string{"get"}, cliBase...), "-space", fmt.Sprint(aliceSpace), remote, local)...)
		got, err := os.ReadFile(local)
		if err != nil {
			t.Fatalf("读取下载文件: %v", err)
		}
		if wantSize >= 0 && int64(len(got)) != wantSize {
			t.Fatalf("下载大小不符: got %d want %d", len(got), wantSize)
		}
		if wantPath != "" {
			want, _ := os.ReadFile(wantPath)
			if !bytes.Equal(got, want) {
				t.Fatalf("下载内容与上传不符")
			}
		}
	}

	t.Run("put get empty file", func(t *testing.T) {
		empty := filepath.Join(root, "empty.src")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		csecMustCLI(t, cliEnv(aliceSession),
			append(append([]string{"put"}, cliBase...), "-space", fmt.Sprint(aliceSpace), empty, "/empty.bin")...)
		getAndCompare(t, "/empty.bin", filepath.Join(root, "empty.dst"), "", 0)
		csecStage("empty file roundtrip ok (secure /auth/files/empty)")
	})

	t.Run("put get small file", func(t *testing.T) {
		src := writeLocal(t, "small.src", 64<<10)
		csecMustCLI(t, cliEnv(aliceSession),
			append(append([]string{"put"}, cliBase...), "-space", fmt.Sprint(aliceSpace), src, "/small.bin")...)
		getAndCompare(t, "/small.bin", filepath.Join(root, "small.dst"), src, 64<<10)
		csecStage("small file roundtrip ok (PutSmall channel)")
	})

	t.Run("put get chunked over SmallFileMax", func(t *testing.T) {
		src := writeLocal(t, "big.src", int(types.SmallFileMax)+64<<10)
		csecMustCLI(t, cliEnv(aliceSession),
			append(append([]string{"put", "-replicas", "2"}, cliBase...),
				"-space", fmt.Sprint(aliceSpace), src, "/big.bin")...)
		getAndCompare(t, "/big.bin", filepath.Join(root, "big.dst"), src, int64(int(types.SmallFileMax)+64<<10))
		csecStage("chunked file roundtrip ok (> SmallFileMax)")
	})

	t.Run("team create member read write revoke", func(t *testing.T) {
		// bob 先在个人空间放文件（后续登出验证用）。
		bobSrc := writeLocal(t, "bob.src", 2048)
		csecMustCLI(t, cliEnv(bobSession),
			append(append([]string{"put"}, cliBase...), "-space", fmt.Sprint(bobSpace), bobSrc, "/bobfile.bin")...)

		out := csecMustCLI(t, cliEnv(aliceSession),
			append(append([]string{"team-create"}, cliBase...), "audit-team")...)
		var team struct {
			ID   uint64 `json:"id"`
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(out), &team); err != nil || team.ID == 0 || team.Kind != "team" {
			t.Fatalf("team-create 输出应含 team space: %q", out)
		}
		teamArg := fmt.Sprint(team.ID)

		member := func(args ...string) {
			csecMustCLI(t, cliEnv(aliceSession),
				append(append(append([]string{"team-member"}, cliBase...), "-space", teamArg), args...)...)
		}
		// 授权 bob 可写。
		member(fmt.Sprint(bobID), "write")
		bobSrc2 := writeLocal(t, "shared.src", 4096)
		csecMustCLI(t, cliEnv(bobSession),
			append(append([]string{"put"}, cliBase...), "-space", teamArg, bobSrc2, "/shared.bin")...)
		csecMustCLI(t, cliEnv(bobSession),
			append(append([]string{"get"}, cliBase...), "-space", teamArg, "/shared.bin", filepath.Join(root, "shared.dst"))...)
		// 降级为只读：写被拒，读仍可。
		member(fmt.Sprint(bobID), "read")
		if res := csecCLI(t, cliEnv(bobSession), true,
			append(append([]string{"put"}, cliBase...), "-space", teamArg, bobSrc2, "/shared2.bin")...); res.code == 0 {
			t.Fatalf("只读成员 put 应失败")
		} else {
			csecLogResult([]string{"put (read-only member, expect fail)"}, res)
		}
		csecMustCLI(t, cliEnv(bobSession),
			append(append([]string{"get"}, cliBase...), "-space", teamArg, "/shared.bin", filepath.Join(root, "shared2.dst"))...)
		// 撤销成员：读写全拒。
		member(fmt.Sprint(bobID), "remove")
		if res := csecCLI(t, cliEnv(bobSession), true,
			append(append([]string{"get"}, cliBase...), "-space", teamArg, "/shared.bin", filepath.Join(root, "shared3.dst"))...); res.code == 0 {
			t.Fatalf("撤销成员后 get 应失败")
		} else {
			csecLogResult([]string{"get (revoked member, expect fail)"}, res)
		}
		// bob 个人空间不受影响。
		csecMustCLI(t, cliEnv(bobSession),
			append(append([]string{"get"}, cliBase...), "-space", fmt.Sprint(bobSpace), "/bobfile.bin", filepath.Join(root, "bob.dst"))...)
		csecStage("team member write/read/revoke ok")
	})

	t.Run("logout invalidates session", func(t *testing.T) {
		csecMustCLI(t, cliEnv(bobSession),
			append([]string{"logout"}, cliBase...)...)
		if res := csecCLI(t, cliEnv(bobSession), true,
			append(append([]string{"get"}, cliBase...), "-space", fmt.Sprint(bobSpace), "/bobfile.bin", filepath.Join(root, "bob-after-logout.dst"))...); res.code == 0 {
			t.Fatalf("登出后 get 应失败（会话已吊销）")
		} else {
			csecLogResult([]string{"get (after logout, expect fail)"}, res)
		}
		if res := csecCLI(t, cliEnv(bobSession), true, append([]string{"spaces"}, cliBase...)...); res.code == 0 {
			t.Fatalf("登出后 spaces 应失败")
		}
		csecStage("logout invalidation ok")
	})

	t.Run("plain http rejected", func(t *testing.T) {
		// 安全 master 的 -listen 走 TLS：明文请求在 TLS 层即被 Go 服务器以
		// "Client sent an HTTP request to an HTTPS server" 拒绝（fail-closed）。
		// 注：securityHandler 里的 426 分支仅在明文监听器下可达，而 -allow-insecure
		// 放行明文后该分支又不触发——经真实 flag 组合不可达（实现备注，非缺陷）。
		plain := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
		resp, err := plain.Post(fmt.Sprintf("http://127.0.0.1:%d/auth/login", masterPort), "application/json",
			strings.NewReader(`{"username":"alice","password":"x"}`))
		if err != nil {
			t.Fatalf("明文请求应到达服务器被 TLS 层拒绝: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("明文 HTTP 登录不应成功，got 200")
		}
		if !strings.Contains(string(raw), "Client sent an HTTP request to an HTTPS server") {
			t.Fatalf("应得到 TLS 层明文拒绝说明，got %d: %s", resp.StatusCode, raw)
		}
		csecStage("plain http rejected at TLS layer ok")
	})

	t.Run("client negatives: no ca, skip verify", func(t *testing.T) {
		// 无 -tls-ca：自签证书不在系统信任链 → 握手失败。
		if res := csecCLI(t, csecEnv("ATOLL_PASSWORD="+alicePw), true,
			"login", "-master", masterURL, "-user", "alice"); res.code == 0 {
			t.Fatalf("无 CA 登录应失败（不信任自签 CA）")
		}
		// -tls-skip-verify 必须显式 allow-insecure 才放行 → 直接拒绝。
		// 补 path 参数避免 usage 错误；断言具体拒绝原因。
		res := csecCLI(t, cliEnv(aliceSession), true,
			append(append([]string{"ls", "-tls-skip-verify"}, cliBase...), "/")...)
		if res.code == 0 {
			t.Fatalf("-tls-skip-verify 未配 -allow-insecure 应失败")
		}
		if !strings.Contains(res.stderr, "InsecureSkipVerify") && !strings.Contains(res.stderr, "allowInsecure") {
			t.Fatalf("应提示 InsecureSkipVerify/allowInsecure 拒绝原因，got stderr: %s", res.stderr)
		}
		csecStage("client tls negatives ok")
	})

	t.Run("secure roles refuse insecure startup", func(t *testing.T) {
		// master -secure 无证书。
		res := csecCLI(t, masterEnv(), true, "master", "-secure", "-listen",
			fmt.Sprintf("127.0.0.1:%d", csecFreePort(t)), "-db", filepath.Join(root, "unused.db"))
		if res.code == 0 {
			t.Fatalf("secure master 无证书应拒绝启动")
		}
		// master -secure + skip-verify。
		res = csecCLI(t, masterEnv(), true, "master", "-secure", "-tls-skip-verify", "-listen",
			fmt.Sprintf("127.0.0.1:%d", csecFreePort(t)),
			"-tls-cert", masterCert, "-tls-key", masterKey, "-db", filepath.Join(root, "unused.db"))
		if res.code == 0 {
			t.Fatalf("secure master -tls-skip-verify 应拒绝启动")
		}
		// node -secure + skip-verify。
		cert, key := leafCert("node-skip")
		res = csecCLI(t, csecEnv("ATOLL_NODE_INVITE=unused"), true, "node", "-secure", "-tls-skip-verify",
			"-master", masterURL, "-listen", fmt.Sprintf("127.0.0.1:%d", csecFreePort(t)),
			"-data-dir", filepath.Join(root, "node-skip"),
			"-tls-cert", cert, "-tls-key", key, "-tls-ca", caPath)
		if res.code == 0 {
			t.Fatalf("secure node -tls-skip-verify 应拒绝启动")
		}
		csecStage("insecure startup refusals ok")
	})

	t.Run("device revoke idempotent", func(t *testing.T) {
		st, raw := httpc.do(t, "POST", masterURL+"/auth/devices/revoke", adminBearer,
			map[string]any{"node_id": node1ID})
		if st != 200 {
			t.Fatalf("吊销设备应 200，got %d: %s", st, raw)
		}
		// 幂等：重复吊销必须不误报失败（此前经 deviceByNodeTx 返回 ErrDeviceAuth→400）。
		st2, raw2 := httpc.do(t, "POST", masterURL+"/auth/devices/revoke", adminBearer,
			map[string]any{"node_id": node1ID})
		if st2 != 200 {
			t.Errorf("IMPLEMENTATION ISSUE: 重复吊销已吊销设备 got %d: %s（应幂等 200，避免重试把已生效误报为失败）", st2, raw2)
		}
		var list []struct {
			NodeID  uint64 `json:"node_id"`
			Revoked bool   `json:"revoked"`
		}
		st3, raw3 := httpc.do(t, "GET", masterURL+"/auth/devices", adminBearer, nil)
		if st3 != 200 || json.Unmarshal(raw3, &list) != nil {
			t.Fatalf("devices 列表: %d %s", st3, raw3)
		}
		for _, d := range list {
			if d.NodeID == node1ID && !d.Revoked {
				t.Fatalf("设备 %d 应标记 revoked", node1ID)
			}
		}
		csecStage("device revoke (idempotent) ok")
	})

	t.Run("no-secure restart fail-closed", func(t *testing.T) {
		// 停 master（TERM+Wait），不带 -secure 重启同一安全库：必须拒绝启动。
		master.csecStop()
		res := csecCLI(t, masterEnv(), true, "master", "-listen",
			fmt.Sprintf("127.0.0.1:%d", masterPort), "-db", dbPath)
		if res.code == 0 {
			t.Fatalf("安全库不带 -secure 重启必须 fail-closed 拒绝启动")
		}
		if !strings.Contains(res.stderr, "security mode must match") {
			t.Fatalf("应提示 security mode must match，got stderr: %s", res.stderr)
		}
		// 正常重启只验证同一本地数据库的持久化，不代替快照与 WAL 重建测试。
		master2 := csecStart(t, "master-restart", masterEnv(),
			"master", "-secure",
			"-listen", fmt.Sprintf("127.0.0.1:%d", masterPort),
			"-db", dbPath,
			"-tls-cert", masterCert, "-tls-key", masterKey, "-tls-ca", caPath,
			"-node-max-age", "20s")
		_ = master2
		csecPoll(t, 20*time.Second, "master 重启 /healthz", func() bool {
			resp, err := httpc.client.Get(masterURL + "/healthz")
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == 200
		})
		out := csecMustCLI(t, cliEnv(aliceSession), append([]string{"spaces"}, cliBase...)...)
		if !strings.Contains(out, "personal") {
			t.Fatalf("重启后旧会话应有效且能列出空间: %q", out)
		}
		csecStage("no-secure restart fail-closed + secure restart session durable ok")
	})

	t.Run("node restart without secure flag fail-closed", func(t *testing.T) {
		// node1 已被吊销，但 dataDir 已落安全标记：重启不带 --secure 必须失败
		//（注册被拒 / 标记 fail-closed），绝不静默退回 legacy 暴露数据。
		// 补 -tls-ca 确保 TLS 握手成功，使失败原因是 registration/marker 拒绝而非证书错误。
		node1.csecStop()
		res := csecCLI(t, csecEnv(), true, "node",
			"-master", masterURL,
			"-listen", fmt.Sprintf("127.0.0.1:%d", node1Port),
			"-advertise", fmt.Sprintf("127.0.0.1:%d", node1Port),
			"-data-dir", filepath.Join(root, "node1"),
			"-tls-ca", caPath)
		if res.code == 0 {
			t.Fatalf("带安全标记的 dataDir 重启忘带 --secure 必须 fail-closed（注册/启动失败）")
		}
		csecLogResult([]string{"node restart without --secure (expect fail)"}, res)
		csecStage("node marker fail-closed ok")
	})

	// node2 从入列起持续运行（心跳/续期不断）直到测试结束，由 t.Cleanup TERM+Wait。
	if !node2.alive() {
		t.Fatalf("node2 应全程存活（心跳与会话续期正常）")
	}
	csecStage("TestCLISecurityAcceptance done")
}

// SmallFileMax 引用包内常量，避免手写镜像值。
