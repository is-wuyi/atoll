package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"atoll/client"
	"atoll/pkg/access"
	"atoll/pkg/peerauth"
	"atoll/pkg/types"
)

type cliProcessLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *cliProcessLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.Len() < 256<<10 {
		l.b.Write(p[:min(len(p), (256<<10)-l.b.Len())])
	}
	return len(p), nil
}

func (l *cliProcessLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type cliProcess struct {
	cmd  *exec.Cmd
	log  cliProcessLog
	done chan struct{}
	err  error
	once sync.Once
}

func peerCLIEnv(extra ...string) []string {
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ATOLL_") {
			env = append(env, entry)
		}
	}
	return append(env, extra...)
}

func runPeerCLI(t *testing.T, binary string, env []string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("CLI %s failed: %v\n%s", args[0], err, stderr.String())
	}
	return stdout.Bytes()
}

func startPeerCLI(t *testing.T, binary string, env []string, args ...string) *cliProcess {
	t.Helper()
	p := &cliProcess{cmd: exec.Command(binary, args...), done: make(chan struct{})}
	p.cmd.Env = env
	p.cmd.Stdout, p.cmd.Stderr = &p.log, &p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start CLI %s: %v", args[0], err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() { p.stop(t) })
	return p
}

func (p *cliProcess) stop(t *testing.T) {
	t.Helper()
	p.once.Do(func() {
		select {
		case <-p.done:
		default:
			if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Errorf("signal CLI: %v", err)
			}
			select {
			case <-p.done:
			case <-time.After(20 * time.Second):
				_ = p.cmd.Process.Kill()
				<-p.done
				t.Errorf("CLI did not stop after SIGTERM\n%s", p.log.String())
			}
		}
		if p.err != nil {
			t.Errorf("CLI process exit: %v\n%s", p.err, p.log.String())
		}
	})
}

func peerCLIAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func peerCLIJSON(hc *http.Client, method, url, token string, space uint64, body, out any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if space != 0 {
		req.Header.Set(access.SpaceHeader, strconv.FormatUint(space, 10))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: HTTP %d", method, req.URL.Path, resp.StatusCode)
	}
	if out != nil {
		return peerauth.DecodeJSONLimit(resp.Body, out, peerauth.MaxDirectoryBytes)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return err
}

func waitPeerCLI(t *testing.T, p *cliProcess, check func() error) {
	t.Helper()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if last = check(); last == nil {
			return
		}
		select {
		case <-p.done:
			t.Fatalf("CLI exited before ready: %v\n%s", p.err, p.log.String())
		case <-deadline.C:
			t.Fatalf("CLI readiness: %v\n%s", last, p.log.String())
		case <-ticker.C:
		}
	}
}

func TestPeerCLIProcessesAndRelease(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs real CLI processes")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "atoll")
	buildCtx, buildCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer buildCancel()
	build := exec.CommandContext(buildCtx, "go", "build", "-race", "-o", binary, "./cmd/atoll")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	pki := newTestPKI(t)
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.caCert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	_, certFile, keyFile := pki.leafCert(t, "127.0.0.1")
	dbPath := filepath.Join(dir, "meta.db")
	kekPath := filepath.Join(dir, "keys", "content.key")
	runPeerCLI(t, binary, peerCLIEnv("ATOLL_PASSWORD="+testAdminPassword), "auth", "init", "-db", dbPath, "-user", "admin")
	runPeerCLI(t, binary, peerCLIEnv(), "content-key-init", "-path", kekPath)
	masterAddr := peerCLIAddress(t)
	origin := "https://" + masterAddr
	masterPeerPath := filepath.Join(dir, "custom-master-peer.key")
	mp := startPeerCLI(t, binary, peerCLIEnv("ATOLL_CONTROL_TOKEN="+testControlToken),
		"master", "-secure", "-write-planning", "-write-max-replicas", "1", "-p2p", "-p2p-origin", origin,
		"-db", dbPath, "-listen", masterAddr, "-p2p-identity", masterPeerPath,
		"-tls-cert", certFile, "-tls-key", keyFile, "-tls-ca", caFile, "-content-key-file", kekPath,
		"-p2p-listen", "/ip4/127.0.0.1/tcp/0")
	hc := pki.httpsClient()
	hc.Timeout = 30 * time.Second
	t.Cleanup(hc.CloseIdleConnections)
	waitPeerCLI(t, mp, func() error { return peerCLIJSON(hc, http.MethodGet, origin+"/healthz", "", 0, nil, nil) })
	if _, err := os.Stat(masterPeerPath); err != nil {
		t.Fatalf("Master ignored the explicit peer identity path: %v", err)
	}
	if _, err := os.Stat(dbPath + ".peer.key"); !os.IsNotExist(err) {
		t.Fatalf("Master created its default identity despite explicit path: %v", err)
	}
	var admin client.LoginResult
	if err := json.Unmarshal(runPeerCLI(t, binary, peerCLIEnv("ATOLL_PASSWORD="+testAdminPassword), "login", "-master", origin, "-tls-ca", caFile, "-user", "admin"), &admin); err != nil {
		t.Fatal(err)
	}
	var invite struct {
		Invite    string    `json:"invite"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := peerCLIJSON(hc, http.MethodPost, origin+"/auth/invites", admin.Token, 0, map[string]any{"expires_at": time.Now().Add(time.Hour)}, &invite); err != nil {
		t.Fatal(err)
	}
	if err := peerCLIJSON(hc, http.MethodPost, origin+"/auth/register", "", 0, map[string]string{"invite": invite.Invite, "username": "alice", "password": testUserPassword}, nil); err != nil {
		t.Fatal(err)
	}
	var login client.LoginResult
	if err := json.Unmarshal(runPeerCLI(t, binary, peerCLIEnv("ATOLL_PASSWORD="+testUserPassword), "login", "-master", origin, "-tls-ca", caFile, "-user", "alice"), &login); err != nil {
		t.Fatal(err)
	}
	spaceID := userSpaceID(login)
	if login.Token == "" || spaceID == 0 {
		t.Fatal("CLI login returned no usable user session")
	}
	if err := peerCLIJSON(hc, http.MethodPost, origin+"/auth/devices/invites", admin.Token, 0, map[string]any{"expires_at": time.Now().Add(time.Hour)}, &invite); err != nil {
		t.Fatal(err)
	}
	nodeAddr := peerCLIAddress(t)
	nodeDir := filepath.Join(dir, "node")
	nodeArgs := []string{"node", "-secure", "-p2p", "-master", origin, "-listen", nodeAddr, "-advertise", nodeAddr,
		"-data-dir", nodeDir, "-tls-cert", certFile, "-tls-key", keyFile, "-tls-ca", caFile, "-p2p-listen", "/ip4/127.0.0.1/tcp/0"}
	np := startPeerCLI(t, binary, peerCLIEnv("ATOLL_NODE_INVITE="+invite.Invite), nodeArgs...)
	var directory peerauth.Directory
	readDirectory := func() error {
		directory = peerauth.Directory{}
		return peerCLIJSON(hc, http.MethodGet, origin+"/peers/directory", login.Token, spaceID, nil, &directory)
	}
	waitPeerCLI(t, np, func() error {
		if err := peerCLIJSON(hc, http.MethodGet, "https://"+nodeAddr+"/healthz", "", 0, nil, nil); err != nil {
			return err
		}
		if err := readDirectory(); err != nil {
			return err
		}
		for _, e := range directory.Endpoints {
			if e.Role == peerauth.RoleNode && e.Addr == nodeAddr {
				return nil
			}
		}
		return fmt.Errorf("node not yet published")
	})
	var before peerauth.Endpoint
	for _, e := range directory.Endpoints {
		if e.Role == peerauth.RoleNode {
			before = e
		}
	}
	payload := bytes.Repeat([]byte("cli-aead-peer-process-roundtrip-"), 4096)
	input := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	clientEnv := peerCLIEnv("ATOLL_SESSION=" + login.Token)
	common := []string{"-master", origin, "-p2p", "-tls-ca", caFile, "-space", strconv.FormatUint(spaceID, 10), "-p2p-listen", "/ip4/127.0.0.1/tcp/0"}
	assertReleased := func() {
		t.Helper()
		if err := readDirectory(); err != nil {
			t.Fatal(err)
		}
		for _, e := range directory.Endpoints {
			if e.Role == peerauth.RoleClient {
				t.Fatalf("completed CLI left an active peer slot: %s", e.PeerID)
			}
		}
	}
	for i := 0; i < 3; i++ {
		remote := fmt.Sprintf("/cli-%d.bin", i)
		runPeerCLI(t, binary, clientEnv, append(append([]string{"put"}, common...), input, remote)...)
		assertReleased()
		output := filepath.Join(dir, fmt.Sprintf("output-%d.bin", i))
		runPeerCLI(t, binary, clientEnv, append(append([]string{"get"}, common...), remote, output)...)
		assertReleased()
		got, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("CLI pair %d readback mismatch: %v", i, err)
		}
	}
	lookup, err := client.NewSecure(origin, pki.verifiedTLS(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := lookup.SetSession(login.Token); err != nil {
		t.Fatal(err)
	}
	if err := lookup.UseSpace(spaceID); err != nil {
		t.Fatal(err)
	}
	in, _, err := lookup.Lookup("/cli-0.bin")
	if err != nil || len(in.Chunks) != 1 || in.Chunks[0].Encoding != types.AeadRecordEncoding || !in.Chunks[0].ChecksumKnown || len(in.Chunks[0].Done) != 1 {
		t.Fatalf("CLI upload missing encrypted confirmed content: %+v %v", in, err)
	}
	persistent := filepath.Join(dir, "persistent-client.key")
	getPersistent := func() {
		output := filepath.Join(dir, "persistent-readback.bin")
		args := append(append([]string{"get"}, common...), "-p2p-identity", persistent, "/cli-0.bin", output)
		runPeerCLI(t, binary, clientEnv, args...)
		assertReleased()
		got, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("persistent CLI readback: %v", err)
		}
	}
	getPersistent()
	np.stop(t)
	np = startPeerCLI(t, binary, peerCLIEnv(), nodeArgs...)
	waitPeerCLI(t, np, func() error {
		if err := readDirectory(); err != nil {
			return err
		}
		for _, e := range directory.Endpoints {
			if e.Role == peerauth.RoleNode && e.NodeID == before.NodeID && e.PeerID == before.PeerID && e.Addr == before.Addr && e.Revision > before.Revision && transportAddrsChanged(before.Addresses, e.Addresses) {
				return peerCLIJSON(hc, http.MethodGet, "https://"+nodeAddr+"/healthz", "", 0, nil, nil)
			}
		}
		return fmt.Errorf("restarted node has not published the same identity with new transport addresses")
	})
	getPersistent()
	np.stop(t)
	mp.stop(t)
}
