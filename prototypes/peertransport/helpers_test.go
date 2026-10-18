package peertransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
)

func TestMain(m *testing.M) {
	testLog = log.New(os.Stderr, "[pt-test] ", log.LstdFlags|log.Lmicroseconds)
	os.Exit(m.Run())
}

var testLog *log.Logger

// cluster is a full prototype topology for one test: independent relay,
// control role and N storage peers, all on loopback with identities under a
// fresh temp dir.
type cluster struct {
	ctx       context.Context
	cancel    context.CancelFunc
	base      string
	relay     *RelayNode
	control   *ControlNode
	controlAI peer.AddrInfo
	relayAI   peer.AddrInfo
	peers     []*StoragePeer
	ids       []*Identity
	allow     *Allowlist
}

func startCluster(t *testing.T, n int, mutate ...func(i int, cfg *PeerConfig)) *cluster {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &cluster{ctx: ctx, cancel: cancel, base: t.TempDir()}
	t.Cleanup(func() {
		cancel()
		for _, p := range c.peers {
			_ = p.Close()
		}
		if c.control != nil {
			_ = c.control.Close()
		}
		if c.relay != nil {
			_ = c.relay.Close()
		}
	})

	for i := 0; i < n; i++ {
		id, err := LoadOrCreateIdentity(filepath.Join(c.base, fmt.Sprintf("peer%d", i+1)))
		if err != nil {
			t.Fatalf("identity peer%d: %v", i+1, err)
		}
		c.ids = append(c.ids, id)
	}
	idList := make([]peer.ID, 0, len(c.ids))
	for _, id := range c.ids {
		idList = append(idList, id.ID)
	}
	c.allow = NewAllowlist(idList...)

	relay, err := NewRelayNode(ctx, RelayConfig{
		DataDir:         filepath.Join(c.base, "relay"),
		Allowlist:       c.allow,
		Limit:           DefaultRelayLimit(),
		ReservationTTL:  30 * time.Minute,
		MaxReservations: 16,
		MaxCircuits:     8,
		Logger:          testLog,
	})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	c.relay = relay
	c.relayAI = relay.AddrInfo()

	control, err := NewControlNode(ctx, ControlConfig{
		DataDir:       filepath.Join(c.base, "control"),
		Authorized:    c.allow,
		RelayAddrInfo: &c.relayAI,
		Logger:        testLog,
	})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	c.control = control
	c.controlAI = control.AddrInfo()

	for i := range c.ids {
		cfg := PeerConfig{
			DataDir:    filepath.Join(c.base, fmt.Sprintf("peer%d", i+1)),
			Peers:      c.allow,
			Control:    &c.controlAI,
			Relay:      &c.relayAI,
			Logger:     testLog,
			EnableQUIC: false,
		}
		for _, m := range mutate {
			m(i, &cfg)
		}
		p, err := NewStoragePeer(ctx, cfg)
		if err != nil {
			t.Fatalf("peer%d: %v", i+1, err)
		}
		c.peers = append(c.peers, p)
	}

	testLog.Printf("cluster ready: %d peers, relay=%s control=%s", n, relay.ID, control.Host.ID())
	return c
}

// Addrs returns the direct endpoints of peer i.
func (c *cluster) Addrs(i int) []ma.Multiaddr { return c.peers[i].AddrInfo().Addrs }

// ===================== content helpers =====================

// deterministicBuf builds reproducible content plus its sha256.
func deterministicBuf(n int64, seed byte) ([]byte, string) {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = seed ^ byte(i*2654435761>>24)
	}
	sum := sha256.Sum256(buf)
	return buf, hex.EncodeToString(sum[:])
}

func shaOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// push streams data into dst's store via the given policy from srcIdx.
func push(t *testing.T, src *StoragePeer, dstID peer.ID, policy DialPolicy, addrs []ma.Multiaddr, key string, data []byte, want string) (serverSha string, stats TransferStats, httpCode int, err error) {
	t.Helper()
	client, dc := src.Dial(dstID, policy, addrs)
	req, rerr := http.NewRequest("PUT", "http://peer/objects/"+key, bytes.NewReader(data))
	if rerr != nil {
		t.Fatalf("new request: %v", rerr)
	}
	req = req.WithContext(context.Background())
	if want != "" {
		req.Header.Set("X-Object-Sha256", want)
	}
	req.ContentLength = int64(len(data))
	resp, derr := client.Do(req)
	if derr != nil {
		return "", dc.LastStats(), 0, derr
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated {
		return "", dc.LastStats(), resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var meta ObjectMeta
	_ = json.Unmarshal(body, &meta)
	return meta.Sha256, dc.LastStats(), http.StatusCreated, nil
}

// fetch reads an object from dstID's store.
func fetch(t *testing.T, src *StoragePeer, dstID peer.ID, policy DialPolicy, addrs []ma.Multiaddr, key string) ([]byte, string, TransferStats, error) {
	t.Helper()
	client, dc := src.Dial(dstID, policy, addrs)
	req, err := http.NewRequest("GET", "http://peer/objects/"+key, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", dc.LastStats(), err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", dc.LastStats(), fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", dc.LastStats(), err
	}
	return data, shaOf(data), dc.LastStats(), nil
}

// assertAllConnectionsSecured fails the test if any live connection on any
// host lacks a verified remote identity (peerstore public key), which is the
// observable of the identity-locked secure handshake (Noise on TCP,
// identity-locked TLS inside QUIC).
func assertAllConnectionsSecured(t *testing.T, hosts ...host.Host) {
	t.Helper()
	for _, h := range hosts {
		for _, conn := range h.Network().Conns() {
			remote := conn.RemotePeer()
			if h.Peerstore().PubKey(remote) == nil {
				t.Errorf("unsecured connection to %s via %s (no verified public key)", remote, conn.RemoteMultiaddr())
			}
		}
	}
}

// waitForCleanStore polls the store until the failed/aborted object is absent
// and no uncommitted temp file remains (the destination cleans up
// asynchronously when a transfer breaks mid-stream).
func waitForCleanStore(t *testing.T, st *ObjectStore, key string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !st.Has(key) {
			if err := st.VerifyNoPartial(); err == nil {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if st.Has(key) {
		t.Errorf("object %q became visible despite failed transfer", key)
	}
	if err := st.VerifyNoPartial(); err != nil {
		t.Errorf("partial object left behind: %v", err)
	}
}
