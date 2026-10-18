package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"atoll/pkg/types"
)

func configureIntegrityMaster(t *testing.T, n *Node, objects map[uint64][]byte, sources []types.NodeInfo) *httptest.Server {
	t.Helper()
	n.SetNodeIDForTest(2)
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		id, _ := strconv.ParseUint(r.URL.Query().Get("object_id"), 10, 64)
		data, ok := objects[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(types.ReplicationPlan{
			Protocol: types.IntegrityProtocol,
			Object:   types.ObjectIntegrity{ObjectID: id, InodeID: id, Size: int64(len(data)), Checksum: types.CRC32C(data), ChecksumKnown: true, Replicas: []uint64{1, 2}},
			Sources:  sources,
		})
	}))
	n.masterURL = master.URL
	t.Cleanup(master.Close)
	return master
}

func TestStoreVerifiedObjectExactLengthAndZeroCRC(t *testing.T) {
	n := New(t.TempDir(), "", "", 1<<30)
	good := []byte("keep old object")
	if _, _, err := n.storeObject(7, bytes.NewReader(good), types.CRC32C(good)); err != nil {
		t.Fatal(err)
	}
	zero := uint32(0)
	for _, tc := range []struct {
		name string
		data []byte
		size int64
		crc  *uint32
	}{
		{"short", []byte("x"), 2, nil},
		{"long", []byte("xx"), 1, nil},
		{"zero-crc", good, int64(len(good)), &zero},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := n.storeVerifiedObject(7, bytes.NewReader(tc.data), tc.crc, tc.size); err == nil {
				t.Fatal("invalid body accepted")
			}
			got, err := os.ReadFile(n.objectPath(7))
			if err != nil || !bytes.Equal(got, good) {
				t.Fatalf("old contents changed: %q %v", got, err)
			}
			files, err := filepath.Glob(filepath.Join(filepath.Dir(n.objectPath(7)), ".tmp-*"))
			if err != nil || len(files) != 0 {
				t.Fatalf("temporary file leaked: %v %v", files, err)
			}
		})
	}
	zeroBytes := []byte{0xab, 0x9b, 0xe0, 0x9b}
	if types.CRC32C(zeroBytes) != 0 {
		t.Fatal("invalid zero CRC fixture")
	}
	if _, _, err := n.storeVerifiedObject(8, bytes.NewReader(zeroBytes), &zero, int64(len(zeroBytes))); err != nil {
		t.Fatalf("real zero CRC rejected: %v", err)
	}
}

func TestPushRefusesCorruptSourceAgainstMasterChecksum(t *testing.T) {
	good := []byte("authoritative object contents")
	bad := append([]byte(nil), good...)
	bad[4] ^= 0xff
	var targetWrites atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetWrites.Add(1)
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer target.Close()
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		json.NewEncoder(w).Encode(types.ReplicationPlan{
			Protocol: types.IntegrityProtocol,
			Object:   types.ObjectIntegrity{ObjectID: 42, InodeID: 42, Size: int64(len(good)), Checksum: types.CRC32C(good), ChecksumKnown: true, Replicas: []uint64{2, 3}},
			Targets:  []types.NodeInfo{{ID: 3, Addr: strings.TrimPrefix(target.URL, "http://")}},
		})
	}))
	defer master.Close()
	n := New(t.TempDir(), master.URL, "", 1<<30)
	n.SetNodeIDForTest(2)
	if _, _, err := n.storeObject(42, bytes.NewReader(good), types.CRC32C(good)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(n.objectPathForTest(42), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := n.pushObject(strings.TrimPrefix(target.URL, "http://"), 42); err == nil {
		t.Error("corrupt source was accepted as its own checksum authority")
	}
	if got := targetWrites.Load(); got != 0 {
		t.Fatalf("corrupt contents sent to target %d times", got)
	}
}

func TestPushValidSourceAgainstMasterChecksum(t *testing.T) {
	data := []byte("valid immutable contents")
	var targetWrites atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("target payload: %q %v", got, err)
		}
		targetWrites.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer target.Close()
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(types.ReplicationPlan{
			Protocol: types.IntegrityProtocol,
			Object: types.ObjectIntegrity{ObjectID: 42, InodeID: 42, Size: int64(len(data)),
				Checksum: types.CRC32C(data), ChecksumKnown: true, Replicas: []uint64{2, 3}},
			Targets: []types.NodeInfo{{ID: 3, Addr: target.Listener.Addr().String()}},
		})
	}))
	defer master.Close()
	n := New(t.TempDir(), master.URL, "", 1<<30)
	n.SetNodeIDForTest(2)
	if _, _, err := n.storeObject(42, bytes.NewReader(data), types.CRC32C(data)); err != nil {
		t.Fatal(err)
	}
	if err := n.pushObject(target.Listener.Addr().String(), 42); err != nil {
		t.Fatal(err)
	}
	if targetWrites.Load() != 1 {
		t.Fatalf("valid source not delivered: %d", targetWrites.Load())
	}
	if err := n.pushObject("127.0.0.1:1", 42); err == nil {
		t.Fatal("unassigned target was accepted")
	}
}

func TestPushRejectsUnknownMasterIntegrityProtocol(t *testing.T) {
	var targetWrites atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetWrites.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer target.Close()
	master := httptest.NewServer(http.NotFoundHandler())
	defer master.Close()
	n := New(t.TempDir(), master.URL, "", 1<<30)
	n.SetNodeIDForTest(2)
	if _, _, err := n.storeObject(42, bytes.NewBufferString("payload"), 0); err != nil {
		t.Fatal(err)
	}
	if err := n.pushObject(strings.TrimPrefix(target.URL, "http://"), 42); err == nil {
		t.Fatal("missing master integrity protocol must not silently fall back to source CRC")
	}
	if got := targetWrites.Load(); got != 0 {
		t.Fatal(fmt.Sprintf("unexpected target writes: %d", got))
	}
}
