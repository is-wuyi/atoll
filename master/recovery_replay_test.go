package master

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

func TestSmallReplayWaitsForSynchronousDurability(t *testing.T) {
	store, backup, addrs := newBackupCluster(t, 1)
	var nodeID uint64
	for id := range addrs {
		nodeID = id
	}
	data := []byte("sync-replay-data")
	fingerprint := fmt.Sprintf("%s|%d|%08x|%t|%d", "/file", len(data), types.CRC32C(data), false, 1)
	obj, _, err := store.PrepareSmallFile(meta.SmallFileTarget{
		ParentID: meta.RootID, Name: "file", RemotePath: "/file",
		Size: int64(len(data)), Checksum: types.CRC32C(data),
		Replicas: []uint64{nodeID}, PrimaryID: nodeID, Mtime: time.Now(),
		OpID: "replay-after-sync-failure", Fingerprint: fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	put, err := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/objects/%d", addrs[nodeID], obj.ID), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	put.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", types.CRC32C(data)))
	resp, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("store object: %s", resp.Status)
	}
	if _, err := backup.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	seq, err := store.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	blockedPath := fmt.Sprintf("/meta-backup/wal-sync-%d", seq+1)
	base := backup.httpClient.Transport
	var blocked atomic.Bool
	blocked.Store(true)
	backup.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if blocked.Load() && r.Method == http.MethodPut && r.URL.Path == blockedPath {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header),
				Body: io.NopCloser(bytes.NewBufferString("injected sync failure")), Request: r}, nil
		}
		return base.RoundTrip(r)
	})
	backup.SetConfig(MetaBackupConfig{Replicas: 1, Retention: 3, Interval: time.Hour, SyncBeforeAck: true, SyncMinCopies: 1})
	backup.InstallSyncHook()
	if _, _, _, _, err := store.CommitSmallFile(obj.ID); err == nil {
		t.Fatal("commit must report the injected synchronous replication failure")
	}
	if _, ok, err := store.GetOpResult("replay-after-sync-failure"); err != nil || !ok {
		t.Fatalf("local commit must retain its result after hook failure: %v %v", ok, err)
	}
	server := NewServer(store, time.Hour)
	server.SetMetaBackup(backup)
	replay := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost,
			"/files/small?path=/file&replicas=1&overwrite=false&op_id=replay-after-sync-failure", bytes.NewReader(data))
		req.Header.Set(types.FeaturesHeader, types.ObjectIDFeature)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := replay(); rec.Code >= 200 && rec.Code < 300 {
		t.Fatalf("replay bypassed failed durability confirmation: %d %s", rec.Code, rec.Body.String())
	}
	blocked.Store(false)
	if rec := replay(); rec.Code != http.StatusOK || rec.Header().Get("X-Atoll-Replay") != "true" {
		t.Fatalf("replay after repair: %d %s", rec.Code, rec.Body.String())
	}
	restored, err := backup.Recover(filepath.Join(t.TempDir(), "restore.db"), seedAddrs(backup, t), RecoverCluster)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	in, err := restored.ResolvePath("/file")
	if err != nil || in.ObjID != obj.ID || in.Generation != 1 {
		t.Fatalf("acknowledged replay was not recoverable: %+v %v", in, err)
	}
	if _, ok, err := restored.GetOpResult("replay-after-sync-failure"); err != nil || !ok {
		t.Fatalf("replayed op result missing after restore: %v %v", ok, err)
	}
}
