package master

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

func waitSecureCopies(t *testing.T, c *secCluster, objectID uint64, count int) types.ObjectIntegrity {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last types.ObjectIntegrity
	for time.Now().Before(deadline) {
		var err error
		last, err = c.store.ObjectIntegrity(objectID)
		if err != nil {
			t.Fatal(err)
		}
		if len(last.Done) == count && len(last.Suspect) == 0 {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("copy receipts did not converge: replicas=%v done=%v suspect=%v", last.Replicas, last.Done, last.Suspect)
	return last
}

func secureDiskObject(n *secNode, objectID uint64) string {
	return filepath.Join(n.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", objectID%256), fmt.Sprint(objectID))
}

func TestSecurePhysicalReplicationAndRepair(t *testing.T) {
	c := newSecureCluster(t, 3)
	user, _ := c.adminLogin()
	body := bytes.Repeat([]byte("secure-replica-data"), 2000)
	in, err := user.PutSmall("/small", body, 3, false)
	if err != nil {
		t.Fatal(err)
	}
	waitSecureCopies(t, c, in.ObjID, 3)
	for _, node := range c.nodes {
		got, err := os.ReadFile(secureDiskObject(node, in.ObjID))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("node %d did not receive the full replica: %v", node.node.NodeIDForTest(), err)
		}
	}

	local := filepath.Join(t.TempDir(), "chunked-input")
	if err := os.WriteFile(local, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := user.PutChunkedWithMinCopies(local, "/chunked", 3, 3, false); err != nil {
		t.Fatal(err)
	}
	chunked, _, err := user.Lookup("/chunked")
	if err != nil || len(chunked.Chunks) != 1 {
		t.Fatalf("lookup: %+v %v", chunked, err)
	}
	ch := chunked.Chunks[0]
	objectID := types.ChunkObjID(ch, chunked.ID)
	waitSecureCopies(t, c, objectID, 3)
	victim := c.nodes[0]
	bad := append([]byte(nil), body...)
	bad[5] ^= 0xff
	if err := os.WriteFile(secureDiskObject(victim, objectID), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := user.ReportChunkSuspect(context.Background(), chunked, ch, victim.node.NodeIDForTest()); err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(c.store, time.Hour, 20*time.Millisecond, time.Hour)
	c.srv.SetScanner(scanner)
	c.srv.AttachSecureTransports()
	scanner.RepairScanOnce()
	waitSecureCopies(t, c, objectID, 3)
	got, err := os.ReadFile(secureDiskObject(victim, objectID))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("secure repair did not restore physical contents: %v", err)
	}
}

func TestSecureAutonomyAddsVerifiedReplica(t *testing.T) {
	c := newSecureCluster(t, 2)
	user, _ := c.adminLogin()
	for _, n := range c.nodes {
		if err := c.store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: n.node.NodeIDForTest(), FailureDomains: map[string]string{"site": n.addr()}}); err != nil {
			t.Fatal(err)
		}
	}
	body := []byte("secure autonomous copy")
	in, err := user.PutSmall("/auto", body, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	waitSecureCopies(t, c, in.ObjID, 1)
	a, err := NewAutonomy(c.store, time.Hour, AutonomyConfig{Mode: AutonomyAdd, MaxReplicas: 2, RetryInterval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	c.srv.SetAutonomy(a)
	c.srv.AttachSecureTransports()
	report, err := a.Step(context.Background())
	if err != nil || report.Dispatched == 0 {
		t.Fatalf("no actual autonomous dispatch: %+v %v", report, err)
	}
	waitSecureCopies(t, c, in.ObjID, 2)
	for _, n := range c.nodes {
		got, err := os.ReadFile(secureDiskObject(n, in.ObjID))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("autonomous target contents: %v", err)
		}
		res, err := user.HTTP.Get(n.server.URL + fmt.Sprintf("/objects/%d", in.ObjID))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("authorized read returned %d", res.StatusCode)
		}
	}
}
