package node

// 对象退役回归：持久 fence 先于 unlink、慢写 pending 且晚写不复活、满容量 replay
// 不绕 fence、重启对账、非法 fence 拒启动/写入、缺席对象与身份/大小校验。

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/pkg/types"
)

const (
	retireTestNodeID = uint64(7)
	retireTestFence  = "fence-token-0000000001"
	retireTestAtt1   = "attempt-token-00000001"
	retireTestAtt2   = "attempt-token-00000002"
)

func newRetireTestNode(t *testing.T) *Node {
	t.Helper()
	n := New(t.TempDir(), "", "", 1<<20)
	n.SetNodeIDForTest(retireTestNodeID)
	return n
}

func retireTestReq(id uint64, attempt string, expectedSize int64) types.ObjectRetirement {
	return types.ObjectRetirement{
		Version:      types.RetirementVersion,
		ObjectID:     id,
		NodeID:       retireTestNodeID,
		FenceID:      retireTestFence,
		AttemptID:    attempt,
		ExpectedSize: expectedSize,
	}
}

func writeRawObject(t *testing.T, n *Node, id uint64, data []byte) string {
	t.Helper()
	path := n.objectPath(id)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir object bucket: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write raw object: %v", err)
	}
	return path
}

func assertObjectAbsent(t *testing.T, n *Node, id uint64) {
	t.Helper()
	if _, err := os.Lstat(n.objectPath(id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("object %d must not exist, stat err=%v", id, err)
	}
}

func tempFileBytes(t *testing.T, n *Node, id uint64) int64 {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(n.objectPath(id)))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatalf("read object bucket: %v", err)
	}
	var total int64
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("stat temp file: %v", err)
		}
		total += info.Size()
	}
	return total
}

func assertNoTempFiles(t *testing.T, n *Node, id uint64) {
	t.Helper()
	if got := tempFileBytes(t, n, id); got != 0 {
		t.Fatalf("%d temporary write bytes survived", got)
	}
}

// 让对象桶不可写使 unlink 失败；fence 仍在即证明它先于 unlink 持久化。
func TestRetireObjectPersistsFenceBeforeUnlink(t *testing.T) {
	n := newRetireTestNode(t)
	id := uint64(21)
	data := []byte("durable-before-unlink")
	if _, _, err := n.storeObject(id, bytes.NewReader(data), 0); err != nil {
		t.Fatalf("seed object: %v", err)
	}
	bucket := filepath.Dir(n.objectPath(id))
	if os.Geteuid() == 0 {
		t.Skip("root can unlink from a read-only directory; ordering probe needs a non-root user")
	}
	if err := os.Chmod(bucket, 0o555); err != nil {
		t.Fatalf("make bucket read-only: %v", err)
	}
	defer os.Chmod(bucket, 0o755)

	req := retireTestReq(id, retireTestAtt1, int64(len(data)))
	if _, err := n.retireObject(req); err == nil {
		t.Fatal("retirement must fail when the object cannot be unlinked")
	}

	fence, err := n.readFence(id)
	if err != nil {
		t.Fatalf("fence after failed unlink: %v", err)
	}
	if fence == nil {
		t.Fatal("fence must be durable before the object is unlinked")
	}
	if fence.FenceID != req.FenceID || fence.NodeID != req.NodeID || fence.ExpectedSize != int64(len(data)) || fence.RemovedBytes != int64(len(data)) {
		t.Fatalf("unexpected fence: %+v", fence)
	}
	if st, err := os.Stat(n.objectPath(id)); err != nil || st.Size() != int64(len(data)) {
		t.Fatalf("object must survive a failed retirement: stat=%v err=%v", st, err)
	}
	if got := n.used.Load(); got != int64(len(data)) {
		t.Fatalf("used after failed retirement = %d, want %d", got, len(data))
	}

	if err := os.Chmod(bucket, 0o755); err != nil {
		t.Fatalf("restore bucket permissions: %v", err)
	}
	req.AttemptID = retireTestAtt2
	receipt, err := n.retireObject(req)
	if err != nil {
		t.Fatalf("same fence with a fresh attempt must succeed: %v", err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("receipt invalid: %v", err)
	}
	if receipt.RemovedBytes != int64(len(data)) {
		t.Fatalf("removed_bytes = %d, want %d", receipt.RemovedBytes, len(data))
	}
	if receipt.Usage.UsedBytes != 0 || n.used.Load() != 0 {
		t.Fatalf("usage after retirement: receipt=%d used=%d, want 0", receipt.Usage.UsedBytes, n.used.Load())
	}
	assertObjectAbsent(t, n, id)
}

func TestRetireObjectFreshUsageAndRemovedBytes(t *testing.T) {
	n := newRetireTestNode(t)
	id := uint64(22)
	data := bytes.Repeat([]byte{0x5a}, 4096)
	if _, _, err := n.storeObject(id, bytes.NewReader(data), 0); err != nil {
		t.Fatalf("seed object: %v", err)
	}
	if got := n.used.Load(); got != int64(len(data)) {
		t.Fatalf("used before retirement = %d, want %d", got, len(data))
	}
	req := retireTestReq(id, retireTestAtt1, int64(len(data)))
	receipt, err := n.retireObject(req)
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("receipt invalid: %v", err)
	}
	if receipt.State != types.RetirementRemoved || receipt.RemovedBytes != int64(len(data)) {
		t.Fatalf("receipt = %+v, want removed %d", receipt, len(data))
	}
	if receipt.Usage.UsedBytes != 0 || receipt.Usage.Epoch == "" || receipt.Usage.Sequence == 0 {
		t.Fatalf("fresh usage snapshot = %+v, want used 0 with epoch/sequence", receipt.Usage)
	}
	if n.used.Load() != 0 {
		t.Fatalf("used after retirement = %d, want 0", n.used.Load())
	}
	assertObjectAbsent(t, n, id)
	fence, err := n.readFence(id)
	if err != nil || fence == nil {
		t.Fatalf("fence after retirement: %+v err=%v", fence, err)
	}
	if fence.RemovedBytes != int64(len(data)) || fence.ExpectedSize != int64(len(data)) {
		t.Fatalf("persisted fence = %+v", fence)
	}

	req.AttemptID = retireTestAtt2
	again, err := n.retireObject(req)
	if err != nil {
		t.Fatalf("idempotent retirement retry: %v", err)
	}
	if again.RemovedBytes != receipt.RemovedBytes || again.Usage.UsedBytes != 0 {
		t.Fatalf("retry receipt = %+v, want removed=%d used=0", again, receipt.RemovedBytes)
	}
}

// 首块 payload 落 tmp 后 gate：第二块读取前关闭 started，保证已发生真实写入。
type retireGatedReader struct {
	r       io.Reader
	reads   int
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *retireGatedReader) Read(p []byte) (int, error) {
	r.reads++
	if r.reads > 1 {
		r.once.Do(func() { close(r.started) })
		<-r.release
	}
	return r.r.Read(p)
}

// 慢写已有 payload 在 tmp 且 inflight>0 时退役必须 pending；晚写不得 rename 复活，
// 清理后 active/inflight/used 归零，同 fence 新 attempt 成功。
func TestRetirePendingDuringSlowBodyAndLateWriteCannotResurrect(t *testing.T) {
	n := newRetireTestNode(t)
	id := uint64(23)
	prefix := []byte("late-write-")
	rest := []byte("payload")
	data := append(append([]byte(nil), prefix...), rest...)

	pr, pw := io.Pipe()
	body := &retireGatedReader{r: pr, started: make(chan struct{}), release: make(chan struct{})}
	storeDone := make(chan error, 1)
	go func() {
		_, _, err := n.storeObject(id, body, 0)
		storeDone <- err
	}()
	writeRest := make(chan struct{})
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		_, _ = pw.Write(prefix)
		<-writeRest
		_, _ = pw.Write(rest)
		_ = pw.Close()
	}()

	select {
	case <-body.started:
	case <-time.After(5 * time.Second):
		t.Fatal("slow store never gated after the first chunk")
	}
	if got := n.inflightForTest(); got <= 0 {
		t.Fatalf("inflight = %d, want >0 while payload sits in the temp file", got)
	}
	if got := tempFileBytes(t, n, id); got < int64(len(prefix)) {
		t.Fatalf("temp file bytes = %d, want >= %d before retirement", got, len(prefix))
	}

	req := retireTestReq(id, retireTestAtt1, int64(len(data)))
	if _, err := n.retireObject(req); !errors.Is(err, errRetirementPending) {
		t.Fatalf("retirement during an active write = %v, want errRetirementPending", err)
	}
	if fence, err := n.readFence(id); err != nil || fence == nil {
		t.Fatalf("pending retirement must still persist the fence first: %+v err=%v", fence, err)
	}

	close(body.release)
	close(writeRest)
	<-writeDone
	select {
	case err := <-storeDone:
		if !errors.Is(err, errObjectRetired) {
			t.Fatalf("late write after retirement = %v, want errObjectRetired", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("late write did not finish")
	}
	assertObjectAbsent(t, n, id)
	assertNoTempFiles(t, n, id)
	if _, ok := n.activeObjectWrites.Load(id); ok {
		t.Fatal("active write registration leaked after the late write")
	}
	if got := n.used.Load(); got != 0 {
		t.Fatalf("used after rejected late write = %d, want 0", got)
	}
	if got := n.inflightForTest(); got != 0 {
		t.Fatalf("inflight after rejected late write = %d, want 0", got)
	}

	req.AttemptID = retireTestAtt2
	receipt, err := n.retireObject(req)
	if err != nil {
		t.Fatalf("fresh attempt after late write cleanup: %v", err)
	}
	if receipt.RemovedBytes != 0 || receipt.Usage.UsedBytes != 0 {
		t.Fatalf("receipt after absent-object retirement = %+v, want removed=0 used=0", receipt)
	}
}

func TestRetireFullCapacityReplayCannotBypassFence(t *testing.T) {
	data := []byte("replay-data-1234")
	n := New(t.TempDir(), "", "", int64(len(data)))
	n.SetNodeIDForTest(retireTestNodeID)
	id := uint64(24)
	crc := types.CRC32C(data)
	if _, _, err := n.storeVerifiedObject(id, bytes.NewReader(data), &crc, int64(len(data))); err != nil {
		t.Fatalf("seed full-capacity object: %v", err)
	}
	fence := objectFence{
		Version:      types.RetirementVersion,
		ObjectID:     id,
		NodeID:       retireTestNodeID,
		FenceID:      retireTestFence,
		ExpectedSize: int64(len(data)),
		RemovedBytes: int64(len(data)),
	}
	if err := n.persistFence(fence); err != nil {
		t.Fatalf("persist crash-window fence: %v", err)
	}

	_, _, err := n.storeVerifiedObject(id, bytes.NewReader(data), &crc, int64(len(data)))
	if !errors.Is(err, errObjectRetired) {
		t.Fatalf("full-capacity replay under fence = %v, want errObjectRetired", err)
	}
	got, readErr := os.ReadFile(n.objectPath(id))
	if readErr != nil || !bytes.Equal(got, data) {
		t.Fatalf("replay under fence changed the object: %x err=%v", got, readErr)
	}
	if n.used.Load() != int64(len(data)) {
		t.Fatalf("used after rejected replay = %d, want %d", n.used.Load(), len(data))
	}
	if n.inflightForTest() != 0 {
		t.Fatalf("inflight after rejected replay = %d, want 0", n.inflightForTest())
	}
}

func TestFenceReconcileOnRestartRemovesObject(t *testing.T) {
	n := newRetireTestNode(t)
	id := uint64(25)
	data := []byte("crash-window-object")
	writeRawObject(t, n, id, data)
	fence := objectFence{
		Version:      types.RetirementVersion,
		ObjectID:     id,
		NodeID:       retireTestNodeID,
		FenceID:      retireTestFence,
		ExpectedSize: int64(len(data)),
		RemovedBytes: int64(len(data)),
	}
	if err := n.persistFence(fence); err != nil {
		t.Fatalf("persist fence: %v", err)
	}
	if n.used.Load() != 0 {
		t.Fatalf("used before restart reconciliation = %d, want 0", n.used.Load())
	}

	if err := n.InitUsedBytes(); err != nil {
		t.Fatalf("restart reconciliation: %v", err)
	}
	assertObjectAbsent(t, n, id)
	if got := n.used.Load(); got != 0 {
		t.Fatalf("used after reconciliation = %d, want 0", got)
	}
	if _, err := os.Lstat(n.fencePath(id)); err != nil {
		t.Fatalf("fence must remain after reconciliation: %v", err)
	}
}

func TestFenceReconcileKeepsUnfencedObject(t *testing.T) {
	n := newRetireTestNode(t)
	keepID := uint64(26)
	keepData := []byte("survivor")
	writeRawObject(t, n, keepID, keepData)
	if err := n.InitUsedBytes(); err != nil {
		t.Fatalf("restart reconciliation: %v", err)
	}
	if got, err := os.ReadFile(n.objectPath(keepID)); err != nil || !bytes.Equal(got, keepData) {
		t.Fatalf("unfenced object must survive reconciliation: %x err=%v", got, err)
	}
	if got := n.used.Load(); got != int64(len(keepData)) {
		t.Fatalf("used after reconciliation = %d, want %d", got, len(keepData))
	}
}

func TestFenceRejectsCorruptOversizedAndSymlink(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, n *Node, id uint64)
	}{
		{
			name: "corrupt",
			setup: func(t *testing.T, n *Node, id uint64) {
				path := n.fencePath(id)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatalf("mkdir fence dir: %v", err)
				}
				if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
					t.Fatalf("write corrupt fence: %v", err)
				}
			},
		},
		{
			name: "oversized",
			setup: func(t *testing.T, n *Node, id uint64) {
				path := n.fencePath(id)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatalf("mkdir fence dir: %v", err)
				}
				if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 4097), 0o600); err != nil {
					t.Fatalf("write oversized fence: %v", err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, n *Node, id uint64) {
				path := n.fencePath(id)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatalf("mkdir fence dir: %v", err)
				}
				raw, err := json.Marshal(objectFence{
					Version:      types.RetirementVersion,
					ObjectID:     id,
					NodeID:       retireTestNodeID,
					FenceID:      retireTestFence,
					ExpectedSize: 1,
					RemovedBytes: 1,
				})
				if err != nil {
					t.Fatalf("marshal fence: %v", err)
				}
				target := filepath.Join(t.TempDir(), "fence-target")
				if err := os.WriteFile(target, raw, 0o600); err != nil {
					t.Fatalf("write symlink target: %v", err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("create symlink fence: %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newRetireTestNode(t)
			id := uint64(27)
			tc.setup(t, n, id)
			if err := n.InitUsedBytes(); err == nil {
				t.Fatal("startup reconciliation accepted an invalid fence")
			}
			if _, _, err := n.storeObject(id, bytes.NewReader([]byte("data")), 0); err == nil {
				t.Fatal("store accepted an invalid fence")
			}
			assertObjectAbsent(t, n, id)
			if got := n.inflightForTest(); got != 0 {
				t.Fatalf("rejected store leaked reservation: inflight=%d", got)
			}
		})
	}
}

func TestRetireAbsentObjectAndLateWriteBlocked(t *testing.T) {
	n := newRetireTestNode(t)
	id := uint64(28)
	req := retireTestReq(id, retireTestAtt1, 32)
	receipt, err := n.retireObject(req)
	if err != nil {
		t.Fatalf("retire absent object: %v", err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("receipt invalid: %v", err)
	}
	if receipt.RemovedBytes != 0 || receipt.Usage.UsedBytes != 0 {
		t.Fatalf("absent-object receipt = %+v, want removed=0 used=0", receipt)
	}
	if fence, err := n.readFence(id); err != nil || fence == nil || fence.RemovedBytes != 0 {
		t.Fatalf("absent-object fence = %+v err=%v", fence, err)
	}

	if _, _, err := n.storeObject(id, bytes.NewReader(make([]byte, 32)), 0); !errors.Is(err, errObjectRetired) {
		t.Fatalf("late write after absent-object retirement = %v, want errObjectRetired", err)
	}
	assertObjectAbsent(t, n, id)
	if got := n.used.Load(); got != 0 {
		t.Fatalf("used after rejected late write = %d, want 0", got)
	}
}

func TestRetireExpectedSizeMismatchLeavesNoFence(t *testing.T) {
	n := newRetireTestNode(t)
	id := uint64(29)
	data := []byte("0123456789")
	if _, _, err := n.storeObject(id, bytes.NewReader(data), 0); err != nil {
		t.Fatalf("seed object: %v", err)
	}
	req := retireTestReq(id, retireTestAtt1, int64(len(data)+1))
	if _, err := n.retireObject(req); err == nil {
		t.Fatal("expected_size mismatch must be rejected")
	}
	if _, err := os.Lstat(n.fencePath(id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatch must not persist a fence, stat err=%v", err)
	}
	got, err := os.ReadFile(n.objectPath(id))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("mismatch changed the object: %x err=%v", got, err)
	}
	if n.used.Load() != int64(len(data)) {
		t.Fatalf("used after rejected retirement = %d, want %d", n.used.Load(), len(data))
	}
}

func TestRetireWrongNodeRejected(t *testing.T) {
	n := newRetireTestNode(t)
	id := uint64(30)
	data := []byte("node-bound")
	if _, _, err := n.storeObject(id, bytes.NewReader(data), 0); err != nil {
		t.Fatalf("seed object: %v", err)
	}
	req := retireTestReq(id, retireTestAtt1, int64(len(data)))
	req.NodeID = retireTestNodeID + 1
	if _, err := n.retireObject(req); err == nil {
		t.Fatal("retirement for a different node must be rejected")
	}
	if _, err := os.Lstat(n.fencePath(id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong node must not persist a fence, stat err=%v", err)
	}
	if got, err := os.ReadFile(n.objectPath(id)); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("wrong node changed the object: %x err=%v", got, err)
	}
	if n.used.Load() != int64(len(data)) {
		t.Fatalf("used after wrong-node rejection = %d, want %d", n.used.Load(), len(data))
	}
}
