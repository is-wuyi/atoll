package meta

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"atoll/pkg/types"
)

// 造一棵有代表性的元数据树：多级目录、普通文件（带副本）、节点注册。
// 快照恢复后逐项比对，证明"导出→恢复"完整无损。
func seedTree(t *testing.T, s *Store) {
	t.Helper()
	docs, err := s.CreateDir(RootID, "docs")
	if err != nil {
		t.Fatalf("CreateDir docs: %v", err)
	}
	if _, err := s.CreateDir(docs.ID, "sub"); err != nil {
		t.Fatalf("CreateDir sub: %v", err)
	}
	f, err := s.CreateFile(docs.ID, "a.txt", []uint64{7, 8})
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if err := s.UpdateFileSize(f.ID, 1234, 0xdeadbeef); err != nil {
		t.Fatalf("UpdateFileSize: %v", err)
	}
	if _, err := s.RegisterNode("127.0.0.1:9001", 1<<30); err != nil {
		t.Fatalf("RegisterNode: %v", err)
	}
}

// snapshotState 收集一个库的可观测状态，用于恢复前后对比。
type snapshotState struct {
	rootKids []string
	docsKids []string
	fileSize int64
	fileSum  uint32
	fileReps []uint64
	nodes    int
}

func captureState(t *testing.T, s *Store) snapshotState {
	t.Helper()
	var st snapshotState
	rootKids, err := s.ListChildren(RootID)
	if err != nil {
		t.Fatalf("ListChildren root: %v", err)
	}
	for _, k := range rootKids {
		st.rootKids = append(st.rootKids, k.Name)
	}
	docs, err := s.Lookup(RootID, "docs")
	if err != nil {
		t.Fatalf("Lookup docs: %v", err)
	}
	docsKids, err := s.ListChildren(docs.ID)
	if err != nil {
		t.Fatalf("ListChildren docs: %v", err)
	}
	for _, k := range docsKids {
		st.docsKids = append(st.docsKids, k.Name)
	}
	f, err := s.Lookup(docs.ID, "a.txt")
	if err != nil {
		t.Fatalf("Lookup a.txt: %v", err)
	}
	st.fileSize = f.Size
	st.fileSum = f.Checksum
	st.fileReps = append([]uint64(nil), f.Replicas...)
	nodes, err := s.ListNodes()
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	st.nodes = len(nodes)
	return st
}

func eqState(a, b snapshotState) bool {
	return sliceEq(a.rootKids, b.rootKids) &&
		sliceEq(a.docsKids, b.docsKids) &&
		a.fileSize == b.fileSize && a.fileSum == b.fileSum &&
		u64Eq(a.fileReps, b.fileReps) && a.nodes == b.nodes
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func u64Eq(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// 快照到内存 → 从字节流恢复到新库 → 状态逐项一致，校验和自洽。
func TestSnapshotRestoreRoundTrip(t *testing.T) {
	src := newTestStore(t)
	seedTree(t, src)
	want := captureState(t, src)

	var buf bytes.Buffer
	info, err := src.Snapshot(&buf)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if info.Size != int64(buf.Len()) {
		t.Fatalf("info.Size %d != 实际字节 %d", info.Size, buf.Len())
	}
	// 校验和自洽：对同一份字节重算应一致。
	sum, n, err := VerifyCRC32C(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("VerifyCRC32C: %v", err)
	}
	if sum != info.CRC32C || n != info.Size {
		t.Fatalf("校验和/大小不符: got sum=%x n=%d, want sum=%x n=%d", sum, n, info.CRC32C, info.Size)
	}

	// 恢复到一个全新路径。
	dst := filepath.Join(t.TempDir(), "restored.db")
	rs, err := RestoreFromReader(dst, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("RestoreFromReader: %v", err)
	}
	defer rs.Close()

	got := captureState(t, rs)
	if !eqState(want, got) {
		t.Fatalf("恢复后状态不符:\n want=%+v\n got =%+v", want, got)
	}
}

// 恢复后的库是完整可写的（不是只读快照）：能继续创建、且新分配的 inode ID
// 不与快照里已有的冲突（计数器一并恢复了）。
func TestRestoredStoreIsWritable(t *testing.T) {
	src := newTestStore(t)
	seedTree(t, src)
	// 记录 src 里下一个会分配到的 ID：再建一个文件看它拿到的 ID。
	probe, _ := src.CreateFile(RootID, "probe.txt", nil)
	nextIDInSrc := probe.ID

	var buf bytes.Buffer
	if _, err := src.Snapshot(&buf); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "restored.db")
	rs, err := RestoreFromReader(dst, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("RestoreFromReader: %v", err)
	}
	defer rs.Close()

	// 恢复库里再建文件，ID 必须继续递增（> 快照时刻的 nextIDInSrc），不复用。
	f, err := rs.CreateFile(RootID, "after.txt", []uint64{1})
	if err != nil {
		t.Fatalf("恢复库写入: %v", err)
	}
	if f.ID <= nextIDInSrc {
		t.Fatalf("恢复库分配的 ID %d 未超过快照内已用 ID %d（计数器未随快照恢复）", f.ID, nextIDInSrc)
	}
	// 快照里的旧数据仍在。
	if _, _, err := findFile(t, rs, RootID, "docs", "a.txt"); err != nil {
		t.Fatalf("恢复库丢失快照内数据: %v", err)
	}
}

func findFile(t *testing.T, s *Store, root uint64, dir, name string) (types.Inode, uint64, error) {
	t.Helper()
	d, err := s.Lookup(root, dir)
	if err != nil {
		return types.Inode{}, 0, err
	}
	f, err := s.Lookup(d.ID, name)
	return f, d.ID, err
}

// SnapshotToFile 落地 + 原子改名：产物是完整库文件，可被直接 Open。
func TestSnapshotToFile(t *testing.T) {
	src := newTestStore(t)
	seedTree(t, src)
	want := captureState(t, src)

	path := filepath.Join(t.TempDir(), "snap.db")
	info, err := src.SnapshotToFile(path)
	if err != nil {
		t.Fatalf("SnapshotToFile: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 快照文件: %v", err)
	}
	if fi.Size() != info.Size {
		t.Fatalf("落地文件大小 %d != info.Size %d", fi.Size(), info.Size)
	}
	// 临时文件不应残留。
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf(".tmp 未清理: %v", err)
	}
	// 快照文件本身就是完整 bbolt 库，直接 Open 可读。
	opened, err := Open(path)
	if err != nil {
		t.Fatalf("Open 快照文件: %v", err)
	}
	defer opened.Close()
	if got := captureState(t, opened); !eqState(want, got) {
		t.Fatalf("Open 快照文件状态不符:\n want=%+v\n got=%+v", want, got)
	}
}

// 拒绝覆盖已有库：RestoreFromReader 目标存在时必须报错，不能悄悄覆盖。
func TestRestoreRefusesOverwrite(t *testing.T) {
	src := newTestStore(t)
	seedTree(t, src)
	var buf bytes.Buffer
	if _, err := src.Snapshot(&buf); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	existing := filepath.Join(t.TempDir(), "occupied.db")
	if err := os.WriteFile(existing, []byte("dont touch me"), 0o600); err != nil {
		t.Fatalf("准备占位文件: %v", err)
	}
	if _, err := RestoreFromReader(existing, bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("目标已存在时 RestoreFromReader 应报错")
	}
	// 占位文件内容未被动过。
	got, _ := os.ReadFile(existing)
	if string(got) != "dont touch me" {
		t.Fatal("拒绝覆盖后原文件被破坏")
	}
}
