package meta

import (
	"bytes"
	"path/filepath"
	"testing"

	"atoll/pkg/types"
)

// WAL 核心保证：快照(含快照时刻的 WAL) + 其后帧重放 = 原库当前状态。
// 这是"master 换机后从集群恢复"的正确性根基。
func TestSnapshotPlusWALReplay(t *testing.T) {
	src := newTestStore(t)

	// 第一批写：进入快照。
	docs, _ := src.CreateDir(RootID, "docs")
	src.CreateFile(docs.ID, "a.txt", []uint64{1, 2})

	// 取快照 + 记下快照时刻的 WAL seq。
	snapSeq, err := src.WALSeq()
	if err != nil {
		t.Fatalf("WALSeq: %v", err)
	}
	var snap bytes.Buffer
	if _, err := src.Snapshot(&snap); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// 第二批写：快照之后发生，只存在于 WAL。
	src.CreateDir(RootID, "media")
	f, _ := src.CreateFile(docs.ID, "b.txt", []uint64{2, 3})
	src.UpdateFileSize(f.ID, 999, 0xabcd)
	src.Rename(f.ID, "b2.txt")
	src.DeleteFile(f.ID) // 建了又删——重放后应确实不存在

	want := captureFullState(t, src)

	// 恢复：把快照落到新库，再重放快照之后的帧。
	dst := filepath.Join(t.TempDir(), "recovered.db")
	rs, err := RestoreFromReader(dst, bytes.NewReader(snap.Bytes()))
	if err != nil {
		t.Fatalf("RestoreFromReader: %v", err)
	}
	defer rs.Close()

	// 恢复库的 WAL seq 应等于快照时刻(快照包含了 wal 桶)。
	rsSeq, _ := rs.WALSeq()
	if rsSeq != snapSeq {
		t.Fatalf("恢复库 WAL seq %d != 快照时刻 %d", rsSeq, snapSeq)
	}

	// 从源库取快照之后的帧，重放进恢复库。
	frames, err := src.FramesSince(snapSeq)
	if err != nil {
		t.Fatalf("FramesSince: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("快照后应有增量帧")
	}
	if err := rs.ApplyFrames(frames); err != nil {
		t.Fatalf("ApplyFrames: %v", err)
	}

	got := captureFullState(t, rs)
	if !fullStateEq(want, got) {
		t.Fatalf("快照+WAL 重放后状态不符:\n want=%+v\n got =%+v", want, got)
	}

	// 重放后 seq 追平源库。
	srcSeq, _ := src.WALSeq()
	gotSeq, _ := rs.WALSeq()
	if gotSeq != srcSeq {
		t.Fatalf("重放后 WAL seq %d != 源库 %d", gotSeq, srcSeq)
	}
}

// 重放幂等/接续：把已含部分帧的库再喂一次全量帧，不应报错也不应改变结果。
func TestApplyFramesIdempotentPrefix(t *testing.T) {
	src := newTestStore(t)
	src.CreateDir(RootID, "a")
	src.CreateDir(RootID, "b")
	src.CreateDir(RootID, "c")

	// 全新空库从 seq 0 开始重放全部帧。
	dst := filepath.Join(t.TempDir(), "fresh.db")
	fresh, err := Open(dst)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fresh.Close()

	all, _ := src.FramesSince(0)
	if err := fresh.ApplyFrames(all); err != nil {
		t.Fatalf("首次 ApplyFrames: %v", err)
	}
	// 再喂一次同样的帧：seq 都 <= 当前，全部跳过，不报错。
	if err := fresh.ApplyFrames(all); err != nil {
		t.Fatalf("重复 ApplyFrames 应幂等: %v", err)
	}
	kids, _ := fresh.ListChildren(RootID)
	if len(kids) != 3 {
		t.Fatalf("重放后根子项 %d != 3", len(kids))
	}
}

// 帧缺口必须被拒绝：跳号重放会破坏一致性。
func TestApplyFramesRejectsGap(t *testing.T) {
	src := newTestStore(t)
	src.CreateDir(RootID, "a")
	src.CreateDir(RootID, "b")
	frames, _ := src.FramesSince(0)
	if len(frames) < 2 {
		t.Fatalf("需要 >=2 帧，got %d", len(frames))
	}

	dst := filepath.Join(t.TempDir(), "gap.db")
	fresh, _ := Open(dst)
	defer fresh.Close()
	// 只喂第二帧（跳过第一帧）→ 缺口，应报错。
	if err := fresh.ApplyFrames(frames[1:]); err == nil {
		t.Fatal("跳号重放应报错")
	}
}

// TruncateWALThrough 清理已固化帧后，FramesSince 不再返回它们。
func TestTruncateWAL(t *testing.T) {
	src := newTestStore(t)
	src.CreateDir(RootID, "a")
	src.CreateDir(RootID, "b")
	mid, _ := src.WALSeq()
	src.CreateDir(RootID, "c")
	last, _ := src.WALSeq()

	if err := src.TruncateWALThrough(mid); err != nil {
		t.Fatalf("TruncateWALThrough: %v", err)
	}
	// seq<=mid 的帧应没了；FramesSince(0) 只剩 mid 之后的。
	frames, _ := src.FramesSince(0)
	for _, f := range frames {
		if f.Seq <= mid {
			t.Fatalf("截断后仍有 seq %d <= %d", f.Seq, mid)
		}
	}
	if len(frames) != int(last-mid) {
		t.Fatalf("截断后剩余帧数 %d != %d", len(frames), last-mid)
	}
}

// ---- 全量状态快照（比 snapshot_test 的 captureState 更全，含目录树遍历）----

type fullState struct {
	paths map[string]nodeShape // 路径 → 形状
}

type nodeShape struct {
	isDir bool
	size  int64
	sum   uint32
	reps  string
}

func captureFullState(t *testing.T, s *Store) fullState {
	t.Helper()
	fs := fullState{paths: map[string]nodeShape{}}
	var walk func(dirID uint64, prefix string)
	walk = func(dirID uint64, prefix string) {
		kids, err := s.ListChildren(dirID)
		if err != nil {
			t.Fatalf("ListChildren %d: %v", dirID, err)
		}
		for _, k := range kids {
			p := prefix + "/" + k.Name
			sh := nodeShape{isDir: k.Type == types.TypeDir}
			if !sh.isDir {
				sh.size = k.Size
				sh.sum = k.Checksum
				sh.reps = u64sToStr(k.Replicas)
			}
			fs.paths[p] = sh
			if sh.isDir {
				walk(k.ID, p)
			}
		}
	}
	walk(RootID, "")
	return fs
}

func fullStateEq(a, b fullState) bool {
	if len(a.paths) != len(b.paths) {
		return false
	}
	for p, sa := range a.paths {
		sb, ok := b.paths[p]
		if !ok || sa != sb {
			return false
		}
	}
	return true
}

func u64sToStr(xs []uint64) string {
	var b bytes.Buffer
	for _, x := range xs {
		b.WriteByte(byte(x))
	}
	return b.String()
}
