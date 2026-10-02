package meta

import (
	"testing"
	"time"

	"atoll/pkg/types"
)

// TestOpResultStoreAndSweep 操作结果幂等表（v2-3a）：写入→读回→TTL 清理。
// op 结果是"客户端重试去重"的凭据：同 op_id 重试必须返回原结果而非重复执行。
func TestOpResultStoreAndSweep(t *testing.T) {
	s := newTestStore(t)

	in := types.Inode{ID: 42, ParentID: 1, Name: "f.bin", Type: types.TypeFile, Size: 7, Generation: 1}
	if err := s.PutOpResult("op-a", "small", in); err != nil {
		t.Fatalf("PutOpResult: %v", err)
	}

	rec, ok, err := s.GetOpResult("op-a")
	if err != nil || !ok {
		t.Fatalf("GetOpResult: ok=%v err=%v", ok, err)
	}
	if rec.Kind != "small" || rec.Inode.ID != 42 || rec.Inode.Name != "f.bin" {
		t.Fatalf("读回不符: %+v", rec)
	}
	// 未知的 op_id。
	if _, ok, _ := s.GetOpResult("op-none"); ok {
		t.Fatal("未知 op_id 不应命中")
	}

	// TTL 清理：老记录删除，新记录保留。
	if err := s.PutOpResultAt("op-old", "commit", in, time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatalf("PutOpResultAt: %v", err)
	}
	removed, err := s.SweepOpsOlderThan(24 * time.Hour)
	if err != nil {
		t.Fatalf("SweepOpsOlderThan: %v", err)
	}
	if removed != 1 {
		t.Fatalf("应清理 1 条过期 op, got %d", removed)
	}
	if _, ok, _ := s.GetOpResult("op-old"); ok {
		t.Fatal("过期 op 应已删除")
	}
	if _, ok, _ := s.GetOpResult("op-a"); !ok {
		t.Fatal("未过期 op 应保留")
	}
}
