package console

import (
	"path/filepath"
	"testing"

	"atoll/pkg/types"
)

// buildMatrix：主/从/同步/缺失/未分配 五种格子状态都要正确。
func TestBuildMatrix(t *testing.T) {
	in := types.Inode{
		Chunked: true,
		Chunks: []types.ChunkInfo{
			// #0：主(1)已落盘、从(2)已落盘、3 未分配
			{Index: 0, Replicas: []uint64{1, 2}, Done: []uint64{1, 2}},
			// #1：主(1)已落盘、从(3)在副本集但未 Done 且存活 → syncing
			{Index: 1, Replicas: []uint64{1, 3}, Done: []uint64{1}},
			// #2：主(1)已落盘、从(4)已落盘但节点宕机 → missing
			{Index: 2, Replicas: []uint64{1, 4}, Done: []uint64{1, 4}},
		},
	}
	alive := map[uint64]bool{1: true, 2: true, 3: true, 4: false}
	cols, rows := buildMatrix(in, alive)

	// 列 = {1,2,3,4} 并集，升序
	wantCols := []uint64{1, 2, 3, 4}
	if len(cols) != 4 {
		t.Fatalf("列数 %d != 4", len(cols))
	}
	for i, c := range cols {
		if c.ID != wantCols[i] {
			t.Fatalf("列 %d = node %d, want %d", i, c.ID, wantCols[i])
		}
	}
	// 逐格断言（列顺序 1,2,3,4）
	want := [][]string{
		{"primary", "replica", "none", "none"},    // #0
		{"primary", "none", "syncing", "none"},     // #1
		{"primary", "none", "none", "missing"},     // #2
	}
	for r, row := range rows {
		for c, cell := range row.Cells {
			if cell.Class != want[r][c] {
				t.Errorf("#%d 列node%d = %q, want %q", row.Index, cols[c].ID, cell.Class, want[r][c])
			}
		}
	}
}

// redundancy：分块文件取最大副本数，任一块降级则整文件降级。
func TestRedundancy(t *testing.T) {
	in := types.Inode{
		Chunked: true,
		Chunks: []types.ChunkInfo{
			{Replicas: []uint64{1, 2}, Done: []uint64{1, 2}}, // 健康
			{Replicas: []uint64{1, 2}, Done: []uint64{1}},    // 降级（少一个）
		},
	}
	alive := map[uint64]bool{1: true, 2: true}
	n, degraded := redundancy(in, alive)
	if n != 2 || !degraded {
		t.Fatalf("got n=%d degraded=%v, want 2 true", n, degraded)
	}
}

// 用户存储：bcrypt 校验、重复拒绝、持久化。
func TestUserStore(t *testing.T) {
	dir := t.TempDir()
	s, err := openUserStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add("admin", "pw123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("admin", "pw123", RoleAdmin); err != errUserExists {
		t.Fatalf("重复添加应拒绝: %v", err)
	}
	if _, ok := s.verify("admin", "pw123"); !ok {
		t.Error("正确密码应通过")
	}
	if _, ok := s.verify("admin", "wrong"); ok {
		t.Error("错误密码应拒绝")
	}
	if _, ok := s.verify("nobody", "pw123"); ok {
		t.Error("不存在用户应拒绝")
	}
	// 非法角色拒绝
	if err := s.Add("x", "y", "superuser"); err == nil {
		t.Error("非法角色应拒绝")
	}
	// 重新打开，账号仍在（持久化）
	s2, err := openUserStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Count() != 1 {
		t.Fatalf("重开后账号数 %d != 1", s2.Count())
	}
	_ = filepath.Join // 保留 import
}
