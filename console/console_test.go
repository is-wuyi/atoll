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

// 账号管理：list 排序、最后一个 admin 锁死保护、改角色、删除持久化。
func TestUserManagement(t *testing.T) {
	dir := t.TempDir()
	s, err := openUserStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Add("root", "password1", RoleAdmin))
	must(s.Add("alice", "password1", RoleReadonly))
	must(s.Add("bob", "password1", RoleReadonly))

	// list 按用户名升序。
	list := s.list()
	if len(list) != 3 || list[0].Username != "alice" || list[2].Username != "root" {
		t.Fatalf("list 排序不符: %+v", list)
	}

	// 唯一 admin 不能删。
	if err := s.remove("root"); err != errLastAdmin {
		t.Fatalf("删最后一个 admin 应拒绝, got %v", err)
	}
	// 唯一 admin 不能降级。
	if err := s.setRole("root", RoleReadonly); err != errLastAdmin {
		t.Fatalf("降级最后一个 admin 应拒绝, got %v", err)
	}

	// 升 alice 为 admin 后，root 可删（不再是唯一 admin）。
	must(s.setRole("alice", RoleAdmin))
	must(s.remove("root"))
	if _, ok := s.verify("root", "password1"); ok {
		t.Error("root 删除后不应能登录")
	}

	// 删不存在账号。
	if err := s.remove("ghost"); err != errUserNotFound {
		t.Fatalf("删不存在账号应报 not found, got %v", err)
	}

	// 持久化：重开后 alice=admin、bob=readonly、无 root。
	s2, err := openUserStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Role{}
	for _, u := range s2.list() {
		got[u.Username] = u.Role
	}
	if len(got) != 2 || got["alice"] != RoleAdmin || got["bob"] != RoleReadonly {
		t.Fatalf("持久化后状态不符: %+v", got)
	}
}

// validUsername 边界。
func TestValidUsername(t *testing.T) {
	ok := []string{"ab", "user_1", "a.b-c", "ABC123"}
	bad := []string{"a", "", "has space", "汉字", "a/b", string(make([]byte, 33))}
	for _, u := range ok {
		if !validUsername(u) {
			t.Errorf("%q 应合法", u)
		}
	}
	for _, u := range bad {
		if validUsername(u) {
			t.Errorf("%q 应非法", u)
		}
	}
}
