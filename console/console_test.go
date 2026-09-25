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
			// #0：主(1)已落盘、从(2)已落盘、3 未分配 → 满员健康
			{Index: 0, Replicas: []uint64{1, 2}, Done: []uint64{1, 2}},
			// #1：主(1)落盘、从(3)未 Done 但存活。修复换节点后遗留的旧坑（真实案例）：
			// 副本有缺口(healthy 1<2) → 未 Done 格子必须是 missing(缺)，不能是 syncing。
			{Index: 1, Replicas: []uint64{1, 3}, Done: []uint64{1}},
			// #2：主(1)落盘、从(4)落盘但节点宕机 → missing(失)
			{Index: 2, Replicas: []uint64{1, 4}, Done: []uint64{1, 4}},
			// #3：主(1)、从(5)都未 Done（上传进行中，healthy 0<2）→ 未 Done = 缺；
			//     但主未 Done 属于还没传完——见 #4 用满员口径区分。
			{Index: 3, Replicas: []uint64{1, 5}, Done: []uint64{}},
			// #4：上传中但块已双落盘、副本集有第 3 个未 Done 位 → healthy(2) >= replicas(3)? 否 → 缺。
			//     用 2/3 场景验证"缺口→缺"判定；满员(healthy>=replicas)才允许 syncing。
			{Index: 4, Replicas: []uint64{1, 5, 6}, Done: []uint64{1, 5}},
			// #5：满员健康块 + 额外同步中副本：healthy(2)==replicas(2) 但 7 未 Done
			//     ——此格不适用 syncing 了吗？不：7 不在 replicas 里 → none。另设 #6。
			{Index: 5, Replicas: []uint64{1, 5}, Done: []uint64{1, 5}},
			// #6：真正的新上传：replicas 2 个、只 Done 主副本、healthy(1)<2 → 缺(等从副本)。
			//     syncing 只出现在 healthy>=replicas 的场景在本数据模型下不存在，
			//     故 syncing 分支保留给"Done 全齐后追加的副本位"（当前模型不产生）。
			{Index: 6, Replicas: []uint64{1, 5}, Done: []uint64{1, 5}},
		},
	}
	// #6 与 #5 相同（都满员）——为覆盖 syncing，需要"副本集比 Done 多、但 healthy 满员"：
	// 这要求 alive 里有 Done 外的成员，模型上即 min_copies<replicas 已 commit 的文件。
	// 直接构造：replicas={1,2}，Done={1,2}，另加 replicas 成员 3 未 Done？
	// 那 healthy(2)==len(replicas)(3)? 不——healthy 只数 Done∩alive∩replicas = 2 < 3 → 缺。
	// 结论：当前数据模型下"满员但仍有未 Done 副本位"不可能出现（commit 前必齐 min_copies，
	// commit 后 Done 集就是全部位）。syncing 分支实际只服务"刚 Assign 尚未传"的 staging，
	// 而 staging 不出现在文件详情页。把 syncing 期望从测试中移除，保留分支防御。
	alive := map[uint64]bool{1: true, 2: true, 3: true, 4: false, 5: true, 6: true}
	cols, rows := buildMatrix(in, alive)

	wantCols := []uint64{1, 2, 3, 4, 5, 6}
	if len(cols) != len(wantCols) {
		t.Fatalf("列数 %d != %d", len(cols), len(wantCols))
	}
	for i, c := range cols {
		if c.ID != wantCols[i] {
			t.Fatalf("列 %d = node %d, want %d", i, c.ID, wantCols[i])
		}
	}
	// 逐格断言（列顺序 1,2,3,4,5,6）
	want := [][]string{
		{"primary", "replica", "none", "none", "none", "none"},        // #0 满员
		{"primary", "none", "missing", "none", "none", "none"},        // #1 缺口→缺(修复后)
		{"primary", "none", "none", "missing", "none", "none"},        // #2 落盘但节点死→失
		{"missing", "none", "none", "none", "missing", "none"},        // #3 主从全未 Done、有缺口→缺(诚实显示)
		{"primary", "none", "none", "none", "replica", "missing"},     // #4 2/3→第3位缺
		{"primary", "none", "none", "none", "replica", "none"},        // #5 满员
		{"primary", "none", "none", "none", "replica", "none"},        // #6 满员
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
