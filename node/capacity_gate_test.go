package node

// 本地容量硬闸测试：used+inflight+next<=totalBytes 锁内检查、fail-closed、
// 失败归还预留、覆盖写双份空间、同对象 store/delete 分片锁序列化。
// 注意：账面口径 = 对象数据（objects/ 目录，不含 .tmp-*），meta-backup 是独立预算边界。

import (
	"bytes"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"atoll/pkg/types"
)

// inflightForTest 读取当前在飞预留字节。
func (n *Node) inflightForTest() int64 {
	n.capMu.Lock()
	defer n.capMu.Unlock()
	return n.inflight
}

// objectsDirBytes 统计 objects 目录实际数据占用（跳过 .tmp-* 临时文件）。
func objectsDirBytes(t *testing.T, n *Node) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(filepath.Join(n.DataDirForTest(), "objects"), func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !d.IsDir() && !strings.HasPrefix(d.Name(), ".tmp-") {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk objects dir: %v", err)
	}
	return total
}

// 预算耗尽：拒绝、不落盘、无泄漏；剩余预算恰好可用。
func TestCapacityGateRejectsOverBudget(t *testing.T) {
	n := New(t.TempDir(), "", "", 100)
	if _, _, err := n.storeObject(1, bytes.NewReader(make([]byte, 60)), 0); err != nil {
		t.Fatalf("60B 应成功: %v", err)
	}
	if n.used.Load() != 60 {
		t.Fatalf("used = %d, want 60", n.used.Load())
	}
	if _, _, err := n.storeObject(2, bytes.NewReader(make([]byte, 50)), 0); err == nil {
		t.Fatal("60+50 超出 100 预算应拒绝")
	}
	if n.used.Load() != 60 {
		t.Fatalf("拒绝后 used = %d, want 60", n.used.Load())
	}
	if n.inflightForTest() != 0 {
		t.Fatalf("失败的写必须归还预留, inflight = %d", n.inflightForTest())
	}
	if _, err := os.Stat(n.objectPathForTest(2)); !os.IsNotExist(err) {
		t.Fatal("拒绝的写不应留下对象文件")
	}
	// 剩余 40 恰好用满。
	if _, _, err := n.storeObject(3, bytes.NewReader(make([]byte, 40)), 0); err != nil {
		t.Fatalf("40B 应成功: %v", err)
	}
	if n.used.Load() != 100 {
		t.Fatalf("used = %d, want 100", n.used.Load())
	}
	if _, _, err := n.storeObject(4, bytes.NewReader([]byte("x")), 0); err == nil {
		t.Fatal("满载后 1B 也应拒绝")
	}
	if got := objectsDirBytes(t, n); got != 100 {
		t.Fatalf("磁盘实占 = %d, 账面 = %d, 应一致", got, n.used.Load())
	}
}

// 并发写总量不超卖：40B×4 打满 100B 预算，恰好 2 成 2 败（预留锁内串行）。
func TestCapacityGateConcurrentWritesBounded(t *testing.T) {
	n := New(t.TempDir(), "", "", 100)
	const writers = 4
	errs := make([]error, writers)
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = n.storeObject(uint64(10+i), bytes.NewReader(make([]byte, 40)), 0)
		}(i)
	}
	wg.Wait()
	ok, fail := 0, 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else {
			fail++
		}
	}
	if ok != 2 || fail != 2 {
		t.Fatalf("40B×4 on 100B: ok=%d fail=%d, want 2/2（并发总量不得超卖）", ok, fail)
	}
	if n.used.Load() != 80 {
		t.Fatalf("used = %d, want 80", n.used.Load())
	}
	if n.inflightForTest() != 0 {
		t.Fatalf("全部完成后 inflight = %d, want 0", n.inflightForTest())
	}
	if got := objectsDirBytes(t, n); got != 80 {
		t.Fatalf("磁盘实占 = %d, 账面 = %d, 应一致", got, n.used.Load())
	}
}

// 失败（校验和不符 / 中途断流）必须全额归还预留，预算可立即复用。
func TestCapacityGateFailedWriteReleasesReservation(t *testing.T) {
	n := New(t.TempDir(), "", "", 100)
	data := bytes.Repeat([]byte{0x5a}, 60)
	if _, _, err := n.storeObject(1, bytes.NewReader(data), types.CRC32C(data)^0xff); err == nil {
		t.Fatal("校验和不符应失败")
	}
	if n.inflightForTest() != 0 {
		t.Fatalf("校验和失败后 inflight = %d, want 0", n.inflightForTest())
	}
	if n.used.Load() != 0 {
		t.Fatalf("失败不应改变 used, got %d", n.used.Load())
	}
	if _, _, err := n.storeObject(2, errReader{}, 0); err == nil {
		t.Fatal("中途断流应失败")
	}
	if n.inflightForTest() != 0 {
		t.Fatalf("断流后 inflight = %d, want 0", n.inflightForTest())
	}
	// 预算全额可用（若 60B 泄漏，90B 将无法写入）。
	if _, _, err := n.storeObject(3, bytes.NewReader(bytes.Repeat([]byte{0xa5}, 90)), 0); err != nil {
		t.Fatalf("归还后 90B 应成功: %v", err)
	}
	if n.used.Load() != 90 {
		t.Fatalf("used = %d, want 90", n.used.Load())
	}
}

// 覆盖写需要双份空间（旧对象 + 临时文件并存）：预算不足必须拒绝且旧对象原样；
// 预算足够时按差值结算。
func TestCapacityGateOverwriteNeedsDoubleSpace(t *testing.T) {
	n := New(t.TempDir(), "", "", 100)
	old := bytes.Repeat([]byte{0x11}, 60)
	if _, _, err := n.storeObject(1, bytes.NewReader(old), 0); err != nil {
		t.Fatal(err)
	}
	fresh := bytes.Repeat([]byte{0x22}, 60)
	if _, _, err := n.storeObject(1, bytes.NewReader(fresh), 0); err == nil {
		t.Fatal("60B 覆盖写需 120B 双份空间，超预算应拒绝")
	}
	got, err := os.ReadFile(n.objectPathForTest(1))
	if err != nil || !bytes.Equal(got, old) {
		t.Fatalf("失败覆盖不得影响旧对象: %v", err)
	}
	if n.used.Load() != 60 || n.inflightForTest() != 0 {
		t.Fatalf("失败覆盖后 used=%d inflight=%d, want 60/0", n.used.Load(), n.inflightForTest())
	}
	// 30B 覆盖：60+30=90 ≤ 100 → 成功，used 按差值变 30。
	small := bytes.Repeat([]byte{0x33}, 30)
	if _, _, err := n.storeObject(1, bytes.NewReader(small), 0); err != nil {
		t.Fatalf("30B 覆盖应成功: %v", err)
	}
	if n.used.Load() != 30 {
		t.Fatalf("覆盖后 used = %d, want 30", n.used.Load())
	}
	if got := objectsDirBytes(t, n); got != 30 {
		t.Fatalf("磁盘实占 = %d, 账面 = %d, 应一致", got, n.used.Load())
	}
}

// totalBytes<=0 fail-closed：无预算即拒写，绝不视作无限/legacy 兼容。
func TestCapacityGateZeroCapacityFailClosed(t *testing.T) {
	for _, total := range []int64{0, -1} {
		n := New(t.TempDir(), "", "", total)
		if _, _, err := n.storeObject(1, bytes.NewReader([]byte("x")), 0); err == nil {
			t.Fatalf("total=%d: 无预算必须 fail-closed 拒写", total)
		}
		if _, err := os.Stat(n.objectPathForTest(1)); !os.IsNotExist(err) {
			t.Fatalf("total=%d: 拒写不应留下对象文件", total)
		}
		if n.inflightForTest() != 0 {
			t.Fatalf("total=%d: 拒写不应留下预留", total)
		}
	}
}

// 同对象 store/delete 经分片锁串行化：交错压力后账面必须与磁盘一致且归零。
func TestStripedLockSerializesSameObjectStoreAndDelete(t *testing.T) {
	n := New(t.TempDir(), "", "", 1<<20)
	data := bytes.Repeat([]byte{0x77}, 64)
	del := func() {
		req := httptest.NewRequest(http.MethodDelete, "/objects/7", nil)
		req.SetPathValue("id", "7") // 直连 handler 调用需手动填充路径参数
		rec := httptest.NewRecorder()
		n.handleDelete(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("delete = %d, want 200", rec.Code)
		}
	}
	for round := 0; round < 50; round++ {
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); _, _, _ = n.storeObject(7, bytes.NewReader(data), 0) }()
		go func() { defer wg.Done(); _, _, _ = n.storeObject(7, bytes.NewReader(data), 0) }()
		go func() { defer wg.Done(); del() }()
		wg.Wait()
		if u, disk := n.used.Load(), objectsDirBytes(t, n); u != disk {
			t.Fatalf("round %d: 账面 used=%d 与磁盘 %d 不一致", round, u, disk)
		}
	}
	// 收尾：无论交错结果如何，再删一次应幂等归零。
	del()
	if u := n.used.Load(); u != 0 {
		t.Fatalf("最终 used = %d, want 0", u)
	}
	if n.inflightForTest() != 0 {
		t.Fatalf("最终 inflight = %d, want 0", n.inflightForTest())
	}
}

// 覆盖写并发的差值结算：不同尺寸的并发 store 对同一对象交错时，最终账面必须
// 与磁盘实际内容一致（分片锁只覆盖 commit 段：旧大小统计→改名→结算在同一临界区）。
func TestStripedLockConcurrentOverwriteDeltasStayConsistent(t *testing.T) {
	n := New(t.TempDir(), "", "", 1<<20)
	sizes := []int64{10, 60, 120, 7, 33, 45, 90, 16}
	var wg sync.WaitGroup
	for i, size := range sizes {
		wg.Add(1)
		go func(id int, size int64) {
			defer wg.Done()
			_, _, _ = n.storeVerifiedObject(55, bytes.NewReader(make([]byte, size)), nil, size)
		}(i, size)
	}
	// 同时并发 delete 同一对象。
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodDelete, "/objects/55", nil)
			req.SetPathValue("id", "55")
			rec := httptest.NewRecorder()
			n.handleDelete(rec, req)
		}()
	}
	wg.Wait()
	// 交错全部落定后：账面必须精确等于磁盘。
	want := objectsDirBytes(t, n)
	if u := n.used.Load(); u != want {
		t.Fatalf("并发覆盖后账面 used=%d 与磁盘 %d 不一致", u, want)
	}
	if n.inflightForTest() != 0 {
		t.Fatalf("inflight = %d, want 0", n.inflightForTest())
	}
}

// reserveCapacity 溢出/边界：near-int64max 的账面与请求组合不得因 int64 回绕被放行。
func TestReserveCapacityRejectsOverflowingSums(t *testing.T) {
	const maxI64 = int64(^uint64(0) >> 1)

	// 直接三值相加会回绕成负数的经典场景：
	// used=MaxInt64, inflight=1, next=1 → 和溢出；短路减法必须拒绝。
	n := New(t.TempDir(), "", "", maxI64)
	n.used.Store(maxI64)
	n.capMu.Lock()
	n.inflight = 1
	n.capMu.Unlock()
	if err := n.reserveCapacity(1); err == nil {
		t.Fatal("used=MaxInt64 时任何新预留都必须拒绝（三值相加会回绕）")
	}
	// inflight 违例时 next=MaxInt64（回绕场景的另一半）也必须拒绝。
	if err := n.reserveCapacity(maxI64); err == nil {
		t.Fatal("int64max 请求不得因加法回绕被放行")
	}
	if n.inflightForTest() != 1 {
		t.Fatalf("拒绝不得改变 inflight, got %d", n.inflightForTest())
	}

	// 账面快到顶但合法：used=inflight=2^62-1，total=MaxInt64。
	// 直接三值相加 used+inflight+1 在 int64 内回绕成负数；短路减法仍须正确放行
	// 恰好可用的 1B、拒绝超出的部分。
	n2 := New(t.TempDir(), "", "", maxI64)
	half := int64(1)<<62 - 1 // 4611686018427387903
	n2.used.Store(half)
	n2.capMu.Lock()
	n2.inflight = half
	n2.capMu.Unlock()
	// headroom = 1：最后 1B 可预留。
	if err := n2.reserveCapacity(1); err != nil {
		t.Fatalf("headroom=1 时最后 1B 应可预留: %v", err)
	}
	// 满载后下一步必须拒绝。
	if err := n2.reserveCapacity(1); err == nil {
		t.Fatal("满载后 1B 也必须拒绝")
	}
	// 归还全部预留回到初始状态。
	n2.settleCapacity(0, half+1)
	if n2.inflightForTest() != 0 {
		t.Fatalf("归还后 inflight = %d, want 0", n2.inflightForTest())
	}
	// 归还后 1B 重新可用。
	if err := n2.reserveCapacity(1); err != nil {
		t.Fatalf("归还后 1B 应可重新预留: %v", err)
	}
	n2.settleCapacity(0, 1)

	// used>total 的不变式违例（账面已坏）：fail-closed。
	n3 := New(t.TempDir(), "", "", 10)
	n3.used.Store(11)
	if err := n3.reserveCapacity(0); err == nil {
		t.Fatal("used>total 时必须 fail-closed 拒绝")
	}

	// 负值预留（调用方 bug 防御）：typed err 拒绝。
	if err := n3.reserveCapacity(-1); err == nil || !errors.Is(err, errCapacityExceeded) {
		t.Fatalf("负值预留必须被拒且带 typed err: %v", err)
	}
}

// 已知大小写的多读探针：超长 body 的第 expectSize+1 字节不落盘、不额外占用预算
// ——预算恰好用满时「恰好等长」的请求可成功，超长请求失败且不留任何占用。
func TestKnownSizeOverlongProbeDoesNotExceedBudget(t *testing.T) {
	data := []byte("0123456789")
	crc := types.CRC32C(data)
	// 90B 预算恰好等于对象大小：成功（预留=expectSize 即上限，不再需要 +1）。
	n := New(t.TempDir(), "", "", 90)
	if _, _, err := n.storeVerifiedObject(1, bytes.NewReader(data), &crc, int64(len(data))); err != nil {
		t.Fatalf("10B 已知大小应成功: %v", err)
	}
	if u := n.used.Load(); u != int64(len(data)) {
		t.Fatalf("used = %d, want %d", u, len(data))
	}
	// 10B 预算：12B 超长 body 必须被探针拒绝（若实现需要 +1 预算或落盘超读字节，
	// 这里要么放行超卖、要么把「恰好」也误拒——两个方向都拦住）。
	n2 := New(t.TempDir(), "", "", 10)
	if _, _, err := n2.storeVerifiedObject(3, bytes.NewReader([]byte("0123456789AB")), &crc, 10); err == nil {
		t.Fatal("10B 预算下 12B 超长 body 必须被探针拒绝")
	} else if !errors.Is(err, errIntegrityMismatch) {
		t.Fatalf("超长应报 integrity mismatch: %v", err)
	}
	// 拒绝后账面干净，且恰好 10B 仍可写入（探针没有偷偷预留 +1）。
	if u := n2.used.Load(); u != 0 {
		t.Fatalf("拒绝后 used = %d, want 0", u)
	}
	if n2.inflightForTest() != 0 {
		t.Fatalf("拒绝后 inflight = %d, want 0", n2.inflightForTest())
	}
	if _, _, err := n2.storeVerifiedObject(4, bytes.NewReader(data), &crc, 10); err != nil {
		t.Fatalf("拒绝后恰好 10B 应仍可写入: %v", err)
	}
}

// 容量闸拒绝的直写映射 507 Insufficient Storage；配置缺失仍 500 之外的路径不回归。
func TestPutCapacityExceededMapsTo507(t *testing.T) {
	n, ts := newTestNode(t)
	n.totalBytes = 10 // 收紧到 10B
	if _, _, err := n.storeObject(1, bytes.NewReader([]byte("0123456789")), 0); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/2", bytes.NewReader([]byte("overflow-me")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("超预算 PUT = %d, want 507", resp.StatusCode)
	}
	if objectExists(ts.URL, 2) {
		t.Fatal("拒绝的 PUT 不应落盘")
	}
	if u := n.used.Load(); u != 10 {
		t.Fatalf("used = %d, want 10", u)
	}
	if n.inflightForTest() != 0 {
		t.Fatalf("inflight = %d, want 0", n.inflightForTest())
	}
}
