package mount

// ---- 分块读句柄：整块校验 + per-Mount 有界缓存 + 副本轮换 ----
//
// 完整性策略（阶段 A chunked 部分）：
//   - 块表带已知 Checksum（ChecksumKnown 或 ≠0）：数据交给 FUSE 前必须整块校验——
//     不带 Range 的整块 GET，长度恰为 c.Size 且 CRC32C 匹配才采纳；不符（位翻转/
//     截断/超长）即上报 suspect 并轮换下一副本。绝不用部分 Range 数据的 CRC 与
//     整块 checksum 比较。
//   - 旧数据 Checksum==0 且未标 ChecksumKnown（legacy）：不凭空造校验，保持 Range
//     读取但收紧验证——206 必须 Content-Range 逐字节等于 "bytes start-end/<c.Size>"，
//     200 仅当 start==0 且请求覆盖完整块；短读/超长一律拒绝换副本。
//   - Suspect 副本（master 标记待修）殿后仅作兜底：健康副本优先，绝不首选可疑数据源。
//
// 内存有界（per-Mount 总预算，不随句柄数放大）：
//   - 已校验整块缓存是 Mount 级共享 LRU（mountChunkCache），字节预算可注入
//     （默认 128MiB ≈ 2 个默认 64MiB 块）；单块超预算则不缓存（本次调用用完即弃）。
//   - 整块校验读取另受 Mount 级 semaphore（chunkVerifyInFlight 个在飞）限流：
//     每个在飞校验至多缓冲 ChunkSize+1 字节，跨句柄合计有界。
//   - 并发首读（含跨句柄读同一块）经缓存内 singleflight 合并成一次 GET；
//     失败不缓存，等待者重新竞争或随 ctx 退出。
//
// 取消语义：ctx 贯穿 semaphore 等待、singleflight 等待与 HTTP 请求
// （NewRequestWithContext），取消后读返回 EINTR、semaphore 许可由 defer 归还。
//
// suspect 上报：快照 Open 时的 FileID（ino）与 generation，按 (nodeID, objID) 去重，
// 异步 5s 超时打 /files/chunks/suspect；绝不回退旧 /files/corrupt 删除通道。

import (
	"container/list"
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"syscall"
	"time"

	"atoll/pkg/types"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// chunkVerifyInFlight 是每 Mount 同时进行的整块校验读取数上限：每个在飞校验至多
// 缓冲 ChunkSize+1（默认 64MiB+1）字节，2 个在飞 ⇒ 校验飞行内存 ≤ ~128MiB。
const chunkVerifyInFlight = 2

// defaultChunkCacheBytes 是 Mount 级已校验整块缓存的默认字节预算
// （≈ 2 个默认 64MiB 块）；测试可注入更小预算（m.chunkCache.maxBytes）。
const defaultChunkCacheBytes int64 = 128 << 20

// chunkVerifyTimeout 按整块字节数给单次校验 GET 的 deadline：30s 基线 + 每 512KiB
// 加 1s，封顶 150s（与 client.ioTimeout 同刻度）——64MiB 整取若沿用 30s 全程超时，
// 不足 ~2MiB/s 的副本会被反复误杀。整块校验客户端（verifyHTTP）无全程 Timeout，
// deadline 全部来自这里注入的 ctx。
var chunkVerifyTimeoutFn = chunkVerifyTimeout

func chunkVerifyTimeout(size int64) time.Duration {
	t := 30*time.Second + time.Duration(size/(512*1024))*time.Second
	if t > 150*time.Second {
		t = 150 * time.Second
	}
	return t
}

// chunkedReadHandle 分块文件的读句柄。
// offset → (块 index, 块内偏移) 的换算由块表顺序推累计基址；
// 每个块的候选节点：Done 副本优先、组内随机打散（读时轮换故障转移）。
type chunkedReadHandle struct {
	ino        uint64 // 逻辑 FileID（suspect 上报身份，与物理寻址分离）
	size       int64
	generation uint64 // Open 时快照的内容版本：suspect 按 (FileID, generation) 比对
	// content 是 Open 时快照的内容清单：aead 块解密需要 ContentVersion.ID 作
	// 记录 AAD 的内容身份；nil = 旧数据（无清单，块必然是 plain）。
	content *types.ContentVersion
	chunks  []types.ChunkInfo
	addr    map[uint64]string // 节点 ID → 地址（lookup 的地址表）
	next    map[int]int       // 块 index → 下一个候选起点（读时记忆可用节点）
	http    *http.Client
	scheme  string
	m       *Mount // nil 兼容直接构造句柄的测试：无上报、无共享缓存与全局限流

	mu       sync.Mutex
	reported map[[2]uint64]bool // (nodeID, chunkObjID) → 已上报过，去重
}

var _ fs.FileReader = (*chunkedReadHandle)(nil)

// ---- Mount 级共享缓存：已校验整块 LRU + singleflight ----

// chunkCacheKey 绑定身份+size+CRC：同一对象 ID 只可能有一种内容，但坏元数据可能
// 给出同 objID 不同 size/CRC 的矛盾表项——四元组不匹配的句柄命中不了他人校验过的
// 条目，各自独立验证。isChunk 隔离 ID 命名空间：v1 派生块 ID (ino<<8|index) 与旧
// 整文件对象 ID（=ino）数值可重叠。
type chunkCacheKey struct {
	obj     uint64
	size    int64
	crc     uint32
	isChunk bool
}

type chunkCacheEntry struct {
	key  chunkCacheKey
	data []byte
}

// chunkLoadFlight 是 singleflight 的在飞标记：等待者挂在 done 上。
type chunkLoadFlight struct {
	done chan struct{}
}

// mountChunkCache 是 Mount 级共享的已校验整块缓存：全局字节预算有界（maxBytes
// 可注入），LRU 淘汰；并发加载同一块合并为一次读取（singleflight，跨句柄生效）。
type mountChunkCache struct {
	maxBytes int64
	mu       sync.Mutex
	curBytes int64
	order    *list.List // *chunkCacheEntry，front = 最近使用
	entries  map[chunkCacheKey]*list.Element
	loading  map[chunkCacheKey]*chunkLoadFlight
}

func newMountChunkCache(maxBytes int64) *mountChunkCache {
	return &mountChunkCache{
		maxBytes: maxBytes,
		order:    list.New(),
		entries:  make(map[chunkCacheKey]*list.Element),
		loading:  make(map[chunkCacheKey]*chunkLoadFlight),
	}
}

// get 返回命中条目并提升 LRU 位次（无 permit 快路径：数据已在预算内计费）。
func (cc *mountChunkCache) get(key chunkCacheKey) ([]byte, bool) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if el, ok := cc.entries[key]; ok {
		cc.order.MoveToFront(el)
		return el.Value.(*chunkCacheEntry).data, true
	}
	return nil, false
}

// load 返回已校验整块数据：命中缓存；否则 singleflight 合并为一次 fetch
// （整块校验读取）。失败不缓存，等待者重新竞争加载或随 ctx 退出。
// 命中检查与 loading 注册必须持同一把锁：分离的话，G1 在 get 未命中到注册之间，
// G2 可能已完成整轮加载——G1 既看不到条目也看不到在飞者，会发起重复 fetch。
// fetch 内不取校验 permit：permit 由调用方管理，须覆盖 fetch 与 copy-out。
func (cc *mountChunkCache) load(ctx context.Context, key chunkCacheKey,
	fetch func(context.Context) ([]byte, syscall.Errno)) ([]byte, syscall.Errno) {
	for {
		cc.mu.Lock()
		if el, ok := cc.entries[key]; ok {
			cc.order.MoveToFront(el)
			data := el.Value.(*chunkCacheEntry).data
			cc.mu.Unlock()
			return data, 0
		}
		if pending := cc.loading[key]; pending != nil {
			cc.mu.Unlock()
			select {
			case <-pending.done:
				continue
			case <-ctx.Done():
				return nil, syscall.EINTR
			}
		}
		pending := &chunkLoadFlight{done: make(chan struct{})}
		cc.loading[key] = pending
		cc.mu.Unlock()

		data, errno := fetch(ctx)

		cc.mu.Lock()
		delete(cc.loading, key)
		close(pending.done)
		if errno == 0 {
			cc.insertLocked(key, data)
		}
		cc.mu.Unlock()
		return data, errno
	}
}

// insertLocked 按预算插入（LRU 淘汰到预算内）；计费按 cap——校验缓冲实分配
// size+1，按 len 计费会低估驻留。单块超预算不缓存；同键已存在保留先到副本。
func (cc *mountChunkCache) insertLocked(key chunkCacheKey, data []byte) {
	sz := int64(cap(data))
	if sz > cc.maxBytes {
		return
	}
	if el, ok := cc.entries[key]; ok {
		cc.order.MoveToFront(el)
		return
	}
	cc.entries[key] = cc.order.PushFront(&chunkCacheEntry{key: key, data: data})
	cc.curBytes += sz
	for cc.curBytes > cc.maxBytes {
		back := cc.order.Back()
		if back == nil {
			break
		}
		victim := cc.order.Remove(back).(*chunkCacheEntry)
		delete(cc.entries, victim.key)
		cc.curBytes -= int64(cap(victim.data))
	}
}

// ---- 句柄实现 ----

// plainChunkData 返回整块已验证的最终数据：plain 块直接返回密文缓冲（物理即
// 逻辑）；aead 块解密全部记录返回明文。解密失败不返回部分明文。
func (ch *chunkedReadHandle) plainChunkData(ctx context.Context, c types.ChunkInfo) ([]byte, syscall.Errno) {
	data, errno := ch.fetchChunkWholeVerified(ctx, c)
	if errno != 0 {
		return nil, errno
	}
	if types.ChunkEncoding(c) != types.AeadRecordEncoding {
		return data, 0
	}
	plain, err := ch.m.client.DecryptChunk(ctx, ch.contentManifest(c), c, data)
	if err != nil {
		log.Printf("aead chunk %d inode %d decrypt: %v", c.Index, ch.ino, err)
		return nil, syscall.EIO
	}
	return plain, 0
}

// contentManifest 以 Open 快照构造解密用的 inode 视图（ContentVersion.ID 即
// 记录 AAD 的内容身份）。
func (ch *chunkedReadHandle) contentManifest(c types.ChunkInfo) types.Inode {
	return types.Inode{ID: ch.ino, Generation: ch.generation, Content: ch.content}
}

// loadChunk 返回整块已校验的最终交付数据（Mount 共享缓存 + singleflight）：
// plain 块即密文整块；aead 块为解密后的明文。release 必须在调用方 copy-out
// 完成后调用：校验 permit 覆盖 fetch 与 copy-out，已校验数据在被消费前始终
// 计入在飞预算；命中缓存快路径的 release 为 no-op（数据已计费）。无 Mount
// （直接构造句柄的测试）permit 为 no-op。
func (ch *chunkedReadHandle) loadChunk(ctx context.Context, c types.ChunkInfo) ([]byte, syscall.Errno, func()) {
	key := chunkCacheKey{obj: types.ChunkObjID(c, ch.ino), size: c.Size, crc: c.Checksum, isChunk: true}
	if ch.m == nil || ch.m.chunkCache == nil {
		release, errno := ch.acquireVerify(ctx)
		if errno != 0 {
			return nil, errno, nil
		}
		plain, errno := ch.plainChunkData(ctx, c)
		if errno != 0 {
			release()
			return nil, errno, nil
		}
		return plain, 0, release
	}
	if data, ok := ch.m.chunkCache.get(key); ok {
		// 缓存里存的是已验证的最终交付字节：plain 即密文，aead 已解密成明文。
		return data, 0, func() {}
	}
	release, errno := ch.acquireVerify(ctx)
	if errno != 0 {
		return nil, errno, nil
	}
	// 缓存层存"已验证的最终交付字节"：plain 块即密文本身；aead 块存解密后
	// 明文（密钥/记录 AAD 由句柄快照固定，同键即同明文）。
	data, errno := ch.m.chunkCache.load(ctx, key, func(ctx context.Context) ([]byte, syscall.Errno) {
		data, errno := ch.fetchChunkWholeVerified(ctx, c)
		if errno != 0 {
			return nil, errno
		}
		if types.ChunkEncoding(c) != types.AeadRecordEncoding {
			return data, 0
		}
		plain, err := ch.m.client.DecryptChunk(ctx, ch.contentManifest(c), c, data)
		if err != nil {
			log.Printf("aead chunk %d inode %d decrypt: %v", c.Index, ch.ino, err)
			return nil, syscall.EIO
		}
		return plain, 0
	})
	if errno != 0 {
		release()
		return nil, errno, nil
	}
	return data, 0, release
}

// chunkCandidates 拆分块的读取候选：healthy 为健康副本（Done 在前、组内随机打散做
// 负载均衡），suspects 为 master 标记待修的副本。suspect 段固定殿后兜底，不参与
// 轮转——否则 next 会把后续请求直接带进 suspect 段。
func chunkCandidates(c types.ChunkInfo) (healthy, suspects []uint64) {
	var primary, pending []uint64
	done := len(c.Done) > 0
	for _, id := range c.Replicas {
		if types.ContainsUint64(c.Suspect, id) {
			suspects = append(suspects, id)
		} else if done && types.ContainsUint64(c.Done, id) {
			primary = append(primary, id)
		} else {
			pending = append(pending, id)
		}
	}
	rand.Shuffle(len(primary), func(i, j int) { primary[i], primary[j] = primary[j], primary[i] })
	healthy = append(append(healthy, primary...), pending...)
	return healthy, suspects
}

// reportChunkSuspect 上报坏块副本：(nodeID, objID) 去重，异步 + 5s 超时，不阻塞读路径。
// 只走 suspect 通道（master 按 tuple CAS 标记待修复，不删对象）——绝不回退旧
// /files/corrupt 删除接口，块表 Checksum 缺失的误报不能变成唯一副本丢失。
func (ch *chunkedReadHandle) reportChunkSuspect(nodeID uint64, c types.ChunkInfo) {
	if ch.m == nil || nodeID == 0 {
		return
	}
	key := [2]uint64{nodeID, types.ChunkObjID(c, ch.ino)}
	ch.mu.Lock()
	if ch.reported[key] {
		ch.mu.Unlock()
		return
	}
	if ch.reported == nil {
		ch.reported = make(map[[2]uint64]bool)
	}
	ch.reported[key] = true
	ch.mu.Unlock()

	// 上报用 Open 时快照的 FileID + generation（chunked 文件校验和在块表，
	// inode 的 Size/Checksum 不参与块级版本比对）：master 按完整 tuple CAS，
	// 旧版本读者的上报不会撤销新版本的块副本，也不会删除任何对象。
	in := types.Inode{ID: ch.ino, Generation: ch.generation}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := ch.m.client.ReportChunkSuspect(ctx, in, c, nodeID); err != nil {
			log.Printf("report chunk suspect inode %d chunk %d node %d: %v", in.ID, c.Index, nodeID, err)
		}
	}()
}

// acquireVerify 获取整块校验读取许可（Mount 级 semaphore，限制在飞校验内存）；
// 返回释放函数。nil Mount（测试直接构造句柄）不限流。
func (ch *chunkedReadHandle) acquireVerify(ctx context.Context) (func(), syscall.Errno) {
	return ch.m.acquireVerify(ctx)
}

// acquireVerify 是 Mount 级在飞校验闸门：每个在飞校验至多缓冲 ChunkSize+1 字节，
// chunkVerifyInFlight 个在飞合计有界。ctx 取消时返回 EINTR、不占许可。
func (m *Mount) acquireVerify(ctx context.Context) (func(), syscall.Errno) {
	if m == nil || m.chunkVerifySem == nil {
		return func() {}, 0
	}
	select {
	case m.chunkVerifySem <- struct{}{}:
		return func() { <-m.chunkVerifySem }, 0
	case <-ctx.Done():
		return nil, syscall.EINTR
	}
}

// fetchChunkWholeVerified 整块 GET + 完整校验：不带 Range 请求整块对象，长度恰为
// c.Size 且 CRC32C == c.Checksum 才采纳；不符（CRC/长度）上报 suspect 并轮换下一
// 副本。缓冲循环外分配一次复用于所有候选；坏块大小在任何 GET/alloc 前拒绝。
// 轮转只在健康段内：next 是健康候选起点，suspect 段固定殿后，健康全败才依序试。
func (ch *chunkedReadHandle) fetchChunkWholeVerified(ctx context.Context, c types.ChunkInfo) ([]byte, syscall.Errno) {
	if c.Size <= 0 || c.Size > chunkStoredBound(ch.chunks) {
		return nil, syscall.EIO // 坏元数据：make(c.Size+1) 前拒绝，防按块表无限分配
	}
	// 整块 GET 用无全程 Timeout 的共享 Transport 客户端，deadline 按字节数缩放
	// （挂连接/响应头超时由 Transport 承担）；Range 路径仍走 30s 全程的 ch.http。
	httpClient := ch.http
	if ch.m != nil && ch.m.verifyHTTP != nil {
		httpClient = ch.m.verifyHTTP
	}
	objID := types.ChunkObjID(c, ch.ino)
	healthy, suspects := chunkCandidates(c)
	ch.mu.Lock()
	next := ch.next[c.Index]
	ch.mu.Unlock()
	if len(healthy) > 0 {
		next %= len(healthy)
	}
	buf := make([]byte, c.Size+1) // 多读 1 字节探测超长；一次分配复用于所有候选
	try := func(id uint64) ([]byte, bool) {
		a, ok := ch.addr[id]
		if !ok || a == "" {
			return nil, false
		}
		attemptCtx, cancel := context.WithTimeout(ctx, chunkVerifyTimeoutFn(c.Size))
		defer cancel()
		req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet,
			fmt.Sprintf("%s://%s/objects/%d", ch.scheme, a, objID), nil)
		if err != nil {
			return nil, false
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, false
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, false
		}
		n, err := io.ReadFull(resp.Body, buf)
		resp.Body.Close()
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, false // 传输中断不等于损坏：不误报
		}
		if int64(n) != c.Size || types.CRC32C(buf[:n]) != c.Checksum {
			ch.reportChunkSuspect(id, c)
			return nil, false
		}
		return buf[:n], true
	}

	for i := range healthy {
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		if data, ok := try(healthy[(next+i)%len(healthy)]); ok {
			ch.rememberChunkNext(c, (next+i+1)%len(healthy))
			return data, 0
		}
	}
	for _, id := range suspects { // 健康全败才试；成功不改动健康段轮转基准
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		if data, ok := try(id); ok {
			return data, 0
		}
	}
	if ctx.Err() != nil {
		return nil, syscall.EINTR
	}
	return nil, syscall.EIO
}

// rememberChunkNext 记录块的健康候选轮转起点。
func (ch *chunkedReadHandle) rememberChunkNext(c types.ChunkInfo, next int) {
	ch.mu.Lock()
	if ch.next == nil {
		ch.next = make(map[int]int)
	}
	ch.next[c.Index] = next
	ch.mu.Unlock()
}

// fetchChunkRangeStrict legacy 块（无已知 CRC，Range 读取不整块校验）的读取，
// 验证收紧：
//   - 206：Content-Range 必须逐字节等于 "bytes start-end/<c.Size>"；
//   - 200：仅当 start==0 且请求覆盖完整块（want == c.Size）时接受；
//   - 短读/超长拒绝并上报 suspect；状态/头不符仅轮换副本。
//     轮转只在健康段内（next 为健康候选起点），suspect 段固定殿后兜底。
func (ch *chunkedReadHandle) fetchChunkRangeStrict(ctx context.Context, c types.ChunkInfo, start, end int64) ([]byte, syscall.Errno) {
	if c.Size <= 0 || c.Size > chunkStoredBound(ch.chunks) {
		return nil, syscall.EIO // 坏元数据：alloc/GET 前拒绝
	}
	want := end - start + 1
	objID := types.ChunkObjID(c, ch.ino)
	healthy, suspects := chunkCandidates(c)
	ch.mu.Lock()
	next := ch.next[c.Index]
	ch.mu.Unlock()
	if len(healthy) > 0 {
		next %= len(healthy)
	}
	buf := make([]byte, want+1) // 多读 1 字节探测超长；复用于所有候选
	try := func(id uint64) ([]byte, bool) {
		a, ok := ch.addr[id]
		if !ok || a == "" {
			return nil, false
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s://%s/objects/%d", ch.scheme, a, objID), nil)
		if err != nil {
			return nil, false
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
		resp, err := ch.http.Do(req)
		if err != nil {
			return nil, false
		}
		validRange := resp.StatusCode == http.StatusPartialContent &&
			resp.Header.Get("Content-Range") == fmt.Sprintf("bytes %d-%d/%d", start, end, c.Size)
		wholeObject := resp.StatusCode == http.StatusOK && start == 0 && want == c.Size
		if !validRange && !wholeObject {
			resp.Body.Close()
			return nil, false
		}
		n, err := io.ReadFull(resp.Body, buf)
		resp.Body.Close()
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, false // 传输中断不等于损坏：不误报
		}
		if int64(n) != want {
			ch.reportChunkSuspect(id, c) // 干净短读（EOF 族）或超长（读满 want+1）：疑似损坏
			return nil, false
		}
		return buf[:want], true
	}

	for i := range healthy {
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		if data, ok := try(healthy[(next+i)%len(healthy)]); ok {
			ch.rememberChunkNext(c, (next+i+1)%len(healthy))
			return data, 0
		}
	}
	for _, id := range suspects { // 健康全败才试；成功不改动健康段轮转基准
		if ctx.Err() != nil {
			return nil, syscall.EINTR
		}
		if data, ok := try(id); ok {
			return data, 0
		}
	}
	if ctx.Err() != nil {
		return nil, syscall.EINTR
	}
	return nil, syscall.EIO
}

// Read 读取 [off, off+len(dest))：按块表顺序切分；带 checksum 的块经整块校验 +
// 共享缓存，legacy 块走严格 Range。负偏移/空 dest/EOF/元数据不一致均无 panic，
// 校验不通过的字节绝不出现在返回值里。
func (ch *chunkedReadHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off < 0 || ch.size < 0 {
		return nil, syscall.EINVAL
	}
	if off >= ch.size || len(dest) == 0 {
		return fuse.ReadResultData(nil), 0 // EOF / 空读
	}
	if ctx.Err() != nil {
		return nil, syscall.EINTR
	}
	count := min(int64(len(dest)), ch.size-off)
	end := off + count - 1

	// 定位起始块：块表按 Index 升序，块基址 = Σ前序块逻辑长度。逐块先验大小：
	// 上界保证 base 累加 ≤ MaxChunks×(ChunkSize+记录开销) 永不溢出，且超大/0/
	// 负长在任何 GET/alloc 前被拒（fetch 侧另有同款防御兜底）。aead 块的物理
	// Size 含记录开销，几何由逻辑长度与编码共同约束。
	bound := chunkStoredBound(ch.chunks)
	idx := len(ch.chunks)
	var base int64
	for i, c := range ch.chunks {
		logical := types.ChunkLogicalSize(c)
		if logical <= 0 || logical > types.ChunkSize || c.Size <= 0 || c.Size > bound {
			return nil, syscall.EIO
		}
		if off < base+logical {
			idx = i
			break
		}
		base += logical
	}
	if idx >= len(ch.chunks) {
		return nil, syscall.EIO // 块表覆盖不住文件大小：元数据不一致
	}
	out := make([]byte, 0, count)
	cur := off
	for cur <= end && idx < len(ch.chunks) {
		c := ch.chunks[idx]
		logical := types.ChunkLogicalSize(c)
		chunkStart := cur - base              // 块内偏移（cur 是绝对偏移）
		chunkEnd := min(end-base, logical-1)   // 同为块内偏移：end 绝对 → 相对
		n := chunkEnd - chunkStart + 1
		if logical <= 0 || logical > types.ChunkSize || c.Size <= 0 || c.Size > bound || chunkStart < 0 || chunkEnd < chunkStart || chunkStart >= logical {
			return nil, syscall.EIO // 块表损坏：拒绝而不是 panic / 读出错误字节
		}
		if c.ChecksumKnown || c.Checksum != 0 {
			whole, errno, release := ch.loadChunk(ctx, c)
			if errno != 0 {
				return nil, errno
			}
			if int64(len(whole)) != logical {
				release()
				return nil, syscall.EIO // 防御：交付数据必须等于逻辑长度
			}
			out = append(out, whole[chunkStart:chunkEnd+1]...)
			release() // copy-out 完成：校验 permit 归还
		} else {
			part, errno := ch.fetchChunkRangeStrict(ctx, c, chunkStart, chunkEnd)
			if errno != 0 {
				return nil, errno
			}
			if int64(len(part)) != n {
				return nil, syscall.EIO
			}
			out = append(out, part...)
		}
		cur += n
		base += logical
		idx++
	}
	if cur <= end {
		return nil, syscall.EIO // 块表提前耗尽：元数据与块表不符
	}
	return fuse.ReadResultData(out), 0
}

// chunkStoredBound 给出一个块表内物理对象长度的安全上界：plain 块 = ChunkSize，
// aead 块 = ChunkSize + 最大记录开销（64MiB 明文至多 1025 条记录）。
func chunkStoredBound(chunks []types.ChunkInfo) int64 {
	bound := types.ChunkSize
	for _, c := range chunks {
		if types.ChunkEncoding(c) != types.AeadRecordEncoding {
			continue
		}
		if want, err := types.AeadStoredSize(types.ChunkSize); err == nil && want > bound {
			bound = want
		}
		break
	}
	return bound
}
