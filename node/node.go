// Package node 实现存储节点：接收客户端直连的对象读写，并向 master 注册与心跳。
package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

// Node 是一个存储节点实例。
type Node struct {
	dataDir           string // 对象文件根目录
	used              atomic.Int64
	masterURL         string
	advertise         string // 注册到 master 的直连地址 host:port
	nodeID            atomic.Int64
	totalBytes        int64
	heartbeatInterval time.Duration
	httpClient        *http.Client  // 与 master 交互（小请求，60s 全程超时）
	bulkClient        *http.Client  // 对等节点大对象传输（push/pull，不设全程超时）
	pulling           sync.Map      // map[uint64]struct{}: 正在拉取的 inode，去重用
	token             auth.Token    // 集群认证；空 = 兼容模式
	sec               *nodeSecurity // 独立身份+在线票据模式；nil = legacy 行为

	capMu              sync.Mutex // 容量闸：保护 inflight 与「used 结算 + 预留归还」的原子性
	usageOnce          sync.Once
	usageEpoch         string
	usageSeq           uint64
	inflight           int64 // 在飞临时写已预留的字节（rename 前的 temp 占用）
	objectLocks        [objectLockStripes]sync.Mutex
	activeObjectWrites sync.Map // object ID -> count, guarded by its object lock
}

func New(dataDir, masterURL, advertise string, totalBytes int64) *Node {
	bulkTransport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	n := &Node{
		dataDir:           dataDir,
		masterURL:         strings.TrimRight(masterURL, "/"),
		advertise:         advertise,
		totalBytes:        totalBytes,
		heartbeatInterval: 5 * time.Second,
		// 大对象传输不能设全程超时：http.Client 的 Timeout 覆盖读 body，
		// 3GB 文件按内网实际带宽可能要数分钟，60s 超时会让每次 pull/push
		// 都在半途被掐死（曾导致 inode 114 副本自 8/21 起从未同步成功）。
		// 改为只在连接/握手/响应头阶段限时，body 传输不限时。
		bulkClient: &http.Client{Transport: &auth.Transport{Fallback: bulkTransport}},
	}
	n.httpClient = &http.Client{
		Timeout:   60 * time.Second,
		Transport: &auth.Transport{Token: n.token},
	}
	n.bulkClient.Transport.(*auth.Transport).Token = n.token
	return n
}

// SetToken 设置集群认证 token：出站请求注入。空 token = 兼容模式。
// 必须在 Handler()/Register() 之前调用。
func (n *Node) SetToken(t auth.Token) {
	n.token = t
	if tr, ok := n.httpClient.Transport.(*auth.Transport); ok {
		tr.Token = t
	}
	if tr, ok := n.bulkClient.Transport.(*auth.Transport); ok {
		tr.Token = t
	}
}

// SetTLS 给出站请求（master 交互 + 对等节点传输）装上 TLS 客户端配置。
// 必须在 Register() 之前调用。cfg 为空则不启用（普通 HTTP）。
// security 模式下两端共享同一原始传输，这里解包各授权包装层设置一次即可。
func (n *Node) SetTLS(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	setTLSOnTransport(n.httpClient.Transport, cfg)
	setTLSOnTransport(n.bulkClient.Transport, cfg)
}

func setTLSOnTransport(rt http.RoundTripper, cfg *tls.Config) {
	switch t := rt.(type) {
	case *auth.Transport:
		base, ok := t.Fallback.(*http.Transport)
		if !ok {
			base = http.DefaultTransport.(*http.Transport).Clone()
			t.Fallback = base
		}
		base.TLSClientConfig = cfg
	case *deviceTransport: // security 模式：master 控制面（与 peer 共享底层）
		if base, ok := t.base.(*http.Transport); ok {
			base.TLSClientConfig = cfg
		}
	case *access.Transport: // security 模式：peer 数据面（同一底层）
		if base, ok := t.Base.(*http.Transport); ok {
			base.TLSClientConfig = cfg
		}
	}
}

// scheme 返回直连对等节点/源节点用的 URL scheme，从 masterURL 推导。
// security 模式直接复用 EnableSecurity 经 url.Parse 归一的 masterScheme（大小写
// 已归一），与 authorizePeer 的 safePeerURL scheme 复核两端判定必须一致；legacy
// 模式保持原前缀推导行为不变。
func (n *Node) scheme() string {
	if n.sec != nil {
		return n.sec.masterScheme
	}
	if strings.HasPrefix(n.masterURL, "https://") {
		return "https"
	}
	return "http"
}

// ---- 对象存储 HTTP API ----

// Handler 返回对象存储路由（整体经 auth 包装，healthz 豁免）。
// 对象以 inode ID 命名，直接落盘。
func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("PUT /objects/{id}", n.handlePut)
	mux.HandleFunc("GET /objects/{id}", n.handleGet)
	mux.HandleFunc("DELETE /objects/{id}", n.handleDelete)
	mux.HandleFunc("POST /retire/{id}", n.handleRetirement)
	mux.HandleFunc("PUT /replicate/{id}", n.handleReplicate)
	mux.HandleFunc("POST /verify/{id}", n.handleVerifyObject)
	mux.HandleFunc("POST /pull", n.handlePull)
	mux.HandleFunc("GET /admin/objects", n.handleAdminObjects)
	// 元数据备份 blob（master HA 灾备后端）：独立目录、字符串 key，与 objects/ 物理隔离。
	mux.HandleFunc("PUT /meta-backup/{key}", n.handleMetaPut)
	mux.HandleFunc("GET /meta-backup/{key}", n.handleMetaGet)
	mux.HandleFunc("DELETE /meta-backup/{key}", n.handleMetaDelete)
	mux.HandleFunc("GET /meta-backup", n.handleMetaList)
	// security 模式：默认全拒 + 在线 check 裁决（/healthz 豁免）。
	// 无 security 但 dataDir 带安全标记（重启忘带 --secure / 标记不可读）：
	// fail-closed，绝不静默退回 legacy 暴露既有数据；无标记 → 原 legacy 行为。
	if n.sec != nil {
		return n.sec.wrapHandler(mux)
	}
	if securityMarkerPresent(n.dataDir) {
		return securityRequiredHandler(mux)
	}
	return auth.Wrap(mux, n.token)
}

// handlePut 写入对象：先写临时文件再原子改名，避免读到半份数据。
func (n *Node) handlePut(w http.ResponseWriter, r *http.Request) {
	id, ok := parseObjectID(w, r)
	if !ok {
		return
	}
	checksum, err := checksumHeader(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	expectedSize := int64(-1)
	if n.nodeID.Load() > 0 && id >= types.StagingInodeBase<<8 {
		plan, err := n.replicationPlan(r.Context(), id)
		if err != nil {
			httpError(w, http.StatusConflict, err.Error())
			return
		}
		expectedSize = plan.Object.Size
		if plan.Object.ChecksumKnown {
			checksum = &plan.Object.Checksum
		}
	}
	size, _, err := n.storeVerifiedObject(id, r.Body, checksum, expectedSize)
	if err != nil {
		log.Printf("put object %d: %v", id, err)
		// 容量硬闸拒绝 ≠ 内部错误：507 让调用方能区分「节点满」与「节点坏」。
		if errors.Is(err, errCapacityExceeded) {
			httpError(w, http.StatusInsufficientStorage, err.Error())
			return
		}
		if errors.Is(err, errObjectRetired) {
			httpError(w, http.StatusConflict, err.Error())
			return
		}
		httpError(w, http.StatusInternalServerError, "write object failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"size": size})
	// 客户端直写视为"我是主副本"：成功后异步推送到其余副本节点。
	if n.nodeID.Load() != 0 {
		go n.replicateToPeers(id)
	}
}

// replicateToPeers 把指定对象推送到 master 分配的其余副本节点（带重试）。
// 目标列表实时从 master 获取，已完成的节点会被 master 过滤掉，因此重试天然幂等。
func (n *Node) replicateToPeers(objectID uint64) {
	for attempt := 1; attempt <= 3; attempt++ {
		plan, err := n.replicationPlan(context.Background(), objectID)
		if err == nil {
			var f *os.File
			f, err = n.verifiedSource(context.Background(), plan.Object)
			if err == nil {
				f.Close()
				err = n.reportStored(context.Background(), plan.Object)
			}
			if err == nil {
				for _, peer := range plan.Targets {
					if pushErr := n.pushWithPlan(context.Background(), peer.Addr, plan); pushErr != nil {
						log.Printf("replicate %d to %s: %v", objectID, peer.Addr, pushErr)
						err = pushErr
					}
				}
			}
		}
		if err == nil {
			return
		}
		log.Printf("replicate %d attempt %d: %v", objectID, attempt, err)
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
}

func (n *Node) pushObject(peerAddr string, objectID uint64) error {
	plan, err := n.replicationPlan(context.Background(), objectID)
	if err != nil {
		return err
	}
	return n.pushWithPlan(context.Background(), peerAddr, plan)
}

func (n *Node) handleReplicate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseObjectID(w, r)
	if !ok {
		return
	}
	plan, err := n.replicationPlan(r.Context(), id)
	if err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	var crc *uint32
	if plan.Object.ChecksumKnown {
		crc = &plan.Object.Checksum
	}
	size, _, err := n.storeVerifiedObject(id, r.Body, crc, plan.Object.Size)
	if err != nil {
		log.Printf("replicate object %d: %v", id, err)
		if errors.Is(err, errObjectRetired) {
			httpError(w, http.StatusConflict, err.Error())
			return
		}
		httpError(w, http.StatusUnprocessableEntity, "object does not match metadata or could not be stored")
		return
	}
	if err := n.reportStored(r.Context(), plan.Object); err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"size": size})
}

func (n *Node) handlePull(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InodeID    uint64 `json:"inode_id"`
		SourceAddr string `json:"source_addr"`
		Checksum   uint32 `json:"checksum"`
		PlanID     string `json:"plan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.InodeID == 0 || req.SourceAddr == "" {
		httpError(w, http.StatusBadRequest, "inode_id and source_addr are required")
		return
	}
	// 同一物理对象并发去重；plan_id 仅增保护计划授权下从计划源拉取。
	if _, loaded := n.pulling.LoadOrStore(req.InodeID, struct{}{}); !loaded {
		go n.pullObject(req.InodeID, req.SourceAddr, req.Checksum, req.PlanID)
	}
	w.WriteHeader(http.StatusAccepted)
}

// planPullTimeout 计划拉取的整体上界：master 控制器对 plan claim 持久化 retryAt
// （默认 5min），node 侧同步给整个计划传输（元数据 GET + 大对象 GET + 落盘 + 回执）
// 加上界，取消/过时计划不会无限占用；body 读中断由 storeVerifiedObject 清理 temp。
// 普通 pull（无 plan_id）保持原无全程超时风格。
// 注意：ctx 无法打断 fsync/目录 fsync（OS 限制），上界只约束网络与 body 读写；
// 计划拉取还会按 descriptor 的 PlanLeaseUntil 进一步收窄（见 pullObject）。
const planPullTimeout = 5 * time.Minute

// errLeaseExpired 表示计划租约缺失或已过期（descriptor/回执校验用）。
var errLeaseExpired = errors.New("plan lease is missing or expired")

// planDeadline 计划流程的总 ctx 截止：min(基础超时, 租约截止)。
// d 为零值（descriptor 未带租约）时按过期处理，fail-closed 不回退。
func planDeadline(base time.Duration, lease time.Time) (time.Time, error) {
	if lease.IsZero() || !time.Now().Before(lease) {
		return time.Time{}, errLeaseExpired
	}
	d := time.Now().Add(base)
	if lease.Before(d) {
		return lease, nil
	}
	return d, nil
}

func (n *Node) pullObject(objectID uint64, sourceAddr string, expectCRC uint32, planID ...string) {
	defer n.pulling.Delete(objectID)
	wantPlan := ""
	if len(planID) > 0 {
		wantPlan = planID[0]
	}
	ctx := context.Background()
	var cancel context.CancelFunc
	if wantPlan != "" {
		// 计划拉取：租约内完成整条链路（取 descriptor + 传输 + 落盘 + 回执）。
		// PlanLeaseUntil 过期 = claim 已被 master 回收，本侧拒绝开新网络流。
		ctx, cancel = context.WithTimeout(ctx, planPullTimeout)
	}
	if cancel != nil {
		defer cancel()
	}
	plan, err := n.replicationPlan(ctx, objectID, wantPlan)
	if err != nil {
		log.Printf("pull %d metadata: %v", objectID, err)
		return
	}
	if wantPlan != "" {
		deadline, lerr := planDeadline(planPullTimeout, plan.Object.PlanLeaseUntil)
		if lerr != nil {
			log.Printf("pull %d: %v", objectID, lerr)
			return
		}
		// 用租约收窄剩余上界（只收窄不放宽）。
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	var sourceID uint64
	for _, src := range plan.Sources {
		if src.Addr == sourceAddr && src.ID != uint64(n.nodeID.Load()) && !types.ContainsUint64(plan.Object.Suspect, src.ID) {
			sourceID = src.ID
		}
	}
	if sourceID == 0 || (expectCRC != 0 && (!plan.Object.ChecksumKnown || expectCRC != plan.Object.Checksum)) {
		log.Printf("pull %d: stale or unassigned source", objectID)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s://%s/objects/%d", n.scheme(), sourceAddr, objectID), nil)
	if err != nil {
		log.Printf("pull %d: %v", objectID, err)
		return
	}
	// 计划拉取把 plan 绑到出站票据上（security 模式换票时一并核验；
	// legacy 模式该头无消费者，原样携带）。
	if wantPlan != "" {
		req.Header.Set(access.PlanHeader, wantPlan)
	}
	resp, err := n.bulkClient.Do(req)
	if err != nil {
		log.Printf("pull %d: %v", objectID, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("pull %d: source status %d", objectID, resp.StatusCode)
		return
	}
	var crc *uint32
	if plan.Object.ChecksumKnown {
		crc = &plan.Object.Checksum
	}
	if _, _, err := n.storeVerifiedObject(objectID, resp.Body, crc, plan.Object.Size); err != nil {
		log.Printf("pull %d: %v", objectID, err)
		if errors.Is(err, errIntegrityMismatch) {
			_ = n.reportIntegrityFor(ctx, "/files/objects/suspect", plan.Object, sourceID)
		}
		return
	}
	if err := n.reportStored(ctx, plan.Object); err != nil {
		log.Printf("pull %d receipt: %v", objectID, err)
	}
}

func (n *Node) storeObject(id uint64, r io.Reader, expectCRC uint32) (int64, uint32, error) {
	var checksum *uint32
	if expectCRC != 0 {
		checksum = &expectCRC
	}
	return n.storeVerifiedObject(id, r, checksum, -1)
}

// ---- 本地容量硬闸 ----
// master 的 admission 是基于心跳/元数据/复制计划的预算；这里是数据面本地的第二道闸，
// 防普通直写与计划写并发超卖。meta-backup blob 走 metabackup.go 的独立路径、不计入
// used、也不受本闸约束（独立预算边界：并非宣称节点上一切路径都硬限）。

const objectLockStripes = 64

// objectLock 返回对象分片锁（有界条带）：同一物理对象的 store/delete 串行化，
// 避免「取旧大小 → 改名 → used 记差值」与并发 delete/store 交错产生的差值竞态。
func (n *Node) objectLock(id uint64) *sync.Mutex {
	return &n.objectLocks[id%objectLockStripes]
}

// errCapacityExceeded 表示本次写被本地容量硬闸拒绝（含非法预留值）。
// 独立类型供 HTTP 层映射 507/400，避免与网络/IO 错误混淆。
var errCapacityExceeded = errors.New("local capacity budget exceeded")

// reserveCapacity 锁内检查 used+inflight+next<=totalBytes 并预留 next 字节。
// totalBytes<=0 一律 fail-closed：无可用预算即拒写，绝不视作无限。
//
// 溢出安全：全程不做三项 int64 直接加法（大 used+大 inflight 会回绕成负数绕过
// 上限）。改用短路减法链：每个子式只会拿 total 减去已验证非负且 ≤total 的值，
// 中间结果单调收窄、始终落在 [0,total] 内，无任何回绕可能。
func (n *Node) reserveCapacity(next int64) error {
	if next < 0 {
		return fmt.Errorf("%w: negative reservation %d", errCapacityExceeded, next)
	}
	n.capMu.Lock()
	defer n.capMu.Unlock()
	// 锁内快照（非 atomic：used 只随本锁结算/增删原子路径变化，见 settleCapacity、
	// handleDelete；此处的 Load 与后续 n.inflight += next 在同一临界区，无 TOCTOU）。
	used, inflight, total := n.used.Load(), n.inflight, n.totalBytes
	// fail-closed：totalBytes 未配置（=0）或配置为负，一律拒写。
	if total <= 0 {
		return fmt.Errorf("%w: node storage capacity is not configured (total_bytes=%d)",
			errCapacityExceeded, total)
	}
	// 短路减法边界检查（不做任何三项 int64 加法，杜绝回绕绕过）：
	// 每个子式只出现 total-used / total-used-inflight 的单调收窄，且各操作数
	// 已由前面的检查保证 0<=used,inflight,next<=total，故所有中间值均在
	// [0,total] 内，无符号下溢/上溢都不可能发生。任一违例 fail-closed 拒绝。
	if used < 0 || inflight < 0 || used > total || inflight > total-used || next > total-used-inflight {
		return fmt.Errorf("%w: used %d + inflight %d + %d > total %d (or accounting invariant violated)",
			errCapacityExceeded, used, inflight, next, total)
	}
	// 通过后 used+inflight+next<=total 且各项非负，加法不回绕。
	n.inflight += next
	return nil
}

// settleCapacity 结束一次落盘：rename 成功后 committedDelta 记入 used 并全额归还预留；
// 失败时 committedDelta=0、只归还预留。锁内结算保证 used+inflight 不出现低估窗口。
func (n *Node) settleCapacity(committedDelta, reserved int64) {
	n.capMu.Lock()
	if committedDelta != 0 {
		n.used.Add(committedDelta)
	}
	n.inflight -= reserved
	n.capMu.Unlock()
}

// reservingReader 用于未知大小的写入（expectedSize==-1 的普通直写）：
// 按实际流过的字节增量预留，超预算立即让写入失败。
type reservingReader struct {
	n        *Node
	r        io.Reader
	reserved int64
}

func (rr *reservingReader) Read(p []byte) (int, error) {
	m, err := rr.r.Read(p)
	if m > 0 {
		if rerr := rr.n.reserveCapacity(int64(m)); rerr != nil {
			return 0, rerr
		}
		rr.reserved += int64(m)
	}
	return m, err
}

// reservedSoFar 返回当前已预留字节（已知大小为整笔预付；未知大小看增量累计）。
func reservedSoFar(rr *reservingReader, fixed int64) int64 {
	if rr != nil {
		return rr.reserved
	}
	return fixed
}

func (n *Node) storeVerifiedObject(id uint64, r io.Reader, expectCRC *uint32, expectSize int64) (written int64, checksum uint32, resultErr error) {
	if expectSize < -1 || expectSize == int64(^uint64(0)>>1) {
		return 0, 0, fmt.Errorf("invalid expected object size")
	}
	if err := n.beginObjectWrite(id); err != nil {
		return 0, 0, err
	}
	cleanupCertain := true
	defer func() {
		if cleanupCertain {
			n.endObjectWrite(id)
		}
	}()
	var rr *reservingReader
	reserved := int64(0)
	if expectSize >= 0 {
		if err := n.reserveCapacity(expectSize); err != nil {
			if expectCRC != nil && errors.Is(err, errCapacityExceeded) {
				matched, replayErr := n.verifyStoredReplay(id, r, expectSize, *expectCRC)
				if replayErr != nil {
					return 0, 0, replayErr
				}
				if matched {
					return expectSize, *expectCRC, nil
				}
			}
			return 0, 0, err
		}
		reserved = expectSize
	} else {
		if err := n.reserveCapacity(0); err != nil {
			return 0, 0, err
		}
		rr = &reservingReader{n: n, r: r}
		r = rr
	}
	objPath := n.objectPath(id)
	if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
		n.settleCapacity(0, reservedSoFar(rr, reserved))
		return 0, 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(objPath), ".tmp-*")
	if err != nil {
		n.settleCapacity(0, reservedSoFar(rr, reserved))
		return 0, 0, err
	}
	settled := false
	defer func() {
		if settled {
			return
		}
		// Do not expose the budget as free before the temporary bytes are gone.
		closeErr := tmp.Close()
		if errors.Is(closeErr, os.ErrClosed) {
			closeErr = nil
		}
		removeErr := os.Remove(tmp.Name())
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		if closeErr == nil && removeErr == nil {
			removeErr = syncObjectDirectories(tmp.Name())
		}
		if closeErr != nil || removeErr != nil {
			cleanupCertain = false
			resultErr = errors.Join(resultErr, closeErr, removeErr)
			return // Uncertain cleanup stays charged until restart reconciliation.
		}
		n.settleCapacity(0, reservedSoFar(rr, reserved))
	}()
	crc := types.NewCRC32C()
	var size int64
	if expectSize >= 0 {
		size, err = io.Copy(tmp, io.TeeReader(io.LimitReader(r, expectSize), crc))
		if err == nil {
			var probe [1]byte
			_, probeErr := io.ReadFull(r, probe[:])
			if probeErr == nil {
				err = fmt.Errorf("%w: body exceeds expected size %d", errIntegrityMismatch, expectSize)
			} else if probeErr != io.EOF {
				err = probeErr
			}
		}
	} else {
		size, err = io.Copy(tmp, io.TeeReader(r, crc))
	}
	if err != nil {
		return 0, 0, err
	}
	got := crc.Sum32()
	if expectSize >= 0 && size != expectSize {
		return 0, 0, fmt.Errorf("%w: size got %d want %d", errIntegrityMismatch, size, expectSize)
	}
	if expectCRC != nil && got != *expectCRC {
		return 0, 0, fmt.Errorf("%w: checksum got %08x want %08x", errIntegrityMismatch, got, *expectCRC)
	}
	if err := tmp.Sync(); err != nil {
		return 0, 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, 0, err
	}
	lock := n.objectLock(id)
	lock.Lock()
	if err := n.checkObjectFence(id); err != nil {
		lock.Unlock()
		return 0, 0, err
	}
	var oldSize int64
	if st, err := os.Stat(objPath); err == nil {
		oldSize = st.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		lock.Unlock()
		return 0, 0, err
	}
	if err := os.Rename(tmp.Name(), objPath); err != nil {
		lock.Unlock()
		return 0, 0, err
	}
	n.settleCapacity(size-oldSize, reservedSoFar(rr, reserved))
	settled = true
	lock.Unlock()
	if err := syncObjectDirectories(objPath); err != nil {
		return 0, 0, err
	}
	return size, got, nil
}

// parseChecksumHeader 读取请求里的期望 CRC32C（缺失/非法返回 0 = 不校验）。
func parseChecksumHeader(r *http.Request) uint32 {
	v := r.Header.Get(types.ChecksumHeader)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 16, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// handleAdminObjects 返回本机全部对象的 ID 和大小，跳过 .tmp-* 临时文件。
func (n *Node) handleAdminObjects(w http.ResponseWriter, _ *http.Request) {
	type objInfo struct {
		ID   uint64 `json:"id"`
		Size int64  `json:"size"`
	}
	var objects []objInfo
	objectsDir := filepath.Join(n.dataDir, "objects")
	entries, err := os.ReadDir(objectsDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []objInfo{})
			return
		}
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, bucket := range entries {
		if !bucket.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(objectsDir, bucket.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || strings.HasPrefix(f.Name(), ".tmp-") {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			id, err := strconv.ParseUint(f.Name(), 10, 64)
			if err != nil {
				continue
			}
			objects = append(objects, objInfo{ID: id, Size: info.Size()})
		}
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	writeJSON(w, http.StatusOK, objects)
}

// handleGet 读出对象内容。支持单区间 Range 请求（206 部分内容），
// 供 FUSE 客户端按偏移读取，避免拉取整个对象。
func (n *Node) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := parseObjectID(w, r)
	if !ok {
		return
	}
	f, err := os.Open(n.objectPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			httpError(w, http.StatusNotFound, "object not found")
			return
		}
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")

	if rng := r.Header.Get("Range"); rng != "" {
		start, end, ok := parseRange(rng, st.Size())
		if !ok {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", st.Size()))
			httpError(w, http.StatusRequestedRangeNotSatisfiable, "invalid range")
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, st.Size()))
		w.WriteHeader(http.StatusPartialContent)
		if _, err := f.Seek(start, io.SeekStart); err == nil {
			if _, err := io.CopyN(w, f, end-start+1); err != nil {
				log.Printf("serve object %d range: %v", id, err)
			}
		}
		return
	}
	// 整对象读：显式给出 Content-Length，客户端才能预知长度、检测截断。
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("serve object %d: %v", id, err)
	}
}

// parseRange 解析 "bytes=start-end"（end 可省略；后缀式 bytes=-N 也支持）。
// 返回闭区间 [start, end]；非法、多区间或越界返回 ok=false。
func parseRange(h string, size int64) (start, end int64, ok bool) {
	const prefix = "bytes="
	if !strings.HasPrefix(h, prefix) {
		return 0, 0, false
	}
	spec := h[len(prefix):]
	if strings.Contains(spec, ",") {
		return 0, 0, false // 多区间不支持
	}
	dash := strings.Index(spec, "-")
	if dash < 0 {
		return 0, 0, false
	}
	left, right := spec[:dash], spec[dash+1:]
	if left == "" {
		// 后缀长度：bytes=-N，取最后 N 字节（N 超过文件大小则整个文件）。
		// 用 ParseInt 而非 Sscanf：Sscanf 会接受 "10zz" 这类尾部带垃圾的输入。
		n, err := strconv.ParseInt(right, 10, 64)
		if err != nil || n <= 0 {
			return 0, 0, false
		}
		start = size - n
		if start < 0 {
			start = 0
		}
		return start, size - 1, true
	}
	start, err := strconv.ParseInt(left, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	if right == "" {
		end = size - 1
	} else if e, err := strconv.ParseInt(right, 10, 64); err != nil {
		return 0, 0, false
	} else {
		end = e
	}
	if start < 0 || end < start || start >= size {
		return 0, 0, false
	}
	if end >= size {
		end = size - 1
	}
	return start, end, true
}

// handleDelete 删除对象。与同对象 store 经分片锁串行化，保证 used 差值不错算。
func (n *Node) handleDelete(w http.ResponseWriter, r *http.Request) {
	if n.nodeID.Load() != 0 {
		httpError(w, http.StatusUpgradeRequired, "registered nodes require durable object retirement")
		return
	}
	id, ok := parseObjectID(w, r)
	if !ok {
		return
	}
	lock := n.objectLock(id)
	lock.Lock()
	objPath := n.objectPath(id)
	if st, err := os.Stat(objPath); err == nil {
		if err := os.Remove(objPath); err != nil {
			lock.Unlock()
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		n.settleCapacity(-st.Size(), 0)
	}
	lock.Unlock()
	// 不存在视为幂等成功。
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (n *Node) objectPath(id uint64) string {
	// 按 ID 前 2 位分桶，避免单目录文件过多。
	sub := fmt.Sprintf("%02x", id%256)
	return filepath.Join(n.dataDir, "objects", sub, strconv.FormatUint(id, 10))
}

func parseObjectID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		httpError(w, http.StatusBadRequest, "invalid object id")
		return 0, false
	}
	return id, true
}

// ---- 与 master 交互 ----

// 节点重加入行为说明：
// 节点重启后幂等注册复用原 ID（同一地址重复注册时 master 返回原 ID），
// 心跳恢复即回池；其上旧对象不校验、不裁剪。
// 若该节点曾被修复扫描替换（Replicas 中被新节点替代），其旧副本成为额外副本，
// GC 不删除仍在元数据 inode 集合中的对象（即文件仍存活则不删）。

// Register 向 master 注册并启动心跳循环（阻塞直到首次注册成功）。
// security 模式下注册即设备挑战换会话，并启动到期前主动续期循环。
func (n *Node) Register() error {
	if err := n.registerOnce(); err != nil {
		return err
	}
	if n.sec != nil {
		go n.sec.renewLoop()
	}
	go n.heartbeatLoop()
	return nil
}

func (n *Node) registerOnce() error {
	// security 模式：设备挑战注册/续期（master 报 unknown node 走到这里时
	// 强制重建会话，重新绑定 identity→addr）。已持有未临期会话时为 no-op。
	if n.sec != nil {
		return n.sec.establishSession(context.Background(), n.sec.hasSession())
	}
	body, _ := json.Marshal(map[string]any{
		"addr":        n.advertise,
		"total_bytes": n.totalBytes,
	})
	resp, err := n.httpClient.Post(n.masterURL+"/nodes/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("register: status %d", resp.StatusCode)
	}
	var out struct {
		ID uint64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("register: decode: %w", err)
	}
	n.nodeID.Store(int64(out.ID))
	log.Printf("node registered: id=%d addr=%s", out.ID, n.advertise)
	return nil
}

// heartbeatLoop 定期心跳；master 重启后重新注册。
func (n *Node) heartbeatLoop() {
	t := time.NewTicker(n.heartbeatInterval)
	defer t.Stop()
	for range t.C {
		if err := n.heartbeatOnce(); err != nil {
			if errors.Is(err, errUnknownNode) {
				// master 丢了注册信息（比如 master 数据被清空），重新注册。
				log.Printf("heartbeat: unknown node, re-registering: %v", err)
				if rerr := n.registerOnce(); rerr != nil {
					log.Printf("re-register failed: %v", rerr)
				}
				continue
			}
			log.Printf("heartbeat: %v", err)
		}
	}
}

var errUnknownNode = errors.New("master: node not found")

func (n *Node) usageSnapshot() *types.NodeUsage {
	n.usageOnce.Do(func() {
		var epoch [16]byte
		if _, err := rand.Read(epoch[:]); err == nil {
			n.usageEpoch = hex.EncodeToString(epoch[:])
		}
	})
	n.capMu.Lock()
	defer n.capMu.Unlock()
	if n.usageEpoch == "" || n.usageSeq == ^uint64(0) {
		return nil
	}
	n.usageSeq++
	return &types.NodeUsage{Epoch: n.usageEpoch, Sequence: n.usageSeq, UsedBytes: n.used.Load()}
}

func (n *Node) heartbeatOnce() error {
	usage := n.usageSnapshot()
	used := n.used.Load()
	if usage != nil {
		used = usage.UsedBytes
	}
	body, _ := json.Marshal(map[string]any{
		"node_id":    n.nodeID.Load(),
		"used_bytes": used,
		"usage":      usage,
	})
	resp, err := n.httpClient.Post(n.masterURL+"/nodes/heartbeat", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errUnknownNode
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat: status %d", resp.StatusCode)
	}
	return nil
}

// InitUsedBytes 启动时统计已有数据量（对象目录遍历一次），并清理上次崩溃残留的临时文件。
func (n *Node) InitUsedBytes() error {
	if err := n.cleanupTmpFiles(); err != nil {
		return err
	}
	if err := n.reconcileFences(); err != nil {
		return err
	}
	var total int64
	err := filepath.WalkDir(filepath.Join(n.dataDir, "objects"), func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // objects 目录还不存在
			}
			return err
		}
		if !d.IsDir() && !strings.HasPrefix(d.Name(), ".tmp-") {
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() < 0 || total > int64(^uint64(0)>>1)-info.Size() {
				return errors.New("invalid stored object during usage reconciliation")
			}
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
	n.used.Store(total)
	return nil
}

// cleanupTmpFiles 删除对象目录下全部 .tmp-* 残留（写一半的半成品，重启后已无意义）。
func (n *Node) cleanupTmpFiles() error {
	objectsDir := filepath.Join(n.dataDir, "objects")
	entries, err := os.ReadDir(objectsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 尚无数据
		}
		return err
	}
	removed := 0
	for _, bucket := range entries {
		if !bucket.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(objectsDir, bucket.Name()))
		if err != nil {
			return err
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasPrefix(f.Name(), ".tmp-") {
				continue
			}
			path := filepath.Join(objectsDir, bucket.Name(), f.Name())
			if err := os.Remove(path); err != nil {
				return err
			}
			if err := syncObjectDirectories(path); err != nil {
				return err
			}
			removed++
		}
	}
	if removed > 0 {
		log.Printf("启动清理：删除 %d 个残留临时文件", removed)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ---- 测试辅助（导出仅供集成测试使用） ----

// SetNodeIDForTest 直接设置节点 ID（绕过注册流程，用于测试）。
func (n *Node) SetNodeIDForTest(id uint64) { n.nodeID.Store(int64(id)) }

// NodeIDForTest 返回节点 ID（供测试发送心跳用）。
func (n *Node) NodeIDForTest() uint64 { return uint64(n.nodeID.Load()) }

// DataDirForTest 返回数据目录路径。
func (n *Node) DataDirForTest() string { return n.dataDir }

// objectPathForTest 返回对象的磁盘路径（供测试直接检查文件内容）。
func (n *Node) objectPathForTest(id uint64) string { return n.objectPath(id) }

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
