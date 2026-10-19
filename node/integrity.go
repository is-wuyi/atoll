package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/types"
)

var errIntegrityMismatch = errors.New("object integrity mismatch")

// aeadChunkObjectLimit 是 aead 块对象的物理上限：密文比明文多 33B/64KiB 记录，
// 末块明文 ≤64MiB-1 时密文 ≤ ChunkSize + 528B；再留余量防奇数几何。
// plain 块仍以 ChunkSize 为限。
func aeadChunkObjectLimit() int64 {
	return types.ChunkSize + (types.ChunkSize/types.AeadRecordPlaintext+1)*types.AeadRecordOverhead
}

// verifyTimeout 约束控制面 POST /verify 的完整流程（master 元数据 + 本地全量 CRC + 回执）。
// verify 由 master 异步探测触发，超时后 master 会按自身节奏重试；本批仅加上界，
// 不重写其生命周期。ctx 无法打断 fsync/目录 fsync（OS 限制），上界只约束网络与
// 本地读；计划 verify 还会按 descriptor 的 PlanLeaseUntil 进一步收窄（见 handleVerifyObject）。
const verifyTimeout = 60 * time.Second

func checksumHeader(r *http.Request) (*uint32, error) {
	value := r.Header.Get(types.ChecksumHeader)
	if value == "" {
		return nil, nil
	}
	crc, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid checksum header")
	}
	v := uint32(crc)
	return &v, nil
}

// replicationPlan 向 master 请求对象的复制计划。
// 可选 planID 用于仅增保护计划：非空时必须在 query 里带 plan_id（正确 urlencode），
// 且 master 响应的 Object.PlanID 必须与之完全一致，缺失/未知协议一律报错、不回退；
// 不带 planID 的原流程保持不变，但响应若意外携带 PlanID 也拒绝，防止计划上下文串味。
func (n *Node) replicationPlan(ctx context.Context, objectID uint64, planID ...string) (types.ReplicationPlan, error) {
	var plan types.ReplicationPlan
	if n.nodeID.Load() <= 0 {
		return plan, fmt.Errorf("node is not registered")
	}
	wantPlan := ""
	if len(planID) > 0 {
		wantPlan = planID[0]
	}
	q := url.Values{}
	q.Set("object_id", strconv.FormatUint(objectID, 10))
	q.Set("node_id", strconv.FormatUint(uint64(n.nodeID.Load()), 10))
	if wantPlan != "" {
		q.Set("plan_id", wantPlan)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.masterURL+"/files/replication?"+q.Encode(), nil)
	if err != nil {
		return plan, err
	}
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return plan, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return plan, fmt.Errorf("replication metadata: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&plan); err != nil {
		return plan, err
	}
	d := plan.Object
	if !d.Chunked && d.ObjectID < types.StagingInodeBase<<8 && d.Size == 0 && !d.ChecksumKnown {
		return plan, fmt.Errorf("legacy content is not committed")
	}
	if wantPlan != "" {
		// 计划取数必须拿到同一个计划；且回执只能是内容校验过的 verified，
		// 未记录校验和的对象不能以 length-only 方式进入计划流程。
		if d.PlanID != wantPlan {
			return plan, fmt.Errorf("master answered object %d with a different or missing plan", objectID)
		}
		if !d.ChecksumKnown {
			return plan, fmt.Errorf("plan %s object %d has no recorded checksum", wantPlan, objectID)
		}
		// 计划流程严格要求租约：nonzero 且未过期。缺失/过期 = claim 已被 master
		// 回收或从未 claim，fail-closed 拒绝，不回退到无租约行为。
		if _, lerr := planDeadline(planPullTimeout, d.PlanLeaseUntil); lerr != nil {
			return plan, fmt.Errorf("plan %s object %d: %w", wantPlan, objectID, lerr)
		}
	} else if d.PlanID != "" {
		return plan, fmt.Errorf("unexpected plan context in replication metadata for object %d", objectID)
	}
	if plan.Protocol != types.IntegrityProtocol || d.ObjectID != objectID || d.Size < 0 || d.Size == int64(^uint64(0)>>1) ||
		!types.ContainsUint64(d.Replicas, uint64(n.nodeID.Load())) ||
		(d.Chunked && (d.Size <= 0 || d.Size > aeadChunkObjectLimit() || d.ChunkIndex < 0)) {
		return plan, fmt.Errorf("invalid or unsupported replication metadata")
	}
	for _, nd := range append(append([]types.NodeInfo(nil), plan.Targets...), plan.Sources...) {
		if nd.ID == 0 || nd.Addr == "" || !types.ContainsUint64(d.Replicas, nd.ID) {
			return plan, fmt.Errorf("unassigned replication peer")
		}
	}
	return plan, nil
}

func (n *Node) reportIntegrity(ctx context.Context, path string, d types.ObjectIntegrity) error {
	return n.reportIntegrityFor(ctx, path, d, uint64(n.nodeID.Load()))
}

func (n *Node) reportIntegrityFor(ctx context.Context, path string, d types.ObjectIntegrity, nodeID uint64) error {
	var usage *types.NodeUsage
	if path == "/files/replicated/verified" && nodeID == uint64(n.nodeID.Load()) {
		usage = n.usageSnapshot()
	}
	body, err := json.Marshal(struct {
		Object types.ObjectIntegrity `json:"object"`
		NodeID uint64                `json:"node_id"`
		Usage  *types.NodeUsage      `json:"usage,omitempty"`
	}{d, nodeID, usage})
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.masterURL+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := n.httpClient.Do(req)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("integrity receipt: status %d", resp.StatusCode)
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return last
			}
		} else {
			last = err
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
			}
		}
	}
	return last
}

func (n *Node) reportStored(ctx context.Context, d types.ObjectIntegrity) error {
	if d.PlanID != "" && !d.ChecksumKnown {
		// 计划回执必须是内容校验过的 verified；计划对象不允许降级成 length-only present。
		return fmt.Errorf("plan %s cannot produce a length-only receipt", d.PlanID)
	}
	path := "/files/replicated/verified"
	if !d.ChecksumKnown {
		path = "/files/replicated/present"
	}
	return n.reportIntegrity(ctx, path, d)
}

// The same open file is verified and sent, so an atomic replacement cannot switch the source between those steps.
func (n *Node) verifiedSource(ctx context.Context, d types.ObjectIntegrity) (*os.File, error) {
	f, err := os.Open(n.objectPath(d.ObjectID))
	if err != nil {
		return nil, err
	}
	h := types.NewCRC32C()
	size, err := io.Copy(h, io.LimitReader(&contextReader{ctx: ctx, r: f}, d.Size+1))
	if err != nil || size != d.Size || (d.ChecksumKnown && h.Sum32() != d.Checksum) {
		f.Close()
		if err == nil {
			err = fmt.Errorf("object %d content does not match master metadata", d.ObjectID)
			_ = n.reportIntegrity(ctx, "/files/objects/suspect", d)
		}
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func (n *Node) pushWithPlan(ctx context.Context, peerAddr string, plan types.ReplicationPlan) error {
	assigned := false
	for _, peer := range plan.Targets {
		if peer.Addr == peerAddr && peer.ID != uint64(n.nodeID.Load()) {
			assigned = true
		}
	}
	if !assigned {
		return fmt.Errorf("target is not assigned by master")
	}
	f, err := n.verifiedSource(ctx, plan.Object)
	if err != nil {
		return err
	}
	defer f.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		fmt.Sprintf("%s://%s/replicate/%d", n.scheme(), peerAddr, plan.Object.ObjectID), io.NopCloser(f))
	if err != nil {
		return err
	}
	req.ContentLength = plan.Object.Size
	// 计划推送把 plan 绑到出站票据上（security 模式换票时一并核验）；
	// 非计划推送 PlanID 为空，不携带。
	if plan.Object.PlanID != "" {
		req.Header.Set(access.PlanHeader, plan.Object.PlanID)
	}
	if plan.Object.ChecksumKnown {
		req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", plan.Object.Checksum))
	}
	resp, err := n.bulkClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("replicate: status %d", resp.StatusCode)
	}
	return nil
}

func syncObjectDirectories(objectPath string) error {
	// Both bucket creation and object rename need durable parent entries.
	dir := filepath.Dir(objectPath)
	for i := 0; i < 4; i++ {
		f, err := os.Open(dir)
		if err != nil {
			return err
		}
		err = f.Sync()
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

func (n *Node) handleVerifyObject(w http.ResponseWriter, r *http.Request) {
	id, ok := parseObjectID(w, r)
	if !ok {
		return
	}
	// 可选 plan_id：仅增保护计划下重启/回执丢失时，先校验本机已落盘对象即可补回执，
	// 无需重新传输内容。空字符串 = 原非计划流程。
	planID := r.URL.Query().Get("plan_id")
	// 计划 verify 的总 ctx 截止 = min(verifyTimeout, PlanLeaseUntil)；replicationPlan
	// 已拒绝 zero/过期租约，这里只取收窄后的截止，保证回执在租约窗口内发出。
	// 租约过期后 store/report 的失败不会重试开新流（master 侧 pending receipt 会拒）。
	ctx, cancel := context.WithTimeout(r.Context(), verifyTimeout)
	defer cancel()
	plan, err := n.replicationPlan(ctx, id, planID)
	if err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	if planID != "" {
		deadline, lerr := planDeadline(verifyTimeout, plan.Object.PlanLeaseUntil)
		if lerr != nil {
			// 理论上 replicationPlan 已拦截；防御性 fail-closed，不给回执。
			httpError(w, http.StatusConflict, lerr.Error())
			return
		}
		// 只收窄不放宽。
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	f, err := n.verifiedSource(ctx, plan.Object)
	if err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		httpError(w, http.StatusInternalServerError, "sync object failed")
		return
	}
	if err := syncObjectDirectories(n.objectPath(id)); err != nil {
		httpError(w, http.StatusInternalServerError, "sync directory failed")
		return
	}
	if err := n.reportStored(ctx, plan.Object); err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
}
