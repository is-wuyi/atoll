package master

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
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"atoll/internal/scheduler"
	"atoll/master/meta"
	"atoll/pkg/auth"
	"atoll/pkg/transferbudget"
	"atoll/pkg/types"
)

const (
	AutonomyObserve = "observe"
	AutonomyShadow  = "shadow"
	AutonomyAdd     = "add"
)

type AutonomyConfig struct {
	Mode               string        `json:"mode"`
	Interval           time.Duration `json:"interval"`
	ProbeTimeout       time.Duration `json:"probe_timeout"`
	RequestTimeout     time.Duration `json:"request_timeout"`
	RetryInterval      time.Duration `json:"retry_interval"`
	MaxPlans           int           `json:"max_plans"`
	MaxDispatchPerTick int           `json:"max_dispatch_per_tick"`
	MaxBytesPerRound   int64         `json:"max_bytes_per_round"`
	// 每源/每目标的并发租约上限（0 = 取 MaxDispatchPerTick）。
	MaxSourceConcurrent int `json:"max_source_concurrent"`
	MaxTargetConcurrent int `json:"max_target_concurrent"`
	// 每流速率分配的天花板（0 = 不设天花板）。上限只用于拒绝分配，绝不下调已声明的
	// profile 速率，也不会因为某源声明速率高于天花板而永久淘汰它。
	MaxSourceUploadBPS   uint64 `json:"max_source_upload_bps"`
	MaxTargetDownloadBPS uint64 `json:"max_target_download_bps"`
	MaxReplicas          int    `json:"max_replicas"`
}

type AutonomyDecision struct {
	ObjectID  uint64              `json:"object_id"`
	Status    string              `json:"status"`
	Reason    string              `json:"reason"`
	PlanID    string              `json:"plan_id,omitempty"`
	Suggested *scheduler.Decision `json:"suggested,omitempty"`
}

type AutonomyReport struct {
	At            time.Time          `json:"at"`
	Mode          string             `json:"mode"`
	ObservedNodes int                `json:"observed_nodes"`
	Decisions     []AutonomyDecision `json:"decisions"`
	Dispatched    int                `json:"dispatched"`
	Error         string             `json:"error,omitempty"`
}

type Autonomy struct {
	store      *meta.Store
	nodeMaxAge time.Duration
	config     AutonomyConfig
	http       *http.Client
	scheme     string
	stepMu     sync.Mutex
	mu         sync.Mutex
	last       AutonomyReport
	wg         sync.WaitGroup
	startOnce  sync.Once
}

func NewAutonomy(store *meta.Store, nodeMaxAge time.Duration, cfg AutonomyConfig) (*Autonomy, error) {
	if store == nil || nodeMaxAge <= 0 {
		return nil, errors.New("autonomy requires store and positive node age")
	}
	if cfg.Mode == "" {
		cfg.Mode = AutonomyObserve
	}
	if cfg.Mode != AutonomyObserve && cfg.Mode != AutonomyShadow && cfg.Mode != AutonomyAdd {
		return nil, errors.New("autonomy mode must be observe, shadow or add")
	}
	if cfg.Interval == 0 {
		cfg.Interval = time.Minute
	}
	if cfg.ProbeTimeout == 0 {
		cfg.ProbeTimeout = 3 * time.Second
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 65 * time.Second
	}
	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = 5 * time.Minute
	}
	if cfg.MaxPlans == 0 {
		cfg.MaxPlans = 128
	}
	if cfg.MaxDispatchPerTick == 0 {
		cfg.MaxDispatchPerTick = 2
	}
	if cfg.MaxSourceConcurrent == 0 {
		cfg.MaxSourceConcurrent = cfg.MaxDispatchPerTick
	}
	if cfg.MaxTargetConcurrent == 0 {
		cfg.MaxTargetConcurrent = cfg.MaxDispatchPerTick
	}
	if cfg.MaxBytesPerRound == 0 {
		cfg.MaxBytesPerRound = 256 << 20
	}
	if cfg.MaxReplicas == 0 {
		cfg.MaxReplicas = 8
	}
	if cfg.Interval <= 0 || cfg.ProbeTimeout <= 0 || cfg.RequestTimeout <= 0 || cfg.RetryInterval <= 0 ||
		cfg.MaxPlans < 1 || cfg.MaxPlans > 1024 || cfg.MaxDispatchPerTick < 1 || cfg.MaxDispatchPerTick > 16 ||
		cfg.MaxBytesPerRound <= 0 || cfg.MaxReplicas < 2 || cfg.MaxReplicas > 32 ||
		cfg.MaxSourceConcurrent < 1 || cfg.MaxSourceConcurrent > 32 || cfg.MaxTargetConcurrent < 1 || cfg.MaxTargetConcurrent > 32 ||
		cfg.MaxSourceUploadBPS > transferbudget.MaxRate || cfg.MaxTargetDownloadBPS > transferbudget.MaxRate {
		return nil, errors.New("invalid autonomy resource bounds")
	}
	return &Autonomy{store: store, nodeMaxAge: nodeMaxAge, config: cfg, http: &http.Client{Transport: auth.HTTPTransport("", nil, nil)}, scheme: "http"}, nil
}

func (a *Autonomy) SetTransport(token auth.Token, cfg *tls.Config) {
	a.http = &http.Client{Transport: auth.HTTPTransport(token, cfg, nil)}
	if cfg != nil {
		a.scheme = "https"
	}
}

func (a *Autonomy) Start(ctx context.Context) {
	a.startOnce.Do(func() {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			ticker := time.NewTicker(a.config.Interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := a.Step(ctx); err != nil && ctx.Err() == nil {
						log.Printf("autonomy: %v", err)
					}
				}
			}
		}()
	})
}
func (a *Autonomy) Wait()                  { a.wg.Wait() }
func (a *Autonomy) Config() AutonomyConfig { return a.config }
func (a *Autonomy) Report() AutonomyReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.last
	out.Decisions = append([]AutonomyDecision(nil), a.last.Decisions...)
	return out
}

func (a *Autonomy) Step(ctx context.Context) (report AutonomyReport, err error) {
	if !a.stepMu.TryLock() {
		return report, errors.New("autonomy cycle already running")
	}
	defer a.stepMu.Unlock()
	report = AutonomyReport{At: time.Now().UTC(), Mode: a.config.Mode}
	defer func() {
		if err != nil {
			report.Error = err.Error()
		}
		a.mu.Lock()
		a.last = report
		a.mu.Unlock()
	}()
	if err = a.ObserveOnce(ctx, report.At); err != nil {
		return
	}
	snapshot, e := a.store.AutonomySnapshot()
	if e != nil {
		err = e
		return
	}
	report.ObservedNodes = len(snapshot.Nodes)
	remainingDispatchBytes := a.config.MaxBytesPerRound
	evaluationTime := time.Now().UTC()
	if a.config.Mode == AutonomyObserve {
		return
	}
	if a.config.Mode == AutonomyAdd {
		report.Dispatched, err = a.executePendingBudget(ctx, snapshot.Plans, evaluationTime, a.config.MaxDispatchPerTick, &remainingDispatchBytes)
		if err != nil {
			return
		}
		snapshot, e = a.store.AutonomySnapshot()
		if e != nil {
			err = e
			return
		}
	}
	report.Decisions, err = a.plan(ctx, snapshot, time.Now().UTC())
	if err != nil {
		return
	}
	if a.config.Mode == AutonomyAdd && report.Dispatched < a.config.MaxDispatchPerTick {
		latest, e := a.store.AutonomySnapshot()
		if e != nil {
			err = e
			return
		}
		n, e := a.executePendingBudget(ctx, latest.Plans, time.Now().UTC(), a.config.MaxDispatchPerTick-report.Dispatched, &remainingDispatchBytes)
		report.Dispatched += n
		err = e
	}
	return
}

func (a *Autonomy) ObserveOnce(ctx context.Context, now time.Time) error {
	nodes, err := a.store.ListNodes()
	if err != nil {
		return err
	}
	if len(nodes) > 256 {
		return errors.New("autonomy observation limit exceeded")
	}
	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		sample := meta.NodeSample{At: now, UsedBytes: node.UsedBytes, TotalBytes: node.TotalBytes}
		probeCtx, cancel := context.WithTimeout(ctx, a.config.ProbeTimeout)
		started := time.Now()
		req, e := http.NewRequestWithContext(probeCtx, http.MethodGet, fmt.Sprintf("%s://%s/healthz", a.scheme, node.Addr), nil)
		if e == nil {
			resp, e := a.http.Do(req)
			if e == nil {
				sample.Online = resp.StatusCode == http.StatusOK && now.Sub(node.LastHeartbeat) <= a.nodeMaxAge && !node.LastHeartbeat.After(now.Add(time.Second))
				io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
				resp.Body.Close()
			}
		}
		sample.RTTMillis = float64(time.Since(started).Microseconds()) / 1000
		cancel()
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.store.RecordNodeSample(node.ID, sample); err != nil {
			return err
		}
	}
	return nil
}

func autonomyPolicy(cfg AutonomyConfig, remaining int64) scheduler.Policy {
	return scheduler.Policy{AdditiveOnly: true, CodecLimits: scheduler.CodecLimits{MaxK: -1}, MaxReplicaCount: cfg.MaxReplicas,
		MinFaultTolerance: 1, MinFaultMarginToDefer: 1, MinConfidence: 0.7, MaxDeferOfflineSeconds: 3600,
		MaxMigrationBytesBudget: uint64(remaining), PredictionHorizonSeconds: 3600,
		Search: scheduler.SearchParams{ExactComboLimit: 256, BeamWidth: 8, MaxCandidates: 64}}
}

func (a *Autonomy) schedulerSnapshot(snapshot meta.AutonomySnapshot, d types.ObjectIntegrity, now time.Time, remaining int64) (scheduler.Snapshot, bool) {
	out := scheduler.Snapshot{SchemaVersion: scheduler.SchemaVersion, GeneratedAt: now.Format(time.RFC3339Nano), TraceID: "autonomy", Policy: autonomyPolicy(a.config, remaining)}
	profiles := map[uint64]meta.NodePlacementProfile{}
	for _, p := range snapshot.Profiles {
		profiles[p.NodeID] = p
	}
	observations := map[uint64]meta.NodeObservation{}
	for _, p := range snapshot.Observations {
		observations[p.NodeID] = p
	}
	capacity := map[uint64]meta.NodeCapacity{}
	for _, c := range snapshot.Capacity {
		capacity[c.NodeID] = c
	}
	hasSource := false
	for _, n := range snapshot.Nodes {
		c := capacity[n.ID]
		history := observations[n.ID]
		online := false
		rtt := float64(0)
		if len(history.Samples) > 0 {
			last := history.Samples[len(history.Samples)-1]
			online = last.Online && !last.At.Before(now.Add(-a.nodeMaxAge)) && !last.At.After(now.Add(time.Second))
			rtt = last.RTTMillis
		}
		if types.ContainsUint64(d.Replicas, n.ID) {
			online = online && types.ContainsUint64(d.Done, n.ID) && !types.ContainsUint64(d.Suspect, n.ID)
			if online {
				hasSource = true
			}
		}
		node := scheduler.Node{ID: strconv.FormatUint(n.ID, 10), FailureDomains: profiles[n.ID].FailureDomains, HardCapacityBytes: uint64(max(int64(0), c.Capacity)),
			ReservedBytes: uint64(max(int64(0), c.Capacity-c.Free)), Online: online, RTTMs: rtt, CostPerGBMonth: 1}
		for _, sample := range history.Samples {
			node.History = append(node.History, scheduler.OnlineSample{At: sample.At.Format(time.RFC3339Nano), Online: sample.Online})
		}
		out.Nodes = append(out.Nodes, node)
	}
	id := strconv.FormatUint(d.ObjectID, 10)
	current := &scheduler.Layout{ObjectID: id, ContentVersion: d.Generation, LayoutEpoch: d.IntegrityEpoch, Scheme: scheduler.SchemeReplicate}
	for i, nodeID := range d.Replicas {
		current.Replicas = append(current.Replicas, scheduler.FragmentPlacement{NodeID: strconv.FormatUint(nodeID, 10), FragmentIndex: i, Bytes: uint64(d.Size), Origin: scheduler.OriginExisting})
	}
	out.Objects = []scheduler.ObjectRequirement{{ObjectID: id, SizeBytes: uint64(d.Size), ContentVersion: d.Generation,
		Intent: scheduler.ProtectionIntent{Tier: "normal"}, CurrentLayout: current}}
	return out, hasSource
}

func (a *Autonomy) plan(ctx context.Context, snapshot meta.AutonomySnapshot, now time.Time) (results []AutonomyDecision, resultErr error) {
	active := map[uint64]bool{}
	activeCount := 0
	for _, p := range snapshot.Plans {
		if p.State == meta.ProtectionPending {
			active[p.Expected.ObjectID] = true
			activeCount++
		}
	}
	objects := append([]types.ObjectIntegrity(nil), snapshot.Objects...)
	sort.Slice(objects, func(i, j int) bool { return objects[i].ObjectID < objects[j].ObjectID })
	remaining := a.config.MaxBytesPerRound
	start := sort.Search(len(objects), func(i int) bool { return objects[i].ObjectID > snapshot.ScanAfter })
	if start == len(objects) {
		start = 0
	}
	last, visited := snapshot.ScanAfter, false
	defer func() {
		if visited {
			if err := a.store.SetAutonomyScanAfter(last); resultErr == nil {
				resultErr = err
			}
		}
	}()
	for offset := 0; offset < min(len(objects), 256); offset++ {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		if activeCount >= a.config.MaxPlans || remaining <= 0 {
			break
		}
		d := objects[(start+offset)%len(objects)]
		last, visited = d.ObjectID, true
		if !d.ChecksumKnown || d.Size <= 0 || d.Size > types.ChunkSize || d.ObjectID < types.StagingInodeBase<<8 {
			continue
		}
		if active[d.ObjectID] {
			continue
		}
		if activeCount >= a.config.MaxPlans || remaining <= 0 {
			break
		}
		world, source := a.schedulerSnapshot(snapshot, d, now, remaining)
		if !source {
			results = append(results, AutonomyDecision{ObjectID: d.ObjectID, Status: "no_source", Reason: "no verified online source; existing copies preserved"})
			continue
		}
		decisions, err := scheduler.RunAt(&world, now)
		if err != nil {
			return results, err
		}
		if len(decisions) != 1 {
			return results, errors.New("unexpected scheduler decision count")
		}
		decision := decisions[0]
		entry := AutonomyDecision{ObjectID: d.ObjectID, Status: string(decision.Status), Reason: strings.Join(decision.Reasons, "; "), Suggested: &decision}
		if decision.Plan == nil || decision.Status != scheduler.StatusPlanProposed {
			results = append(results, entry)
			continue
		}
		if decision.Plan.TargetLayout.Scheme != scheduler.SchemeReplicate {
			return results, errors.New("EC plan cannot enter additive executor")
		}
		var targets []uint64
		for _, position := range decision.Plan.TargetLayout.Replicas {
			id, err := strconv.ParseUint(position.NodeID, 10, 64)
			if err != nil {
				return results, err
			}
			if !types.ContainsUint64(d.Replicas, id) {
				targets = append(targets, id)
			}
		}
		for _, old := range d.Replicas {
			found := false
			for _, p := range decision.Plan.TargetLayout.Replicas {
				if p.NodeID == strconv.FormatUint(old, 10) {
					found = true
				}
			}
			if !found {
				return results, errors.New("scheduler attempted to drop a current replica")
			}
		}
		for _, action := range decision.Plan.Actions {
			if action.Kind != "keep" && action.Kind != "add_replica" {
				return results, fmt.Errorf("unsupported autonomous action %s", action.Kind)
			}
		}
		if len(targets) == 0 {
			results = append(results, entry)
			continue
		}
		if d.Size > remaining/int64(len(targets)) {
			entry.Status = "budget_exhausted"
			results = append(results, entry)
			continue
		}
		cost := d.Size * int64(len(targets))
		remaining -= cost
		if a.config.Mode == AutonomyAdd {
			var token [16]byte
			if _, err := rand.Read(token[:]); err != nil {
				return results, err
			}
			request := meta.ProtectionRequest{ID: "protect-" + hex.EncodeToString(token[:]), Expected: d, Targets: targets, MaxBytes: cost,
				NodeMaxAge: a.nodeMaxAge, ProfileRevision: snapshot.ProfileRevision, Reason: entry.Reason}
			p, err := a.store.ReserveProtection(request, now)
			if err != nil {
				entry.Status = "reservation_rejected"
				entry.Reason = err.Error()
			} else {
				entry.PlanID = p.ID
				entry.Status = "reserved"
				activeCount++
				active[d.ObjectID] = true
			}
			results = append(results, entry)
			latest, err := a.store.AutonomySnapshot()
			if err != nil {
				return results, err
			}
			snapshot = latest
		} else {
			results = append(results, entry)
			for i := range snapshot.Capacity {
				if types.ContainsUint64(targets, snapshot.Capacity[i].NodeID) {
					snapshot.Capacity[i].Free = max(int64(0), snapshot.Capacity[i].Free-d.Size)
				}
			}
		}
	}
	return results, nil
}

func (a *Autonomy) executePending(ctx context.Context, plans []meta.ProtectionPlan, now time.Time) (int, error) {
	return a.executePendingLimit(ctx, plans, now, a.config.MaxDispatchPerTick)
}
func (a *Autonomy) executePendingLimit(ctx context.Context, plans []meta.ProtectionPlan, now time.Time, limit int) (int, error) {
	remaining := a.config.MaxBytesPerRound
	return a.executePendingBudget(ctx, plans, now, limit, &remaining)
}

func (a *Autonomy) executePendingBudget(ctx context.Context, plans []meta.ProtectionPlan, now time.Time, limit int, remaining *int64) (int, error) {
	plans = append([]meta.ProtectionPlan(nil), plans...)
	meta.SortProtectionPlans(plans)
	activeLeases := 0
	for _, plan := range plans {
		for _, target := range plan.Targets {
			if !target.Done && target.Attempts > 0 && now.Before(target.NextAttempt) {
				activeLeases++
			}
		}
	}
	limit = min(limit, max(0, a.config.MaxDispatchPerTick-activeLeases))
	dispatched := 0
	for _, p := range plans {
		if dispatched >= limit {
			break
		}
		if p.State != meta.ProtectionPending {
			continue
		}
		if err := ctx.Err(); err != nil {
			return dispatched, err
		}
		plan, target, err := a.store.ClaimProtectionTarget(p.ID, now, a.config.RetryInterval,
			meta.ProtectionExecutionBudget{MaxConcurrent: a.config.MaxDispatchPerTick, MaxBytes: *remaining,
				MaxSourceConcurrent: a.config.MaxSourceConcurrent, MaxTargetConcurrent: a.config.MaxTargetConcurrent,
				MaxSourceUploadBPS: a.config.MaxSourceUploadBPS, MaxTargetDownloadBPS: a.config.MaxTargetDownloadBPS,
				NodeMaxAge: a.nodeMaxAge})
		if err != nil {
			return dispatched, err
		}
		if target == nil {
			continue
		}
		dispatched++
		*remaining -= plan.Expected.Size
		if err := a.executeTarget(ctx, plan, *target); err != nil {
			if recordErr := a.store.RecordProtectionError(plan.ID, target.NodeID, err.Error()); recordErr != nil {
				return dispatched, recordErr
			}
		}
	}
	return dispatched, nil
}

func (a *Autonomy) executeTarget(ctx context.Context, plan meta.ProtectionPlan, target meta.ProtectionTarget) error {
	if err := a.store.EnsureDurable(); err != nil {
		return err
	}
	d, err := a.store.ProtectionDescriptor(plan.ID, plan.Expected.ObjectID, target.NodeID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, d.PlanLeaseUntil)
	defer cancel()
	currentTarget, err := a.store.GetNode(target.NodeID)
	if err != nil {
		return err
	}
	if currentTarget.Addr != target.Addr {
		return errors.New("target endpoint changed")
	}
	verifyURL := fmt.Sprintf("%s://%s/verify/%d?plan_id=%s", a.scheme, target.Addr, d.ObjectID, url.QueryEscape(plan.ID))
	status, err := a.request(ctx, http.MethodPost, verifyURL, nil)
	if err == nil && status == http.StatusOK {
		fresh, e := a.store.ProtectionPlan(plan.ID)
		if e != nil {
			return e
		}
		for _, t := range fresh.Targets {
			if t.NodeID == target.NodeID && t.Done {
				return nil
			}
		}
		return errors.New("node returned success without a committed receipt")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The descriptor and source are refreshed after verification; a concurrent
	// content change or suspect report must not start a transfer from a stale plan.
	d, err = a.store.ProtectionDescriptor(plan.ID, d.ObjectID, target.NodeID)
	if err != nil {
		return err
	}
	// 源绑定是唯一权威：claim 事务把绑定与租约一起持久化，这里只做存活复核
	// （地址变更 / 内容丢失 / 心跳过期 / suspect 都算失效），失败一律拒绝派工，
	// 绝不静默改派到另一个源。RecordProtectionError 只记录 LastError：失败租约的
	// 在飞速率预留保留到租约窗口自然过期，重绑发生在窗口过期后的下一次有效 claim。
	if target.SourceID == 0 {
		return errors.New("protection lease has no persisted source binding")
	}
	n, e := a.store.GetNode(target.SourceID)
	if e != nil {
		return e
	}
	if n.Addr != target.SourceAddr || !types.ContainsUint64(d.Done, n.ID) ||
		types.ContainsUint64(d.Suspect, n.ID) || time.Since(n.LastHeartbeat) > a.nodeMaxAge {
		return errors.New("persisted protection source binding is invalid")
	}
	payload, _ := json.Marshal(map[string]any{"inode_id": d.ObjectID, "source_id": n.ID, "source_addr": n.Addr, "checksum": d.Checksum, "plan_id": plan.ID})
	status, err = a.request(ctx, http.MethodPost, fmt.Sprintf("%s://%s/pull", a.scheme, target.Addr), payload)
	if err != nil {
		return err
	}
	if status != http.StatusAccepted {
		return fmt.Errorf("plan pull returned %d", status)
	}
	return nil
}

func (a *Autonomy) request(ctx context.Context, method, url string, body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, a.config.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}
