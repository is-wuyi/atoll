package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/transferbudget"
	"atoll/pkg/types"
)

type plannedWriteError struct{ err error }

func (e *plannedWriteError) Error() string { return e.err.Error() }
func (e *plannedWriteError) Unwrap() error { return e.err }
func IsPlannedWriteError(err error) bool {
	var target *plannedWriteError
	return errors.As(err, &target)
}
func plannedError(err error) error {
	if err == nil || IsPlannedWriteError(err) {
		return err
	}
	return &plannedWriteError{err: err}
}

// WritePlanning only falls back when an older Master has no discovery endpoint.
// Once enabled, the client never downgrades, including after a Master restart.
func (c *Client) WritePlanning(ctx context.Context) (bool, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEnabled {
		return true, nil
	}
	if !c.writeChecked.IsZero() && time.Since(c.writeChecked) < 30*time.Second {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.MasterURL+"/capabilities", nil)
	if err != nil {
		return false, plannedError(err)
	}
	req.Header.Set(types.FeaturesHeader, types.ObjectIDFeature+","+types.WritePlanFeature+","+types.WriteTransferFeature+","+types.WriteRecoveryFeature)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, plannedError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		c.writeChecked = time.Now()
		return false, nil
	}
	if err = statusError(resp); err != nil {
		return false, plannedError(err)
	}
	var caps struct {
		Features      []string `json:"features"`
		WritePlanning *bool    `json:"write_planning"`
	}
	if err = decodePlannedResponse(resp.Body, &caps); err != nil {
		return false, plannedError(err)
	}
	if caps.WritePlanning == nil {
		return false, plannedError(errors.New("master omitted write planning capability"))
	}
	if *caps.WritePlanning {
		found := false
		for _, feature := range caps.Features {
			if feature == types.WritePlanFeature {
				found = true
			}
		}
		if !found {
			return false, plannedError(errors.New("master enabled an unsupported write protocol"))
		}
		c.writeEnabled = true
		for _, feature := range caps.Features {
			if feature == types.WriteTransferFeature {
				c.transferEnabled = true
			}
			if feature == types.WriteRecoveryFeature {
				c.writeRecovery = true
			}
		}
	}
	c.writeChecked = time.Now()
	return *caps.WritePlanning, nil
}

func decodePlannedResponse(r io.Reader, out any) error {
	raw, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("planned write response too large")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("empty planned write response")
	}
	return json.Unmarshal(raw, out)
}

func (c *Client) writeJSON(ctx context.Context, method, path string, body, out any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.MasterURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	features := types.ObjectIDFeature + "," + types.WritePlanFeature + "," + types.WriteTransferFeature
	if c.writeRecovery {
		features += "," + types.WriteRecoveryFeature
	}
	req.Header.Set(types.FeaturesHeader, features)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err = statusError(resp); err != nil {
		return err
	}
	if out != nil {
		return decodePlannedResponse(resp.Body, out)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return err
}

func waitWriteRetry(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func retryWriteMetadata(err error) bool {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.StatusCode == http.StatusServiceUnavailable
	}
	var u *url.Error
	return errors.As(err, &u) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}
func (c *Client) writeJSONRetry(ctx context.Context, path string, body, out any) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = c.writeJSON(ctx, http.MethodPost, path, body, out)
		if err == nil || !retryWriteMetadata(err) || ctx.Err() != nil {
			return err
		}
		if attempt < 2 {
			if e := waitWriteRetry(ctx, time.Duration(attempt+1)*100*time.Millisecond); e != nil {
				return e
			}
		}
	}
	return err
}

func (c *Client) beginPlannedWrite(ctx context.Context, remote string, size int64, overwrite bool, op string) (types.WriteUpload, error) {
	var out types.BeginWriteResponse
	if size < -1 || types.ChunkSize <= 0 || size > types.ChunkSize*types.MaxChunksPerFile {
		return out.Upload, errors.New("invalid planned file size")
	}
	err := c.writeJSONRetry(ctx, "/writes", types.BeginWriteRequest{Path: remote, Size: size, Overwrite: overwrite, OpID: op}, &out)
	if err != nil {
		return out.Upload, err
	}
	u := out.Upload
	if u.ID < types.StagingInodeBase || u.ID > types.MaxStagingInode || u.PlanID == "" || len(u.PlanID) > 128 || u.Revision != 1 || u.Size != size || !u.Policy.Tier.Valid() || u.CreatedAt.IsZero() || !u.ExpiresAt.After(u.CreatedAt) || (u.State != types.WritePending && u.State != types.WriteCommitted) {
		return u, errors.New("master returned an invalid write upload")
	}
	if u.State == types.WriteCommitted && u.Result == nil {
		return u, errors.New("master omitted committed write result")
	}
	return u, nil
}
func plannedBinding(u types.WriteUpload) types.WriteBinding {
	return types.WriteBinding{UploadID: u.ID, PlanID: u.PlanID, Revision: u.Revision}
}

func validatePlannedChunk(req types.PlanWriteChunkRequest, out types.PlanWriteChunkResponse) error {
	if err := types.ValidateWriteChunkPlan(req, out.Plan); err != nil {
		return err
	}
	p, ch := out.Plan, out.Chunk
	if ch.ID != p.Object.ID || ch.Index != p.Index || ch.Size != p.Object.StoredSize || !ch.ChecksumKnown || ch.Checksum != p.Object.Checksum || !reflect.DeepEqual(ch.Replicas, p.Layout.Nodes) {
		return errors.New("master returned inconsistent chunk metadata")
	}
	if len(out.Nodes) != len(p.Layout.Nodes) {
		return errors.New("master omitted planned node addresses")
	}
	ids := map[uint64]bool{}
	addrs := map[string]bool{}
	for _, n := range out.Nodes {
		if ids[n.ID] || n.ID == 0 || !types.ContainsUint64(p.Layout.Nodes, n.ID) {
			return errors.New("master returned an unplanned node")
		}
		u, err := url.Parse("http://" + n.Addr)
		if err != nil || u.Host != n.Addr || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return errors.New("invalid planned node address")
		}
		host, port, err := net.SplitHostPort(n.Addr)
		if err != nil || host == "" || port == "" {
			return errors.New("invalid planned node address")
		}
		canonical := strings.ToLower(n.Addr)
		if addrs[canonical] {
			return errors.New("planned nodes share an address")
		}
		addrs[canonical] = true
		ids[n.ID] = true
	}
	return nil
}

func (c *Client) uploadPlannedChunk(ctx context.Context, u types.WriteUpload, index int, data []byte) error {
	return c.uploadPlannedChunkAEAD(ctx, u, index, data, nil)
}

// uploadPlannedChunkAEAD 是计划块上传的完整入口：aead 为 nil 或未启用时按
// plain 几何上传（旧行为）；启用时先取块 DEK、密封为 aead-record-v1 密文，
// 以密文字节构造 Reserve（CRC 与存储长度都按密文计），再向计划节点直传。
func (c *Client) uploadPlannedChunkAEAD(ctx context.Context, u types.WriteUpload, index int, data []byte, aead *aeadUpload) error {
	if aead != nil && aead.fatal != nil {
		// requireEncryption 下的探测硬失败：不做明文上传。
		return aead.fatal
	}
	encoding := types.PlainEncoding
	upload := data
	if aead != nil && aead.enabled {
		dek, err := aead.chunkDEK(ctx, c, u, index)
		if err != nil {
			return err
		}
		if dek != nil {
			sealed, err := sealChunk(dek, u, index, data)
			if err != nil {
				return err
			}
			encoding, upload = types.AeadRecordEncoding, sealed
		}
	}
	request := types.PlanWriteChunkRequest{WriteBinding: plannedBinding(u), Index: index, LogicalSize: int64(len(data)), StoredSize: int64(len(upload)), Encoding: encoding, Checksum: types.CRC32C(upload)}
	if c.transferEnabled {
		network, err := c.observeWriteTransfer(ctx, u)
		if err != nil {
			return err
		}
		request.Network = network
	}
	var out types.PlanWriteChunkResponse
	if err := c.writeJSONRetry(ctx, "/writes/chunks", request, &out); err != nil {
		return err
	}
	if err := validatePlannedChunk(request, out); err != nil {
		return err
	}
	if c.transferEnabled && out.Plan.Transfer == nil {
		return errors.New("master omitted required write transfer plan")
	}
	if c.writeRecovery {
		if out.Plan.Recovery == nil {
			return errors.New("master omitted required write recovery state")
		}
		return c.uploadRecoverableChunk(ctx, u, request, out, upload)
	}
	if out.Plan.Recovery != nil {
		return errors.New("master returned unnegotiated write recovery state")
	}
	addresses := map[uint64]string{}
	for _, n := range out.Nodes {
		addresses[n.ID] = n.Addr
	}
	uploadTargets := out.Plan.Confirmations
	if out.Plan.Transfer != nil {
		if !time.Now().Before(out.Plan.Transfer.ExpiresAt) {
			return errors.New("write transfer plan expired")
		}
		uploadTargets = out.Plan.Transfer.UploadTargets
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithDeadline(ctx, out.Plan.Transfer.ExpiresAt)
		defer deadlineCancel()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	slots := make(chan struct{}, 2)
	for _, id := range uploadTargets {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			break
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			defer func() { <-slots }()
			putCtx := ctx
			var rate uint64
			if out.Plan.Transfer != nil {
				for _, leg := range out.Plan.Transfer.Legs {
					if leg.FromNodeID == 0 && leg.ToNodeID == id {
						putCtx = peerhttp.WithPath(putCtx, peerhttp.Path(leg.Path))
						rate = leg.BPS
					}
				}
			}
			err := c.putPlannedObjectWithRate(putCtx, addresses[id], out.Plan.Object.ID, request.Checksum, upload, rate)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("required node %d: %w", id, err)
				}
				mu.Unlock()
				cancel()
			}
		}(id)
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	if out.Plan.Transfer != nil {
		if err := c.waitPlannedChunk(ctx, u, index); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (c *Client) putPlannedObject(ctx context.Context, addr string, id uint64, checksum uint32, data []byte) error {
	return c.putPlannedObjectWithRate(ctx, addr, id, checksum, data, 0)
}

func (c *Client) putPlannedObjectWithRate(ctx context.Context, addr string, id uint64, checksum uint32, data []byte, rate uint64) error {
	if path, required := peerhttp.RequiredPath(ctx); required && (path == peerhttp.PathDirect || path == peerhttp.PathRelay) {
		if c.secTransport == nil {
			return errors.New("P2P write plan requires a configured secure peer transport")
		}
		if _, ok := c.secTransport.base.(*peerhttp.Transport); !ok {
			return errors.New("P2P write plan requires a configured peer resolver")
		}
	}
	var limiter *transferbudget.Limiter
	c.transferMu.Lock()
	limiter = c.transferUpload
	c.transferMu.Unlock()
	if limiter == nil && rate != 0 {
		var err error
		limiter, err = transferbudget.New(rate, 1)
		if err != nil {
			return err
		}
	}
	if limiter != nil {
		release, err := limiter.Acquire(ctx)
		if err != nil {
			return err
		}
		defer release()
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		putCtx, cancel := context.WithTimeout(ctx, c.ioTimeout(int64(len(data))))
		var reader io.Reader = bytes.NewReader(data)
		if limiter != nil {
			reader = limiter.Reader(putCtx, reader, rate)
		}
		req, err := http.NewRequestWithContext(putCtx, http.MethodPut, fmt.Sprintf("%s://%s/objects/%d", c.scheme(), addr, id), reader)
		if err == nil {
			req.ContentLength = int64(len(data))
			req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", checksum))
			var resp *http.Response
			resp, err = c.HTTP.Do(req)
			if err == nil {
				err = statusError(resp)
				if err == nil {
					var result struct {
						Size *int64 `json:"size"`
					}
					err = decodePlannedResponse(resp.Body, &result)
					if err == nil && (result.Size == nil || *result.Size != int64(len(data))) {
						err = errors.New("node acknowledged incorrect stored length")
					}
				}
				resp.Body.Close()
			}
		}
		cancel()
		if err == nil {
			return nil
		}
		last = err
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var he *HTTPError
		if errors.As(err, &he) && he.StatusCode < 500 {
			return err
		}
		if attempt < 2 {
			if err := waitWriteRetry(ctx, 100*time.Millisecond); err != nil {
				return err
			}
		}
	}
	return last
}

func (c *Client) commitPlannedWrite(ctx context.Context, u types.WriteUpload, total int64, count int, op string) (types.Inode, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req := types.CommitWriteRequest{WriteBinding: plannedBinding(u), OpID: op, Size: total, ChunkCount: count}
	for {
		var out types.CommitWriteResponse
		err := c.writeJSON(ctx, http.MethodPost, "/writes/commit", req, &out)
		if err == nil {
			if out.Inode.ID == 0 || out.Inode.Staging || out.Inode.Type != types.TypeFile || out.Inode.Size != total || out.Inode.Content == nil || out.Inode.Content.ID != u.ID || out.Inode.Content.LogicalSize != total || len(out.Inode.Chunks) != count {
				return out.Inode, errors.New("master returned invalid committed contents")
			}
			if err := types.ValidateContentManifest(out.Inode); err != nil {
				return out.Inode, err
			}
			return out.Inode, nil
		}
		if ctx.Err() != nil {
			return types.Inode{}, ctx.Err()
		}
		if WriteCode(err) != types.WriteNotReady && !retryWriteMetadata(err) {
			return types.Inode{}, err
		}
		if err = waitWriteRetry(ctx, 200*time.Millisecond); err != nil {
			return types.Inode{}, err
		}
	}
}
func (c *Client) abortPlannedWrite(u types.WriteUpload) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.writeJSON(ctx, http.MethodPost, "/writes/abort", plannedBinding(u), nil)
}

func (c *Client) putPlannedReader(ctx context.Context, path string, size int64, r io.Reader, overwrite bool) (out types.Inode, err error) {
	if size < 0 {
		return out, plannedError(errors.New("reader upload requires a known nonnegative size"))
	}
	u, err := c.beginPlannedWrite(ctx, path, size, overwrite, newOpID())
	if err != nil {
		return out, plannedError(err)
	}
	if u.State == types.WriteCommitted {
		return *u.Result, nil
	}
	stream := newPlannedStream(c, u, ctx)
	defer func() {
		if err != nil {
			_ = stream.close()
		}
	}()
	for left := size; left > 0; {
		n := min(left, types.ChunkSize)
		data := make([]byte, n)
		if _, err = io.ReadFull(r, data); err != nil {
			return out, plannedError(err)
		}
		left -= n
		if left == 0 && n < types.ChunkSize {
			out, err = stream.finish(data, size)
			return out, plannedError(err)
		}
		if err = stream.push(data); err != nil {
			return out, plannedError(err)
		}
	}
	out, err = stream.finish(nil, size)
	return out, plannedError(err)
}

func (c *Client) GetProtection(path string) (types.ProtectionResponse, error) {
	var out types.ProtectionResponse
	ok, err := c.WritePlanning(context.Background())
	if err != nil {
		return out, err
	}
	if !ok {
		return out, plannedError(errors.New("master does not enable protection preferences"))
	}
	err = c.writeJSON(context.Background(), http.MethodGet, "/protection?"+queryPath(path), nil, &out)
	return out, plannedError(err)
}
func (c *Client) SetProtection(path string, tier types.ProtectionTier) (types.ProtectionResponse, error) {
	var out types.ProtectionResponse
	if tier != "" && !tier.Valid() {
		return out, plannedError(errors.New("unknown protection preference"))
	}
	ok, err := c.WritePlanning(context.Background())
	if err != nil {
		return out, err
	}
	if !ok {
		return out, plannedError(errors.New("master does not enable protection preferences"))
	}
	err = c.writeJSON(context.Background(), http.MethodPost, "/protection", types.ProtectionRequest{Path: path, Tier: tier}, &out)
	return out, plannedError(err)
}
