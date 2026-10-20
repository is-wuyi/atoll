package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"

	"atoll/pkg/contentcrypto"
	"atoll/pkg/types"
)

// aeadUpload 决定一次计划上传是否走加密通道，并持有每块 DEK 的会话内缓存。
// 只有 secure 会话（master 会注入用户会话 + space）才可能加密；master 未配置
// KEK 时退回 plain——加密是可选能力，不是硬前提。
type aeadUpload struct {
	enabled bool
	// fatal：requireEncryption 下探测失败的硬错误；首个块上传前返回它，
	// 阻止明文继续。
	fatal error
	mu    sync.Mutex
	deks  map[uint64]*contentcrypto.DEK
}

func newAeadUpload() *aeadUpload {
	return &aeadUpload{deks: make(map[uint64]*contentcrypto.DEK)}
}

// probe 决定本次上传是否走加密通道：只有 secure 会话才探测 master 的
// content-key 服务（409 = 未配置 KEK、404/405 = 旧 master 不支持，都回退 plain）。
// 其他错误（会话失效、网络、服务故障）分两种策略：默认记录日志后按 plain 继续
// （老集群兼容优先）；设置 RequireEncryption 后返回错误硬停上传——配置了加密
// 的集群不允许在 master 故障窗口静默降级成明文落盘。
func (a *aeadUpload) probe(ctx context.Context, c *Client, u types.WriteUpload) error {
	if c.sec == nil {
		return nil
	}
	probe := newAeadUpload()
	probe.enabled = true
	if _, err := probe.chunkDEK(ctx, c, u, 0); err != nil {
		var he *HTTPError
		if errors.As(err, &he) && (he.StatusCode == http.StatusConflict || he.StatusCode == http.StatusNotFound || he.StatusCode == http.StatusMethodNotAllowed) {
			return nil // master 明确表示无密钥服务：合规回退
		}
		if c.requireEncryption {
			return fmt.Errorf("require-encryption: content key unavailable: %w", err)
		}
		log.Printf("atoll: content-key probe failed, uploading plaintext (use -require-encryption to enforce): %v", err)
		return nil
	}
	a.enabled = true
	a.deks = probe.deks
	return nil
}

// prepareChunkKey 为 (upload, index) 取块 DEK：先查缓存，再向 master 的
// prepare 端点请求（该端点按授权创建/幂等取回 wrapped DEK 并解包发放）。
// 未启用或 plain 模式返回 nil, nil。
func (a *aeadUpload) chunkDEK(ctx context.Context, c *Client, u types.WriteUpload, index int) (*contentcrypto.DEK, error) {
	if !a.enabled {
		return nil, nil
	}
	objectID := types.ChunkID(u.ID, index)
	a.mu.Lock()
	dek := a.deks[objectID]
	a.mu.Unlock()
	if dek != nil {
		return dek, nil
	}
	var out types.ContentKeyResponse
	err := c.writeJSONRetry(ctx, "/auth/content-key/prepare", types.PrepareContentKeyRequest{UploadID: u.ID, Index: index}, &out)
	if err != nil {
		return nil, fmt.Errorf("content key prepare: %w", err)
	}
	if out.ObjectID != objectID || out.Generation != u.ID || out.DEK == "" || out.KeyID == "" {
		return nil, errors.New("master returned a mismatched content key")
	}
	raw, err := base64.RawStdEncoding.DecodeString(out.DEK)
	if err != nil || len(raw) != contentcrypto.KeySize {
		return nil, errors.New("master returned an invalid content key")
	}
	key := &contentcrypto.DEK{}
	copy(key[:], raw)
	a.mu.Lock()
	if prev := a.deks[objectID]; prev != nil {
		key = prev
	} else {
		a.deks[objectID] = key
	}
	a.mu.Unlock()
	return key, nil
}

// sealChunk 把块明文按 64KiB 记录封成密文串：记录 AAD 绑定 (objectID,
// generation=ContentVersion.ID=upload ID, index=对象内记录序号)。
// 返回密文字节与逻辑长度（调用方用逻辑长度构造 Reserve 请求）。
func sealChunk(dek *contentcrypto.DEK, u types.WriteUpload, index int, data []byte) ([]byte, error) {
	if dek == nil {
		return nil, errors.New("aead upload requires a content key")
	}
	objectID := types.ChunkID(u.ID, index)
	count, err := types.AeadRecordCount(int64(len(data)))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(data)+count*types.AeadRecordOverhead)
	for i := 0; i < count; i++ {
		start := int64(i) * types.AeadRecordPlaintext
		end := min(start+types.AeadRecordPlaintext, int64(len(data)))
		record, err := contentcrypto.SealRecord(dek, objectID, u.ID, uint64(i), data[start:end])
		if err != nil {
			return nil, err
		}
		out = append(out, record...)
	}
	if want, err := types.AeadStoredSize(int64(len(data))); err != nil || int64(len(out)) != want {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("sealed chunk does not match the record layout")
	}
	return out, nil
}
