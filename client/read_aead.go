package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"atoll/pkg/contentcrypto"
	"atoll/pkg/types"
)

// chunkKeyCache 按对象缓存已解包的 DEK（读取侧）。
type chunkKeyCache struct {
	mu   sync.Mutex
	deks map[uint64]*contentcrypto.DEK
}

func newChunkKeyCache() *chunkKeyCache {
	return &chunkKeyCache{deks: make(map[uint64]*contentcrypto.DEK)}
}

// fetchContentKey 经授权会话取回并解包对象 DEK。会话不可用（非 secure 模式）
// 或 master 未配置密钥服务时返回错误——aead 块没有明文回退。
func (c *Client) fetchContentKey(ctx context.Context, in types.Inode, objectID uint64) (*contentcrypto.DEK, error) {
	if c.sec == nil {
		return nil, errors.New("encrypted object requires a secure session")
	}
	if in.Content == nil {
		return nil, errors.New("encrypted object lacks a content manifest")
	}
	c.keyCacheMu.Lock()
	if c.keyCache == nil {
		c.keyCache = newChunkKeyCache()
	}
	cache := c.keyCache
	c.keyCacheMu.Unlock()
	cache.mu.Lock()
	dek := cache.deks[objectID]
	cache.mu.Unlock()
	if dek != nil {
		return dek, nil
	}
	path := fmt.Sprintf("/auth/content-key?object_id=%d&generation=%d", objectID, in.Content.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.MasterURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(featuresHeader, objectIDFeature)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return nil, fmt.Errorf("content key: %w", err)
	}
	var out types.ContentKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.ObjectID != objectID || out.Generation != in.Content.ID || out.DEK == "" {
		return nil, errors.New("master returned a mismatched content key")
	}
	raw, err := base64.RawStdEncoding.DecodeString(out.DEK)
	if err != nil || len(raw) != contentcrypto.KeySize {
		return nil, errors.New("master returned an invalid content key")
	}
	key := &contentcrypto.DEK{}
	copy(key[:], raw)
	cache.mu.Lock()
	if prev := cache.deks[objectID]; prev != nil {
		key = prev
	} else {
		cache.deks[objectID] = key
	}
	cache.mu.Unlock()
	return key, nil
}

// DecryptChunk 把 aead-record-v1 块密文解回明文（FUSE 读句柄也走这里）。
// 校验密文 CRC 成功后才逐记录 Open；任何记录验证失败都不返回部分明文。
func (c *Client) DecryptChunk(ctx context.Context, in types.Inode, ch types.ChunkInfo, sealed []byte) ([]byte, error) {
	logical := types.ChunkLogicalSize(ch)
	if logical <= 0 {
		return nil, fmt.Errorf("aead chunk %d has no logical size", ch.Index)
	}
	want, err := types.AeadStoredSize(logical)
	if err != nil || int64(len(sealed)) != want {
		return nil, fmt.Errorf("aead chunk %d stored length %d does not match layout (%v)", ch.Index, len(sealed), err)
	}
	objectID := types.ChunkObjID(ch, in.ID)
	dek, err := c.fetchContentKey(ctx, in, objectID)
	if err != nil {
		return nil, err
	}
	count, _ := types.AeadRecordCount(logical)
	out := make([]byte, 0, logical)
	for i := 0; i < count; i++ {
		start, length, _, err := types.AeadRecordExtent(i, logical)
		if err != nil {
			return nil, err
		}
		plain, err := contentcrypto.OpenRecord(dek, objectID, in.Content.ID, uint64(i), sealed[start:start+length])
		if err != nil {
			return nil, fmt.Errorf("aead chunk %d record %d: %w", ch.Index, i, err)
		}
		out = append(out, plain...)
	}
	if int64(len(out)) != logical {
		return nil, fmt.Errorf("aead chunk %d decrypted %d bytes, want %d", ch.Index, len(out), logical)
	}
	return out, nil
}
