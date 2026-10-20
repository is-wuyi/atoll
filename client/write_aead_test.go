package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"atoll/pkg/contentcrypto"
	"atoll/pkg/types"
)

// TestSealChunkMatchesRecordLayout 用真实 DEK 封一个跨记录长度的块，验证
// 密文长度与 AeadStoredSize 一致且逐记录可解回原明文（封/解双向几何对齐）。
func TestSealChunkMatchesRecordLayout(t *testing.T) {
	dek, err := contentcrypto.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	u := types.WriteUpload{ID: types.StagingInodeBase + 7}
	data := make([]byte, types.AeadRecordPlaintext+123)
	for i := range data {
		data[i] = byte(i)
	}
	sealed, err := sealChunk(dek, u, 0, data)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := types.AeadStoredSize(int64(len(data)))
	if int64(len(sealed)) != want {
		t.Fatalf("sealed %d != stored %d", len(sealed), want)
	}
	if bytes.Contains(sealed, data[:64]) {
		t.Fatal("sealed chunk leaks plaintext")
	}
	in := types.Inode{ID: 1, Generation: 1, Content: &types.ContentVersion{ID: u.ID}}
	ch := types.ChunkInfo{Index: 0, Size: int64(len(sealed)), LogicalSize: int64(len(data)), Encoding: types.AeadRecordEncoding, ChecksumKnown: true, Checksum: types.CRC32C(sealed)}
	var out []byte
	for i := 0; ; i++ {
		start, length, _, err := types.AeadRecordExtent(i, int64(len(data)))
		if err != nil {
			break
		}
		plain, err := contentcrypto.OpenRecord(dek, types.ChunkID(u.ID, 0), u.ID, uint64(i), sealed[start:start+length])
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		out = append(out, plain...)
	}
	if !bytes.Equal(out, data) {
		t.Fatal("record-by-record decrypt mismatch")
	}
	_ = ch
	_ = in
}

// TestSealChunkRejectsTamperedAAD 封装时换内容身份（AAD 绑定）必须解不开：
// 同一 DEK 对不同 upload/generation 的记录相互不可用。
func TestSealChunkRejectsTamperedAAD(t *testing.T) {
	dek, _ := contentcrypto.NewDEK()
	u := types.WriteUpload{ID: types.StagingInodeBase + 9}
	data := []byte("aead binding check payload")
	sealed, err := sealChunk(dek, u, 2, data)
	if err != nil {
		t.Fatal(err)
	}
	start, length, _, _ := types.AeadRecordExtent(0, int64(len(data)))
	if _, err := contentcrypto.OpenRecord(dek, types.ChunkID(u.ID, 2), u.ID+1, 0, sealed[start:start+length]); err == nil {
		t.Fatal("wrong generation opened the record")
	}
	if _, err := contentcrypto.OpenRecord(dek, types.ChunkID(u.ID, 3), u.ID, 0, sealed[start:start+length]); err == nil {
		t.Fatal("wrong object opened the record")
	}
	sealed[start+length-1] ^= 0xff
	if _, err := contentcrypto.OpenRecord(dek, types.ChunkID(u.ID, 2), u.ID, 0, sealed[start:start+length]); err == nil {
		t.Fatal("tampered tag opened the record")
	}
}

// TestAEADProbeFallsBackToPlain KEK 未配置（409）或端点不存在（404）时探测
// 必须静默回退 plain，不产生 enabled 的 aeadUpload。
func TestAEADProbeFallsBackToPlain(t *testing.T) {
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/content-key/prepare", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusConflict)
	})
	master := httptest.NewServer(mux)
	t.Cleanup(master.Close)

	c, err := NewSecure(master.URL, &tls.Config{InsecureSkipVerify: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetSession("sess"); err != nil {
		t.Fatal(err)
	}
	a := newAeadUpload()
	if err := a.probe(context.Background(), c, types.WriteUpload{ID: types.StagingInodeBase + 1}); err != nil || a.enabled {
		t.Fatalf("409 should be compliant fallback: enabled=%v err=%v", a.enabled, err)
	}
	if a.enabled {
		t.Fatal("fallback upload stayed enabled")
	}
	if hits.Load() == 0 {
		t.Fatal("probe did not query the master")
	}
}

// TestProbeDowngradeLoggedNotSilent：探测遇 500 时默认按 plain 继续（老集群
// 兼容），requireEncryption 打开后同错误必须阻止 enabled 且不吞日志语义。
func TestProbeDowngradePolicy(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/content-key/prepare", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	master := httptest.NewServer(mux)
	t.Cleanup(master.Close)

	c, err := NewSecure(master.URL, &tls.Config{InsecureSkipVerify: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetSession("sess"); err != nil {
		t.Fatal(err)
	}
	u := types.WriteUpload{ID: types.StagingInodeBase + 5}

	plain := newAeadUpload()
	if err := plain.probe(context.Background(), c, u); err != nil {
		t.Fatalf("default policy should tolerate 500: %v", err)
	}
	if plain.enabled {
		t.Fatal("fallback upload stayed enabled")
	}

	c.SetRequireEncryption()
	strict := newAeadUpload()
	if err := strict.probe(context.Background(), c, u); err == nil {
		t.Fatal("strict policy swallowed probe failure")
	}
	if !c.RequireEncryption() {
		t.Fatal("require flag not retained")
	}
}
