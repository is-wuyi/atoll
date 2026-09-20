package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"atoll/pkg/types"
)

// 元数据 blob 的 PUT/GET/DELETE/LIST 全链路，含 CRC 校验与隔离性。
func TestMetaBackupPutGetDeleteList(t *testing.T) {
	_, ts := newTestNode(t)
	put := func(key string, body []byte, crc uint32) *http.Response {
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/meta-backup/"+key, bytes.NewReader(body))
		if crc != 0 {
			req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", crc))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	body := []byte("snapshot-bytes-v1")
	crc := types.CRC32C(body)
	resp := put("snapshot-1-0", body, crc)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT 状态 = %d", resp.StatusCode)
	}

	// GET 读回一致。
	g, err := http.Get(ts.URL + "/meta-backup/snapshot-1-0")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(g.Body)
	g.Body.Close()
	if !bytes.Equal(got, body) {
		t.Fatalf("GET 内容不符: %q", got)
	}

	// LIST 应含该 key。
	put("wal-1-0", []byte("wal-seg"), 0).Body.Close()
	l, _ := http.Get(ts.URL + "/meta-backup")
	var list []struct {
		Key  string `json:"key"`
		Size int64  `json:"size"`
	}
	json.NewDecoder(l.Body).Decode(&list)
	l.Body.Close()
	if len(list) != 2 {
		t.Fatalf("LIST 返回 %d 项，期望 2: %+v", len(list), list)
	}

	// DELETE 后 GET 404，且幂等（再删仍 204）。
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/meta-backup/snapshot-1-0", nil)
	d, _ := http.DefaultClient.Do(req)
	d.Body.Close()
	if d.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE 状态 = %d", d.StatusCode)
	}
	g2, _ := http.Get(ts.URL + "/meta-backup/snapshot-1-0")
	g2.Body.Close()
	if g2.StatusCode != http.StatusNotFound {
		t.Fatalf("删后 GET 状态 = %d，期望 404", g2.StatusCode)
	}
	req2, _ := http.NewRequest(http.MethodDelete, ts.URL+"/meta-backup/snapshot-1-0", nil)
	d2, _ := http.DefaultClient.Do(req2)
	d2.Body.Close()
	if d2.StatusCode != http.StatusNoContent {
		t.Fatalf("幂等 DELETE 状态 = %d", d2.StatusCode)
	}
}

// CRC 不符必须拒绝落盘。
func TestMetaBackupChecksumMismatch(t *testing.T) {
	_, ts := newTestNode(t)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/meta-backup/bad", bytes.NewReader([]byte("real")))
	req.Header.Set(types.ChecksumHeader, "deadbeef") // 错的
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("CRC 不符应 400，got %d", resp.StatusCode)
	}
	// 不应残留。
	g, _ := http.Get(ts.URL + "/meta-backup/bad")
	g.Body.Close()
	if g.StatusCode != http.StatusNotFound {
		t.Fatalf("拒绝落盘后仍能 GET: %d", g.StatusCode)
	}
}

// 非法 key（路径穿越/非法字符）必须挡下。
func TestMetaBackupRejectsBadKey(t *testing.T) {
	_, ts := newTestNode(t)
	for _, key := range []string{"..%2f..%2fetc", "a b", "with/slash"} {
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/meta-backup/"+key, bytes.NewReader([]byte("x")))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue // 传输层就拒了也算挡下
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusCreated {
			t.Fatalf("非法 key %q 不应被接受", key)
		}
	}
}

// 隔离性：元数据 blob 不出现在 /admin/objects（孤块 GC 的数据源），
// 反之普通对象也不出现在 /meta-backup。GC 天然碰不到元数据。
func TestMetaBackupIsolatedFromObjects(t *testing.T) {
	_, ts := newTestNode(t)
	// 存一个普通对象。
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/777", bytes.NewReader([]byte("data-block")))
	r1, _ := http.DefaultClient.Do(req)
	r1.Body.Close()
	// 存一个元数据 blob。
	req2, _ := http.NewRequest(http.MethodPut, ts.URL+"/meta-backup/manifest", bytes.NewReader([]byte("mf")))
	r2, _ := http.DefaultClient.Do(req2)
	r2.Body.Close()

	// /admin/objects 只应见 777，不见 manifest。
	ao, _ := http.Get(ts.URL + "/admin/objects")
	var objs []struct {
		ID   uint64 `json:"id"`
		Size int64  `json:"size"`
	}
	json.NewDecoder(ao.Body).Decode(&objs)
	ao.Body.Close()
	if len(objs) != 1 || objs[0].ID != 777 {
		t.Fatalf("/admin/objects 应只含对象 777，got %+v", objs)
	}

	// /meta-backup 只应见 manifest。
	ml, _ := http.Get(ts.URL + "/meta-backup")
	var blobs []struct {
		Key string `json:"key"`
	}
	json.NewDecoder(ml.Body).Decode(&blobs)
	ml.Body.Close()
	if len(blobs) != 1 || blobs[0].Key != "manifest" {
		t.Fatalf("/meta-backup 应只含 manifest，got %+v", blobs)
	}
}
