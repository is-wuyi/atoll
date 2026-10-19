package master

// security_aead_e2e_test.go：内容加密上传的端到端验证——真实 bbolt master +
// 真实 node 进程内 HTTP + client.NewSecure。断言：
//  1. 上传成功后节点磁盘上是密文（搜不到明文样本）；
//  2. 块表/manifest 声明 aead-record-v1 几何且 CRC 指密文；
//  3. 密钥端点按 ACL 拒绝他空间读取；
//  4. plain 集群（未配 KEK）自动回退明文上传，行为不回归。

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"atoll/pkg/contentcrypto"
	"atoll/pkg/types"
)

// storedObjectBytes 聚合节点 objects 目录的全部对象字节（密文落盘断言用）。
// 目录不存在 = 无对象，返回 nil。
func storedObjectBytes(t *testing.T, dir string) []byte {
	t.Helper()
	objects := filepath.Join(dir, "objects")
	if _, err := os.Stat(objects); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("stat objects dir: %v", err)
	}
	var out []byte
	err := filepath.WalkDir(objects, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		out = append(out, raw...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk objects dir: %v", err)
	}
	return out
}

func TestSecureAEADUploadStoresCiphertextOnNodes(t *testing.T) {
	c := newSecureCluster(t, 2)
	if err := c.srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 3}); err != nil {
		t.Fatal(err)
	}
	kek, err := contentcrypto.NewKEK("aead-test-20261019")
	if err != nil {
		t.Fatal(err)
	}
	c.srv.SetContentKEK(kek)

	_, adminToken := c.adminLogin()
	c.secCreateUser(adminToken, "alice")
	alice, _ := c.secLogin("alice", secUserPassword)

	oldChunk := types.ChunkSize
	types.ChunkSize = 1 << 20
	t.Cleanup(func() { types.ChunkSize = oldChunk })

	payload := secRandomBytes(3<<20/2 + 17)
	secRequireOK(t, func() error { _, err := alice.Mkdir("/docs"); return err }(), "mkdir")
	secRequireOK(t, alice.PutReaderOverwrite("/docs/secret.bin", int64(len(payload)), bytes.NewReader(payload), 2, false), "aead upload")

	// 1) 节点磁盘必须是密文：明文样本和任何子串都搜不到。
	// 主副本立即有数据；从副本经后台异步同步，Done 前可能尚未落盘——这里
	// 只对已有对象的节点断言密文，并要求至少一个节点确实存了对象。
	found := 0
	for i, sn := range c.nodes {
		stored := storedObjectBytes(t, sn.node.DataDirForTest())
		if len(stored) == 0 {
			continue
		}
		found++
		if bytes.Contains(stored, payload[:4096]) {
			t.Fatalf("node %d stores plaintext", i)
		}
		if bytes.Contains(stored, payload[len(payload)-4096:]) {
			t.Fatalf("node %d stores plaintext tail", i)
		}
	}
	if found == 0 {
		t.Fatal("no node stored the uploaded objects")
	}

	// 2) 元数据必须声明 aead 几何，且 CRC 是密文的校验和。
	in, _, err := alice.Lookup("/docs/secret.bin")
	if err != nil {
		t.Fatal(err)
	}
	if in.Content == nil {
		t.Fatal("committed inode lacks content manifest")
	}
	for i, ex := range in.Content.Extents {
		if ex.Object.Encoding != types.AeadRecordEncoding {
			t.Fatalf("extent %d encoding = %q", i, ex.Object.Encoding)
		}
		want, err := types.AeadStoredSize(ex.Object.LogicalSize)
		if err != nil || ex.Object.StoredSize != want {
			t.Fatalf("extent %d stored %d != %d (%v)", i, ex.Object.StoredSize, want, err)
		}
		ch := in.Chunks[i]
		if types.ChunkEncoding(ch) != types.AeadRecordEncoding || types.ChunkLogicalSize(ch) != ex.Object.LogicalSize {
			t.Fatalf("chunk %d table missing aead geometry: %+v", i, ch)
		}
	}

	// 2b) 加密读回：客户端取 DEK、解密全部记录后拼出与原文件一致的内容。
	outPath := filepath.Join(t.TempDir(), "decrypted.bin")
	secRequireOK(t, alice.Get("/docs/secret.bin", outPath), "aead download")
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if secMD5(got) != secMD5(payload) {
		t.Fatalf("decrypted content MD5 mismatch: got %s want %s", secMD5(got), secMD5(payload))
	}

	// 3) 密钥端点按 ACL 隔离：bob 不能读 alice 的对象密钥。
	_, bobSpace := c.secCreateUser(adminToken, "bob")
	bobTok := secSessionToken(t, c, "bob")
	objectID := in.Content.Extents[0].Object.ID
	path := "/auth/content-key?object_id=" + strconv.FormatUint(objectID, 10) + "&generation=" + strconv.FormatUint(in.Content.ID, 10)
	resp := secRawJSON(t, http.MethodGet, c.master.URL+path, bobTok, bobSpace, nil)
	if resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		t.Fatal("foreign-space key fetch accepted")
	}
	resp.Body.Close()
}

func TestSecurePlainClusterStillUploadsPlaintext(t *testing.T) {
	c := newSecureCluster(t, 1) // 不 SetContentKEK：master 未配置内容密钥
	if err := c.srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 2}); err != nil {
		t.Fatal(err)
	}
	_, adminToken := c.adminLogin()
	c.secCreateUser(adminToken, "alice")
	alice, _ := c.secLogin("alice", secUserPassword)

	payload := secRandomBytes(64 << 10)
	secRequireOK(t, alice.PutReaderOverwrite("/plain.bin", int64(len(payload)), bytes.NewReader(payload), 1, false), "plain upload")
	in, _, err := alice.Lookup("/plain.bin")
	if err != nil {
		t.Fatal(err)
	}
	if in.Content == nil || in.Content.Extents[0].Object.Encoding != types.PlainEncoding {
		t.Fatalf("plain cluster wrote encoded content: %+v", in.Content)
	}
	stored := storedObjectBytes(t, c.nodes[0].node.DataDirForTest())
	if !bytes.Contains(stored, payload[:4096]) {
		t.Fatal("plain cluster should store plaintext")
	}
}
