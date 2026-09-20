package node

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"atoll/pkg/types"
)

// 元数据备份 blob 存储：master HA 第一阶段用节点当元数据的灾备后端。
//
// 与普通对象(objects/，uint64 命名、参与孤块 GC)彻底物理隔离——单独的 meta-backup/
// 目录、字符串 key。隔离的意义是安全：孤块扫描只走 objects/，天然够不着这里的元数据
// blob，不必靠"记得跳过某段 ID"(见 HA 设计决策点 5)。
//
// key 语义由 master 侧定义(如 snapshot-<ver>-<chunk>、wal-<ver>-<seg>、manifest)；
// 节点这层只做安全的 KV blob 存取，不解释 key。

const metaBackupDir = "meta-backup"

// validMetaKey 限制 key 字符集，防路径穿越。字母/数字/._- 足够表达 master 的命名。
func validMetaKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for _, r := range key {
		ok := r == '_' || r == '-' || r == '.' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	// 额外挡掉 "." / ".." 与前导点串（validMetaKey 已禁 '/'，这里防纯点名）。
	if key == "." || key == ".." {
		return false
	}
	return true
}

func (n *Node) metaBlobPath(key string) string {
	return filepath.Join(n.dataDir, metaBackupDir, key)
}

// handleMetaPut PUT /meta-backup/{key} —— 写入一个元数据 blob（同 storeObject 的
// 临时文件+fsync+原子改名+目录 fsync 持久化模式；带可选 CRC32C 校验）。
func (n *Node) handleMetaPut(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validMetaKey(key) {
		httpError(w, http.StatusBadRequest, "invalid meta key")
		return
	}
	size, err := n.storeMetaBlob(key, r.Body, parseChecksumHeader(r))
	if err != nil {
		if strings.Contains(err.Error(), "checksum mismatch") {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("put meta blob %s: %v", key, err)
		httpError(w, http.StatusInternalServerError, "write meta blob failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"size": size})
}

// handleMetaGet GET /meta-backup/{key} —— 读回一个元数据 blob。
func (n *Node) handleMetaGet(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validMetaKey(key) {
		httpError(w, http.StatusBadRequest, "invalid meta key")
		return
	}
	f, err := os.Open(n.metaBlobPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			httpError(w, http.StatusNotFound, "meta blob not found")
			return
		}
		httpError(w, http.StatusInternalServerError, "open meta blob failed")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, f)
}

// handleMetaDelete DELETE /meta-backup/{key} —— 删除一个元数据 blob（幂等）。
func (n *Node) handleMetaDelete(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validMetaKey(key) {
		httpError(w, http.StatusBadRequest, "invalid meta key")
		return
	}
	if err := os.Remove(n.metaBlobPath(key)); err != nil && !os.IsNotExist(err) {
		httpError(w, http.StatusInternalServerError, "delete meta blob failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleMetaList GET /meta-backup —— 列出本机全部元数据 blob 的 key 与大小。
// master 恢复时向多台节点问 manifest/枚举现存快照用。
func (n *Node) handleMetaList(w http.ResponseWriter, _ *http.Request) {
	type blobInfo struct {
		Key  string `json:"key"`
		Size int64  `json:"size"`
	}
	dir := filepath.Join(n.dataDir, metaBackupDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []blobInfo{})
			return
		}
		httpError(w, http.StatusInternalServerError, "list meta blobs failed")
		return
	}
	out := make([]blobInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, blobInfo{Key: e.Name(), Size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	writeJSON(w, http.StatusOK, out)
}

// storeMetaBlob 落盘一个元数据 blob，返回大小。持久化模式同 storeObject：
// 临时文件 → 边写边算 CRC → 校验 → Sync → 原子改名 → 目录 fsync。
// 不计入 n.used（元数据备份不参与容量计费，与数据块分开）。
func (n *Node) storeMetaBlob(key string, r io.Reader, expectCRC uint32) (int64, error) {
	blobPath := n.metaBlobPath(key)
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(blobPath), ".tmp-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	crc := types.NewCRC32C()
	size, err := io.Copy(tmp, io.TeeReader(r, crc))
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return 0, err
	}
	if expectCRC != 0 && crc.Sum32() != expectCRC {
		tmp.Close()
		os.Remove(tmpName)
		return 0, fmt.Errorf("checksum mismatch: got %08x want %08x", crc.Sum32(), expectCRC)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return 0, err
	}
	if err := os.Rename(tmpName, blobPath); err != nil {
		os.Remove(tmpName)
		return 0, err
	}
	if dir, err := os.Open(filepath.Dir(blobPath)); err == nil {
		if serr := dir.Sync(); serr != nil {
			log.Printf("fsync meta-backup dir: %v", serr)
		}
		dir.Close()
	}
	return size, nil
}
