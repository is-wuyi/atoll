package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"atoll/pkg/types"
)

// ReportChunkSuspect 报告分块文件某块副本与块表不符（CRC 不符或长度不符）：
// POST /files/chunks/suspect，携带完整版本 tuple（FileID、generation、块下标、对象 ID、
// size、checksum）。master 按 tuple 与当前 inode 精确匹配（CAS 语义）：只撤销该节点
// 的 Done 并标 suspect 待修复，不删除任何对象；缺失/旧代上报返回 200 marked:false
// ——旧版本读者既不影响新版本，也不会像旧 /files/corrupt 通道那样删掉唯一副本。
func (c *Client) ReportChunkSuspect(ctx context.Context, inode types.Inode, chunk types.ChunkInfo, nodeID uint64) error {
	body, err := json.Marshal(struct {
		InodeID    uint64 `json:"inode_id"`
		Generation uint64 `json:"generation"`
		ChunkIndex int    `json:"chunk_index"`
		ObjectID   uint64 `json:"object_id"`
		NodeID     uint64 `json:"node_id"`
		Size       int64  `json:"size"`
		Checksum   uint32 `json:"checksum"`
	}{
		InodeID:    inode.ID,
		Generation: inode.Generation,
		ChunkIndex: chunk.Index,
		ObjectID:   types.ChunkObjID(chunk, inode.ID),
		NodeID:     nodeID,
		Size:       chunk.Size,
		Checksum:   chunk.Checksum,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.MasterURL+"/files/chunks/suspect", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return err
}
