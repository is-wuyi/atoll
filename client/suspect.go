package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"atoll/pkg/types"
)

// ReportSuspect 报告整对象副本与读者持有的版本不符；服务端只标记待修复，不删除数据。
// 不回退到旧的无版本删除接口，避免滚动升级时把旧校验和的误报变成数据丢失。
func (c *Client) ReportSuspect(ctx context.Context, in types.Inode, nodeID uint64) error {
	body, err := json.Marshal(struct {
		InodeID    uint64 `json:"inode_id"`
		NodeID     uint64 `json:"node_id"`
		Generation uint64 `json:"generation"`
		Size       int64  `json:"size"`
		Checksum   uint32 `json:"checksum"`
	}{in.ID, nodeID, in.Generation, in.Size, in.Checksum})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.MasterURL+"/files/suspect", bytes.NewReader(body))
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
