// Package console 实现 atoll 的 web 管理后台：独立进程、服务端渲染，
// 通过集群 token 调 master 的只读 /admin/* API，自带控制台用户与会话。
package console

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"atoll/master"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

// masterClient 调用 master 的 read-model API。
// http 用集群 token（只读）；adminHTTP 用 admin token（破坏性操作如 GC 执行）。
type masterClient struct {
	base      string
	http      *http.Client
	adminHTTP *http.Client
}

func newMasterClient(masterURL string, token, adminToken auth.Token, tlsCfg *tls.Config) *masterClient {
	if adminToken == "" {
		adminToken = token // 未单设 admin token 时回退用集群 token
	}
	return &masterClient{
		base:      strings.TrimRight(masterURL, "/"),
		http:      &http.Client{Timeout: 15 * time.Second, Transport: auth.HTTPTransport(token, tlsCfg, nil)},
		adminHTTP: &http.Client{Timeout: 30 * time.Second, Transport: auth.HTTPTransport(adminToken, tlsCfg, nil)},
	}
}

func (c *masterClient) getJSON(path string, out any) error {
	resp, err := c.http.Get(c.base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("master %s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Overview 镜像 master overviewResp（不导出 master 内部类型）。
type Overview struct {
	Namespace     string `json:"namespace"`
	NodesTotal    int    `json:"nodes_total"`
	NodesAlive    int    `json:"nodes_alive"`
	TotalBytes    int64  `json:"total_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
	Files         int    `json:"files"`
	Staging       int    `json:"staging"`
	Objects       int    `json:"objects"`
	DegradedFiles int    `json:"degraded_files"`
}

// NodeView 镜像 master nodeView。
type NodeView struct {
	ID            uint64    `json:"id"`
	Addr          string    `json:"addr"`
	TotalBytes    int64     `json:"total_bytes"`
	UsedBytes     int64     `json:"used_bytes"`
	FreeBytes     int64     `json:"free_bytes"`
	UsedPercent   float64   `json:"used_percent"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	Alive         bool      `json:"alive"`
}

// replicaEntry 是 /meta 响应里的节点条目（地址 + 是否已落盘）。
type replicaEntry struct {
	types.NodeInfo
	Done bool `json:"done"`
}

func (c *masterClient) overview() (Overview, error) {
	var o Overview
	return o, c.getJSON("/admin/overview", &o)
}

func (c *masterClient) nodes() ([]NodeView, error) {
	var n []NodeView
	return n, c.getJSON("/admin/nodes", &n)
}

func (c *masterClient) repairs() (master.RepairSnapshot, error) {
	var r master.RepairSnapshot
	return r, c.getJSON("/admin/repairs", &r)
}

// DegradedItem 镜像 master degradedItem。
type DegradedItem struct {
	Path     string `json:"path"`
	Inode    uint64 `json:"inode"`
	Chunked  bool   `json:"chunked"`
	Index    int    `json:"index"`
	Healthy  int    `json:"healthy"`
	Target   int    `json:"target"`
	SinceSec int64  `json:"since_sec"`
	Warned   bool   `json:"warned"`
}

func (c *masterClient) integrity() ([]DegradedItem, error) {
	var items []DegradedItem
	return items, c.getJSON("/admin/integrity", &items)
}

// GCNodeReport 镜像 master.GCNodeReport（避免 UI 直接依赖 scanner 内部类型）。
type GCNodeReport struct {
	NodeID      uint64 `json:"node_id"`
	NodeAddr    string `json:"node_addr"`
	OrphanBytes int64  `json:"orphan_bytes"`
	Deleted     int    `json:"deleted"`
	Orphans     []struct {
		ID   uint64 `json:"id"`
		Size int64  `json:"size"`
	} `json:"orphans"`
}

// gc 调用 master POST /admin/gc。execute=true 需 adminToken（master 侧路径鉴权）。
// dry-run 用集群 token 即可；执行删除时 token 由 postGC 用 adminToken 注入。
func (c *masterClient) gc(execute bool) ([]GCNodeReport, error) {
	body, _ := json.Marshal(map[string]bool{"execute": execute})
	req, err := http.NewRequest(http.MethodPost, c.base+"/admin/gc", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	cl := c.http
	if execute {
		cl = c.adminHTTP // 破坏性操作用 adminToken
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("gc: %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var reports []GCNodeReport
	return reports, json.NewDecoder(resp.Body).Decode(&reports)
}

// metaBackup 读元数据备份状态（master GET /admin/metabackup）。
func (c *masterClient) metaBackup() (master.BackupStatus, error) {
	var st master.BackupStatus
	return st, c.getJSON("/admin/metabackup", &st)
}

// triggerBackup 手动触发一次元数据全量备份（master POST /admin/metabackup/trigger）。
// 走 adminHTTP（破坏性/有副作用，master 侧 adminToken 鉴权）。
func (c *masterClient) triggerBackup() error {
	req, err := http.NewRequest(http.MethodPost, c.base+"/admin/metabackup/trigger", nil)
	if err != nil {
		return err
	}
	resp, err := c.adminHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("触发备份: %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (c *masterClient) lookup(path string) (types.Inode, []replicaEntry, error) {
	var out struct {
		Inode types.Inode    `json:"inode"`
		Nodes []replicaEntry `json:"nodes"`
	}
	err := c.getJSON("/meta?"+url.Values{"path": {path}}.Encode(), &out)
	return out.Inode, out.Nodes, err
}

func (c *masterClient) children(path string) ([]types.Inode, error) {
	var kids []types.Inode
	err := c.getJSON("/dirs/children?"+url.Values{"path": {path}}.Encode(), &kids)
	return kids, err
}

// deleteEntry 删除文件/空目录（master DELETE /entry）。走 adminHTTP（破坏性）。
func (c *masterClient) deleteEntry(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.base+"/entry?"+url.Values{"path": {path}}.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.adminHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("delete %s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
