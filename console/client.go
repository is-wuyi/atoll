// Package console 实现 atoll 的 web 管理后台：独立进程、服务端渲染，
// 通过集群 token 调 master 的只读 /admin/* API，自带控制台用户与会话。
package console

import (
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
type masterClient struct {
	base string
	http *http.Client
}

func newMasterClient(masterURL string, token auth.Token, tlsCfg *tls.Config) *masterClient {
	return &masterClient{
		base: strings.TrimRight(masterURL, "/"),
		http: &http.Client{Timeout: 15 * time.Second, Transport: auth.HTTPTransport(token, tlsCfg, nil)},
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
