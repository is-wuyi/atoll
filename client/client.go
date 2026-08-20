// Package client 实现 atoll 的 CLI 客户端：
// 元数据操作走 master，数据读写直连存储节点。
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"

	"atoll/pkg/types"
)

type Client struct {
	MasterURL string
	HTTP      *http.Client
}

func New(masterURL string) *Client {
	return &Client{
		MasterURL: strings.TrimRight(masterURL, "/"),
		HTTP:      http.DefaultClient,
	}
}

// ---- 元数据操作 ----

// Mkdir 创建目录（递归创建由调用方逐层调用，MVP 先只支持单层）。
func (c *Client) Mkdir(path string) (types.Inode, error) {
	var in types.Inode
	err := c.postJSON("/dirs", map[string]string{"path": path}, &in)
	return in, err
}

// Ls 列出目录直接子项。
func (c *Client) Ls(path string) ([]types.Inode, error) {
	var kids []types.Inode
	err := c.getJSON("/dirs/children?"+queryPath(path), &kids)
	return kids, err
}

// Rm 删除文件或空目录。
func (c *Client) Rm(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.MasterURL+"/entry?"+queryPath(path), nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return statusError(resp)
}

// lookup 查询路径的 inode 与副本节点详情。
func (c *Client) lookup(path string) (types.Inode, []types.NodeInfo, error) {
	var out struct {
		Inode types.Inode     `json:"inode"`
		Nodes []types.NodeInfo `json:"nodes"`
	}
	if err := c.getJSON("/meta?"+queryPath(path), &out); err != nil {
		return types.Inode{}, nil, err
	}
	return out.Inode, out.Nodes, nil
}

// ---- 数据操作 ----

// Put 上传本地文件：master 建元数据 → 直连节点写数据 → commit 大小。
func (c *Client) Put(localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local: %w", err)
	}
	defer f.Close()
	// 先取大小：http 客户端发送请求体后会关闭 body，之后不能再 Stat。
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat local: %w", err)
	}

	// 1. 在 master 创建文件记录并获取副本节点（阶段1副本数 1）。
	var created struct {
		Inode types.Inode     `json:"inode"`
		Nodes []types.NodeInfo `json:"nodes"`
	}
	if err := c.postJSON("/files", map[string]any{"path": remotePath, "replicas": 1}, &created); err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	if len(created.Nodes) == 0 {
		return fmt.Errorf("master 未分配任何存储节点")
	}

	// 2. 直连第一个节点写入数据。
	if err := c.putObject(created.Nodes[0].Addr, created.Inode.ID, f); err != nil {
		return fmt.Errorf("write object: %w", err)
	}

	// 3. commit 实际大小。
	return c.postJSON("/files/commit", map[string]any{"inode_id": created.Inode.ID, "size": st.Size()}, nil)
}

// Get 下载远程文件：查元数据 → 随机挑一个副本节点直连读。
func (c *Client) Get(remotePath, localPath string) error {
	in, nodes, err := c.lookup(remotePath)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return fmt.Errorf("无可用副本节点")
	}
	n := nodes[rand.Intn(len(nodes))]

	resp, err := c.HTTP.Get(fmt.Sprintf("http://%s/objects/%d", n.Addr, in.ID))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("节点返回 %d", resp.StatusCode)
	}

	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

// putObject 向节点写入对象数据。
func (c *Client) putObject(nodeAddr string, inodeID uint64, r io.Reader) error {
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/objects/%d", nodeAddr, inodeID), r)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return statusError(resp)
}

// ---- HTTP 工具 ----

func (c *Client) postJSON(path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Post(c.MasterURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return err
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) getJSON(path string, out any) error {
	resp, err := c.HTTP.Get(c.MasterURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// statusError 把非 2xx 响应转成带 master 错误信息的 error。
func statusError(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&e); err == nil && e.Error != "" {
		return fmt.Errorf("http %d: %s", resp.StatusCode, e.Error)
	}
	return fmt.Errorf("http %d", resp.StatusCode)
}

// queryPath 构造 path=... 查询串。
func queryPath(p string) string {
	return url.Values{"path": {p}}.Encode()
}
