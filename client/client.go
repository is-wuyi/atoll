// Package client 实现 atoll 的 CLI 客户端：
// 元数据操作走 master，数据读写直连存储节点。
package client

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"atoll/pkg/auth"
	"atoll/pkg/types"
)

type Client struct {
	MasterURL string
	HTTP      *http.Client
	// putTimeout 覆盖块 PUT 的上下文超时；0 = 按块大小公式。测试注入小值以在秒级
	// 验证"节点卡死→超时→换节点"，无需真等 150s。
	putTimeout time.Duration
}

// SetPutTimeout 覆盖块 PUT 超时（测试用，注入小值快速验证超时+换节点）。
func (c *Client) SetPutTimeout(d time.Duration) { c.putTimeout = d }

// metadataTimeout 是 master 元数据请求（assign/commit/create/rm 等）的单次超时。
// 这些调用短小，卡住必是节点失联——绝不能无限挂起（否则上传会永久卡在 wg.Wait）。
const metadataTimeout = 30 * time.Second

// ioTimeout 按数据大小给出对象 PUT/GET 的单次请求超时：给足慢速链路，封顶 150s，
// 卡住即失败换节点/重试而非永久挂起。putTimeout 非 0（测试注入）时直接用它。
func (c *Client) ioTimeout(size int64) time.Duration {
	if c.putTimeout != 0 {
		return c.putTimeout
	}
	t := 30*time.Second + time.Duration(size/(512*1024))*time.Second
	if t > 150*time.Second {
		t = 150 * time.Second
	}
	return t
}

// New 创建客户端。token 为空 = 兼容模式（不注入认证头，连未启认证的旧集群）。
func New(masterURL string) *Client {
	return NewWithToken(masterURL, "")
}

// NewWithToken 创建带认证 token 的客户端（自动注入 Bearer 头）。
func NewWithToken(masterURL string, token auth.Token) *Client {
	return &Client{
		MasterURL: strings.TrimRight(masterURL, "/"),
		HTTP:      &http.Client{Transport: &auth.Transport{Token: token}},
	}
}

// NewWithTLS 创建带认证 + TLS 配置的客户端。tlsCfg 为空等价于 NewWithToken。
// 直连存储节点用的 scheme 从 masterURL 推导（https:// → 节点也走 https）。
func NewWithTLS(masterURL string, token auth.Token, tlsCfg *tls.Config) *Client {
	return &Client{
		MasterURL: strings.TrimRight(masterURL, "/"),
		HTTP:      &http.Client{Transport: auth.HTTPTransport(token, tlsCfg, nil)},
	}
}

// scheme 返回直连存储节点用的 URL scheme，从 MasterURL 推导。
func (c *Client) scheme() string {
	if strings.HasPrefix(c.MasterURL, "https://") {
		return "https"
	}
	return "http"
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

// ClusterCapacity 返回集群总容量与已用字节（供挂载层 Statfs 报告可用空间）。
// 只累计**存活**节点：此前用 /admin/overview 的全量求和，死节点的声明容量也被计入，
// 虚报可用空间 → Finder 放行必然中途失败的拷贝（审计 #7）。控制台的全局视图仍走
// /admin/overview（"名义容量"语义保留在那里）。
func (c *Client) ClusterCapacity() (total, used int64, err error) {
	var nodes []struct {
		TotalBytes int64 `json:"total_bytes"`
		UsedBytes  int64 `json:"used_bytes"`
		Alive      bool  `json:"alive"`
	}
	if err := c.getJSON("/admin/nodes", &nodes); err != nil {
		return 0, 0, err
	}
	for _, n := range nodes {
		if n.Alive {
			total += n.TotalBytes
			used += n.UsedBytes
		}
	}
	return total, used, nil
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

// Replica 是 Lookup 返回的节点条目：地址 + 副本同步状态。
type Replica struct {
	ID   uint64 `json:"id"`
	Addr string `json:"addr"`
	Done bool   `json:"done"`
}

// Lookup 查询路径的 inode 与副本节点详情（导出供挂载层使用）。
func (c *Client) Lookup(path string) (types.Inode, []Replica, error) {
	var out struct {
		Inode types.Inode `json:"inode"`
		Nodes []Replica   `json:"nodes"`
	}
	if err := c.getJSON("/meta?"+queryPath(path), &out); err != nil {
		return types.Inode{}, nil, err
	}
	return out.Inode, out.Nodes, nil
}

// lookup 内部使用（保持旧名）。
func (c *Client) lookup(path string) (types.Inode, []Replica, error) {
	return c.Lookup(path)
}

// Rename 同目录内改名。
func (c *Client) Rename(path, newName string) error {
	return c.postJSON("/entry/rename", map[string]string{"path": path, "new_name": newName}, nil)
}

// ---- 数据操作 ----

// Put 上传本地文件：master 建元数据 → 直连主副本节点写数据 → commit 大小。
// replicas 为期望副本数（含主副本）；从副本由主副本后台异步同步。
func (c *Client) Put(localPath, remotePath string, replicas int) error {
	return c.PutOverwrite(localPath, remotePath, replicas, false)
}

// PutOverwrite 上传本地文件，支持 overwrite 参数。
// overwrite 为 true 时允许覆盖同名文件。
func (c *Client) PutOverwrite(localPath, remotePath string, replicas int, overwrite bool) error {
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
	return c.PutReaderOverwrite(remotePath, st.Size(), f, replicas, overwrite)
}

// PutReader 从 io.Reader 上传：创建元数据 → 直连主副本写 → commit。
// 供 FUSE 挂载层在 flush 时把本地缓冲文件整体上传。
func (c *Client) PutReader(remotePath string, size int64, r io.Reader, replicas int) error {
	return c.PutReaderOverwrite(remotePath, size, r, replicas, false)
}

// PutReaderOverwrite 从 io.Reader 上传，支持 overwrite 参数。
// overwrite 为 true 时允许覆盖同名文件。
func (c *Client) PutReaderOverwrite(remotePath string, size int64, r io.Reader, replicas int, overwrite bool) error {
	// 1. 在 master 创建文件记录并获取副本节点（第一个为主副本）。
	var created struct {
		Inode types.Inode      `json:"inode"`
		Nodes []types.NodeInfo `json:"nodes"`
	}
	if err := c.postJSON("/files", map[string]any{"path": remotePath, "replicas": replicas, "overwrite": overwrite}, &created); err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	if len(created.Nodes) == 0 {
		return fmt.Errorf("master 未分配任何存储节点")
	}

	// 2. 直连主副本写入数据，边传边算 CRC32C（流式上传无法预先知道校验和，
	//    故不带 PUT 头让 node 即时校验；改由 commit 落库、读取时按元数据比对）。
	//    带重试：主副本瞬时故障时，若源可重放（io.Seeker）则回到开头重传。
	//    此前 legacy 路径只 PUT 一次、无重试无换节点，一次抖动就整体失败。
	seeker, seekable := r.(io.Seeker)
	var crcVal uint32
	var putErr error
	for attempt := 1; attempt <= 3; attempt++ {
		hh := types.NewCRC32C()
		if putErr = c.putObject(created.Nodes[0].Addr, created.Inode.ID, io.TeeReader(r, hh), size); putErr == nil {
			crcVal = hh.Sum32()
			break
		}
		if !seekable {
			break // 不可重放，单次即止
		}
		if _, serr := seeker.Seek(0, io.SeekStart); serr != nil {
			break
		}
		time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
	}
	if putErr != nil {
		return fmt.Errorf("write object: %w", putErr)
	}

	// 3. commit 实际大小 + 校验和（主副本会随后异步推送到其余节点）。
	return c.postJSON("/files/commit", map[string]any{
		"inode_id": created.Inode.ID, "size": size, "checksum": crcVal,
	}, nil)
}

// Get 下载远程文件：查元数据 → 优先从已同步完成的副本随机挑一个直连读。
// 分块文件（Chunked=true）：按块表逐块拉取顺序拼装（每块内仍走副本故障转移）。
// 若暂无已完成副本（异步复制还在进行），退化为从任意副本尝试。
// 单个节点不可达/404 时自动转移到下一个副本（故障转移），全部失败才报错。
func (c *Client) Get(remotePath, localPath string) error {
	in, nodes, err := c.lookup(remotePath)
	if err != nil {
		return err
	}
	if in.Chunked {
		return c.getChunked(in, nodes, localPath)
	}
	if len(nodes) == 0 {
		return fmt.Errorf("无可用副本节点")
	}
	// Done 副本优先、组内随机打散做负载均衡；未 Done 的追加在后作兜底
	// （异步复制中可能已落盘只是上报延迟，或 Done 副本全宕时抢救数据）。
	// 此前是"整体 shuffle 再 stable-sort"，绕了一圈；分组各自 shuffle 更直观。
	var done, pending []Replica
	for _, nd := range nodes {
		if nd.Done {
			done = append(done, nd)
		} else {
			pending = append(pending, nd)
		}
	}
	rand.Shuffle(len(done), func(i, j int) { done[i], done[j] = done[j], done[i] })
	rand.Shuffle(len(pending), func(i, j int) { pending[i], pending[j] = pending[j], pending[i] })
	return c.getFromReplicas(in, append(done, pending...), localPath)
}

// getFromReplicas 依次尝试候选副本下载整对象到 localPath，带长度校验与故障转移。
func (c *Client) getFromReplicas(in types.Inode, candidates []Replica, localPath string) error {
	var lastErr error
	for _, n := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), c.ioTimeout(in.Size))
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s://%s/objects/%d", c.scheme(), n.Addr, in.ID), nil)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("节点 %s: %w", n.Addr, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cancel()
			lastErr = fmt.Errorf("节点 %s 返回 %d", n.Addr, resp.StatusCode)
			continue
		}
		out, err := os.Create(localPath)
		if err != nil {
			resp.Body.Close()
			cancel()
			return err
		}
		h := types.NewCRC32C()
		written, copyErr := io.Copy(out, io.TeeReader(resp.Body, h))
		closeErr := out.Close()
		resp.Body.Close()
		cancel()
		if copyErr != nil || closeErr != nil {
			return fmt.Errorf("写本地文件: %v / %v", copyErr, closeErr)
		}
		// 长度校验：读到的字节数必须等于元数据记录的大小。此前不校验，
		// 从内容较短/较慢的副本读到截断数据会被当成功返回（静默截断）。
		// 短读 → 换下一个副本重试（os.Create 会截断，重试覆盖不残留半份）。
		if written != in.Size {
			lastErr = fmt.Errorf("节点 %s: 短读 %d != 声明大小 %d", n.Addr, written, in.Size)
			continue
		}
		// 校验和：元数据有记录（非 0）且不符 → 该副本内容损坏，换下一个副本。
		if in.Checksum != 0 && h.Sum32() != in.Checksum {
			lastErr = fmt.Errorf("节点 %s: 校验和不符 %08x != %08x", n.Addr, h.Sum32(), in.Checksum)
			go func() {
				_ = c.ReportSuspect(context.Background(), in, n.ID)
			}()
			continue
		}
		return nil
	}
	return fmt.Errorf("所有副本读取失败，最后错误: %w", lastErr)
}

// ---- 分块上传（批次 C）----

// chunkAssignOut 是 POST /files/chunks 的响应。
type chunkAssignOut struct {
	Chunk types.ChunkInfo  `json:"chunk"`
	Nodes []types.NodeInfo `json:"nodes"`
}

// PutChunked 分块上传（不覆盖已存在文件）。
func (c *Client) PutChunked(localPath, remotePath string, replicas int) error {
	return c.PutChunkedOverwrite(localPath, remotePath, replicas, false)
}

// PutChunkedOverwrite 分块上传：64MB 固定块 + 流水线。
// staging 建档 → 块写满即异步上传（滞后最多一块）→ 全部落盘 → commit 原子换名。
// 任一环节失败：显式 abort staging（节点上已落盘的块由 master 通知回收）。
func (c *Client) PutChunkedOverwrite(localPath, remotePath string, replicas int, overwrite bool) error {
	return c.PutChunkedWithMinCopies(localPath, remotePath, replicas, 0, overwrite)
}

// PutChunkedWithMinCopies 分块上传 + 持久性档位（改进项3）。
// minCopies>0：commit 前 master 等每块 ≥N 个"Done 且存活"副本（409 重试轮询，
// 最长 15 分钟）；minCopies=0 = 现状（仅主副本 Done 即提交，从副本后台慢同步）。
func (c *Client) PutChunkedWithMinCopies(localPath, remotePath string, replicas, minCopies int, overwrite bool) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat local: %w", err)
	}
	return c.putChunkedCore(remotePath, st.Size(), f, replicas, minCopies, overwrite)
}

// PutChunkedReader 分块上传 io.Reader（不覆盖）。
func (c *Client) PutChunkedReader(remotePath string, size int64, r io.Reader, replicas int) error {
	return c.putChunkedCore(remotePath, size, r, replicas, 0, false)
}

// PutChunkedReaderWithMinCopies 分块上传 io.Reader + 持久性档位（mount Flush 等使用）。
// minCopies>0：commit 前轮询等待每块 ≥N 个"Done 且存活"副本。
func (c *Client) PutChunkedReaderWithMinCopies(remotePath string, size int64, r io.Reader, replicas, minCopies int, overwrite bool) error {
	return c.putChunkedCore(remotePath, size, r, replicas, minCopies, overwrite)
}

// putChunkedCore 分块上传核心：流水线（并发深度 2）+ 可选持久性档位。
// 读满一块即投入上传（信号量限并发，内存占用恒为 2 块 = 128MB），
// 全部块落盘后 commit 原子换名；任一环节失败显式 abort。
// minCopies>0 时 commit 遇 409（副本未到齐）轮询重试，最长 15 分钟。
func (c *Client) putChunkedCore(remotePath string, size int64, r io.Reader, replicas, minCopies int, overwrite bool) error {
	if size <= 0 {
		return fmt.Errorf("empty file not supported in chunked mode")
	}
	chunkCount := int((size + types.ChunkSize - 1) / types.ChunkSize)
	if chunkCount > types.MaxChunksPerFile {
		return fmt.Errorf("文件 %d 字节超过分块上限（%d 块）", size, types.MaxChunksPerFile)
	}
	// 文件名 = 远程路径尾段。
	name := remotePath[strings.LastIndexByte(remotePath, '/')+1:]
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("invalid remote path: %s", remotePath)
	}

	// 1. staging 建档（不动旧文件——覆盖写发生在 commit 的单事务里）。
	var created struct {
		Inode types.Inode      `json:"inode"`
		Nodes []types.NodeInfo `json:"nodes"`
	}
	if err := c.postJSON("/files", map[string]any{
		"path": remotePath, "replicas": replicas, "overwrite": overwrite, "chunked": true,
	}, &created); err != nil {
		return fmt.Errorf("create staging: %w", err)
	}
	stagingID := created.Inode.ID
	fail := func(err error) error {
		c.abortStaging(stagingID)
		return err
	}

	// 2. 流水线：读块（串行）→ 上传（并发 ≤2，错误经 channel 汇聚）。
	errCh := make(chan error, chunkCount) // 每块最多报一个错
	sem := make(chan struct{}, 2)         // 并发信号量：内存上界 ~2×64MB
	var wg sync.WaitGroup

	buf := make([]byte, types.ChunkSize)
	var written int64
	for index := 0; written < size; index++ {
		n, err := io.ReadFull(r, buf[:min(int64(len(buf)), size-written)])
		if n == 0 && err != nil {
			wg.Wait()
			return fail(fmt.Errorf("读本地文件: %w", err))
		}
		if n == 0 {
			break
		}
		written += int64(n)
		data := make([]byte, n)
		copy(data, buf[:n])
		// 信号量前移到生产者循环：读下一块前先占槽位，主循环因此被阻塞，
		// 在途 data 缓冲恒 ≤ 并发深度。此前 sem 写在 goroutine 内部，主循环不等待，
		// 会一次性读入 chunkCount×64MB（16GB 文件驻留 16GB 内存 → OOM）。
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int, data []byte) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := c.uploadChunkOnce(stagingID, idx, data, replicas); err != nil {
				errCh <- fmt.Errorf("chunk %d: %w", idx, err)
			}
		}(index, data)
	}
	wg.Wait()
	close(errCh)
	var firstErr error
	for e := range errCh { // channel 已关闭，range 自然结束；取首个错误
		if firstErr == nil {
			firstErr = e
		}
	}
	if firstErr != nil {
		return fail(firstErr)
	}
	if written != size {
		return fail(fmt.Errorf("读入 %d 字节 != 声明大小 %d", written, size))
	}

	// 3. commit 原子换名（master 校验每块主副本 Done + Σ大小）。
	// minCopies>0：从副本仍在异步同步时 master 返回 409，轮询等待（改进项3）。
	// 15 分钟超时：正常链路 64MB 块同步远快于此；超时说明从副本节点有问题，
	// abort 后由用户决定重传（scanner 不会对 staging 做无意义修复）。
	// v2-3a：commit 带 op_id——网络错误（响应丢失）时同 op_id 重试，服务端幂等回放
	// 原结果，修复"已提交却误报失败"（审计 F3）。
	opID := newOpID()
	commitBody := map[string]any{
		"inode_id": stagingID, "name": name, "size": size, "chunk_count": chunkCount, "op_id": opID,
	}
	if minCopies > 0 {
		commitBody["min_copies"] = minCopies
	}
	deadline := time.Now().Add(15 * time.Minute)
	for attempt := 0; ; attempt++ {
		err := c.postJSON("/files/commit", commitBody, nil)
		if err == nil {
			return nil
		}
		var he *HTTPError
		isStatusErr := errors.As(err, &he)
		if !isStatusErr && attempt < 2 {
			// 网络错误：服务端可能已提交，同 op_id 重试拿回幂等结果。
			time.Sleep(time.Second)
			continue
		}
		if minCopies <= 0 || attempt >= 30 || !strings.Contains(err.Error(), "http 409") || time.Now().After(deadline) {
			return fail(fmt.Errorf("commit: %w", err))
		}
		time.Sleep(30 * time.Second) // 副本同步中，等下一轮
	}
}

// uploadChunkOnce 上传一个块：分配 → PUT 主副本（带重试）→ 失败 reassign 换节点。
func (c *Client) uploadChunkOnce(stagingID uint64, index int, data []byte, replicas int) error {
	crc := types.CRC32C(data) // 块内容校验和：随分配上报 master，PUT 时也带头让 node 落盘即校验。
	// 分配（幂等）：拿到节点列表。
	assign, err := c.assignChunk(stagingID, index, len(data), replicas, crc)
	if err != nil {
		return fmt.Errorf("assign chunk %d: %w", index, err)
	}
	// PUT 主副本，每次带上下文超时：节点在 EasyTier 上可能中途卡死（TCP 不再 ACK），
	// 无超时的 Do 会永久挂起 → 拖死 Flush/close → Finder「设备已消失」。超时按块大小
	// 给足慢速链路，仍卡住即判该节点失联，换节点重试（最多轮换 3 个节点）。
	putTimeout := c.ioTimeout(int64(len(data)))
	var failed []uint64 // 已卡死/失败的节点：reassign 时告诉 master 排除，别再选中
	for round := 0; round < 3; round++ {
		nodes := assign.Nodes
		if round > 0 {
			assign, err = c.reassignChunk(stagingID, index, len(data), replicas, crc, failed)
			if err != nil {
				return fmt.Errorf("reassign chunk %d: %w", index, err)
			}
			nodes = assign.Nodes
		}
		if len(nodes) == 0 {
			return fmt.Errorf("chunk %d: master 未分配节点", index)
		}
		primary := nodes[0].Addr
		ctx, cancel := context.WithTimeout(context.Background(), putTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPut,
			fmt.Sprintf("%s://%s/objects/%d", c.scheme(), primary, types.ChunkID(stagingID, index)),
			bytes.NewReader(data))
		if err == nil {
			req.ContentLength = int64(len(data))
			req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", crc))
			resp, derr := c.HTTP.Do(req)
			if derr == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
					cancel()
					return nil
				}
			}
		}
		cancel()
		failed = append(failed, nodes[0].ID) // 这台失败，下轮排除
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("chunk %d: 全部尝试失败（3 个节点均超时/失败）", index)
}

// assignChunk 向 master 申请块分配（幂等）。checksum 为块内容 CRC32C。
func (c *Client) assignChunk(stagingID uint64, index int, size int, replicas int, checksum uint32) (chunkAssignOut, error) {
	var out chunkAssignOut
	err := c.postJSON("/files/chunks", map[string]any{
		"inode_id": stagingID, "index": index, "size": size, "replicas": replicas, "checksum": checksum,
	}, &out)
	return out, err
}

// reassignChunk 请求 master 强制换一组节点。exclude 是本轮要排除的节点（刚卡死/失败的），
// 避免 master 又把副本分回同一台坏节点、白白耗一轮。
func (c *Client) reassignChunk(stagingID uint64, index int, size int, replicas int, checksum uint32, exclude []uint64) (chunkAssignOut, error) {
	var out chunkAssignOut
	err := c.postJSON("/files/chunks", map[string]any{
		"inode_id": stagingID, "index": index, "size": size, "replicas": replicas,
		"reassign": true, "checksum": checksum, "exclude": exclude,
	}, &out)
	return out, err
}

// abortStaging 显式放弃上传（尽力而为，失败只记错误不阻断主错误返回）。
func (c *Client) abortStaging(stagingID uint64) {
	req, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("%s/files/staging/%d", c.MasterURL, stagingID), nil)
	if err != nil {
		return
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// getChunked 按块表分块下载并拼装。
// 节点地址来自 lookup 返回的 nodes 表（ID → Addr）；done 副本优先、随机打散。
func (c *Client) getChunked(in types.Inode, nodes []Replica, localPath string) error {
	if len(in.Chunks) == 0 {
		return fmt.Errorf("分块文件无块表: %s", in.Name)
	}
	addr := make(map[uint64]string)
	for _, n := range nodes {
		addr[n.ID] = n.Addr
	}
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()
	for _, ch := range in.Chunks {
		if err := c.fetchChunkInto(in.ID, ch, addr, out); err != nil {
			return fmt.Errorf("块 %d: %w", ch.Index, err)
		}
	}
	return nil
}

// fetchChunkInto 下载一个块追加到 w。done 副本优先随机打散，失败轮换副本。
func (c *Client) fetchChunkInto(inodeID uint64, ch types.ChunkInfo, addr map[uint64]string, w io.Writer) error {
	var primary, fallback []uint64
	for _, id := range ch.Replicas {
		if types.ContainsUint64(ch.Done, id) {
			primary = append(primary, id)
		} else {
			fallback = append(fallback, id)
		}
	}
	rand.Shuffle(len(primary), func(i, j int) { primary[i], primary[j] = primary[j], primary[i] })
	candidates := append(append([]uint64{}, primary...), fallback...)

	chunkID := types.ChunkObjID(ch, inodeID) // v2 块表自描述 ID 优先（采纳式替换后不可派生）
	var lastErr error
	for _, id := range candidates {
		a, ok := addr[id]
		if !ok || a == "" {
			lastErr = fmt.Errorf("节点 %d 地址未知", id)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.ioTimeout(ch.Size))
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s://%s/objects/%d", c.scheme(), a, chunkID), nil)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("节点 %s: %w", a, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cancel()
			lastErr = fmt.Errorf("节点 %s 返回 %d", a, resp.StatusCode)
			continue
		}
		// 先整块读入内存再校验后写出：块 ≤64MB，可整块驻留。必须校验后才写，
		// 否则损坏块已落到输出文件、故障转移重写会导致内容重复错位。
		buf, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		if readErr != nil {
			lastErr = fmt.Errorf("节点 %s: 读取失败 %w", a, readErr)
			continue
		}
		if int64(len(buf)) != ch.Size {
			lastErr = fmt.Errorf("节点 %s: 块 %d 短读 %d != %d", a, ch.Index, len(buf), ch.Size)
			continue
		}
		if ch.Checksum != 0 && types.CRC32C(buf) != ch.Checksum {
			lastErr = fmt.Errorf("节点 %s: 块 %d 校验和不符", a, ch.Index)
			go c.ReportCorrupt(chunkID, id) // 尽力上报：master 删坏对象并清 Done → 修复重拉
			continue
		}
		if _, err := w.Write(buf); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("全部副本失败: %w", lastErr)
}

// ReportCorrupt 读端发现某副本内容校验和不符时上报 master（失败静默）。
// objectID 对分块传块对象 ID（ChunkID），对 legacy 传文件 inode ID（与 /files/replicated
// 同编码）。master 会删该节点坏对象并清其 Done，使修复扫描重新拉取覆盖，自愈闭环闭合。
// 调用方以 goroutine 触发：读路径已完成故障转移，上报不得阻塞或影响读结果。
func (c *Client) ReportCorrupt(objectID, nodeID uint64) {
	body, err := json.Marshal(map[string]uint64{"inode_id": objectID, "node_id": nodeID})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.MasterURL+"/files/corrupt", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// newOpID 生成写操作幂等凭据（v2-3a）：128 位随机十六进制。
func newOpID() string {
	b := make([]byte, 16)
	crand.Read(b)
	return hex.EncodeToString(b)
}

// PutSmall 小文件单请求通道（v2-2a）：数据内联进一个 POST，master 服务端写主副本并
// 单事务提交元数据，客户端 1 次往返完成整个文件（分块路径要 4-5 次往返）。
// 落库为 legacy 单对象模型（非 chunked、content=inode ID）；覆盖写保留 inode（Generation++）。
// 上限 types.SmallFileMax，超出报错（调用方走分块路径）。
// 网络错误（响应丢失/连接中断）时以同一 op_id 自动重试一次：服务端按 op 幂等回放
// 原结果——若首次实际已成功，重试拿回的是同一 inode 而非重复创建（v2-3a）。
// HTTP 状态错误（409/404 等服务端明确答复）不重试，直接返回。
func (c *Client) PutSmall(remotePath string, data []byte, replicas int, overwrite bool) (types.Inode, error) {
	if int64(len(data)) == 0 {
		return types.Inode{}, fmt.Errorf("empty file not supported in small path")
	}
	if int64(len(data)) > types.SmallFileMax {
		return types.Inode{}, fmt.Errorf("文件 %d 字节超过小文件通道上限 %d", len(data), types.SmallFileMax)
	}
	opID := newOpID()
	u := func() string {
		return fmt.Sprintf("%s/files/small?path=%s&replicas=%d&overwrite=%t&op_id=%s",
			c.MasterURL, url.QueryEscape(remotePath), replicas, overwrite, opID)
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(300 * time.Millisecond) // 响应丢失窗口：给服务端一点完成时间
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.ioTimeout(int64(len(data))))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u(), bytes.NewReader(data))
		if err != nil {
			cancel()
			return types.Inode{}, err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.ContentLength = int64(len(data))
		resp, err := c.HTTP.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue // 网络错误：同 op_id 重试（服务端幂等回放）
		}
		if err := statusError(resp); err != nil {
			resp.Body.Close()
			cancel()
			return types.Inode{}, err // 服务端明确答复：不重试
		}
		var out struct {
			Inode types.Inode `json:"inode"`
		}
		derr := json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		cancel()
		if derr != nil {
			return types.Inode{}, derr
		}
		return out.Inode, nil
	}
	return types.Inode{}, lastErr
}

// CreateSymlink 创建符号链接（挂载层 SYMLINK op 用）。target 原样存储。
func (c *Client) CreateSymlink(remotePath, target string) (types.Inode, error) {
	var out struct {
		Inode types.Inode `json:"inode"`
	}
	err := c.postJSON("/files/symlink", map[string]any{"path": remotePath, "target": target}, &out)
	return out.Inode, err
}

// putObject 向节点写入对象数据。
func (c *Client) putObject(nodeAddr string, inodeID uint64, r io.Reader, size int64) error {
	// io.NopCloser 包裹：http transport 上传完成后会关闭 req.Body，
	// 若直接传 *os.File 会被关掉句柄，导致同一写句柄后续 Write 报 EIO
	// （实机覆盖写 bug 根因：FLUSH 上传后 transport 关文件 → 再 WRITE 失败）。
	// 带上下文超时：节点中途卡死不能让整传永久挂起（同 uploadChunkOnce）。
	ctx, cancel := context.WithTimeout(context.Background(), c.ioTimeout(size))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("%s://%s/objects/%d", c.scheme(), nodeAddr, inodeID), io.NopCloser(r))
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
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.MasterURL+path, bytes.NewReader(b))
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
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) getJSON(path string, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.MasterURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// HTTPError 保留 HTTP 状态码，调用方不必从错误文案猜测错误类型。
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("http %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("http %d", e.StatusCode)
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
		return &HTTPError{StatusCode: resp.StatusCode, Message: e.Error}
	}
	return &HTTPError{StatusCode: resp.StatusCode}
}

// queryPath 构造 path=... 查询串。
func queryPath(p string) string {
	return url.Values{"path": {p}}.Encode()
}

// ---- GC ----

// GCNodeReport 是 GC 返回的单节点孤儿报告。
type GCNodeReport struct {
	NodeID      uint64 `json:"node_id"`
	NodeAddr    string `json:"node_addr"`
	OrphanCount int    `json:"-"` // 从 Orphans 长度计算
	OrphanBytes int64  `json:"orphan_bytes"`
	Deleted     int    `json:"deleted"` // 本轮实际删除数（execute；两轮确认下首轮为 0）
	Orphans     []struct {
		ID   uint64 `json:"id"`
		Size int64  `json:"size"`
	} `json:"orphans"`
}

// GC 调用 master /admin/gc，execute=true 时执行删除。
func (c *Client) GC(execute bool) ([]GCNodeReport, error) {
	body, _ := json.Marshal(map[string]bool{"execute": execute})
	resp, err := c.HTTP.Post(c.MasterURL+"/admin/gc", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := statusError(resp); err != nil {
		return nil, err
	}
	var reports []GCNodeReport
	if err := json.NewDecoder(resp.Body).Decode(&reports); err != nil {
		return nil, err
	}
	for i := range reports {
		reports[i].OrphanCount = len(reports[i].Orphans)
	}
	return reports, nil
}
