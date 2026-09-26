// Package client 实现 atoll 的 CLI 客户端：
// 元数据操作走 master，数据读写直连存储节点。
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"crypto/tls"
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
// 数据源 /admin/overview 的聚合值（所有存活节点容量之和）。
func (c *Client) ClusterCapacity() (total, used int64, err error) {
	var ov struct {
		TotalBytes int64 `json:"total_bytes"`
		UsedBytes  int64 `json:"used_bytes"`
	}
	if err := c.getJSON("/admin/overview", &ov); err != nil {
		return 0, 0, err
	}
	return ov.TotalBytes, ov.UsedBytes, nil
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
		if putErr = c.putObject(created.Nodes[0].Addr, created.Inode.ID, io.TeeReader(r, hh)); putErr == nil {
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
		resp, err := c.HTTP.Get(fmt.Sprintf("%s://%s/objects/%d", c.scheme(), n.Addr, in.ID))
		if err != nil {
			lastErr = fmt.Errorf("节点 %s: %w", n.Addr, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("节点 %s 返回 %d", n.Addr, resp.StatusCode)
			continue
		}
		out, err := os.Create(localPath)
		if err != nil {
			resp.Body.Close()
			return err
		}
		h := types.NewCRC32C()
		written, copyErr := io.Copy(out, io.TeeReader(resp.Body, h))
		closeErr := out.Close()
		resp.Body.Close()
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
	commitBody := map[string]any{
		"inode_id": stagingID, "name": name, "size": size, "chunk_count": chunkCount,
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
	// 给足慢速链路（≥512KB/s），仍卡住即判该节点失联，换节点重试（最多轮换 3 个节点）。
	putTimeout := c.putTimeout
	if putTimeout == 0 {
		putTimeout = 30*time.Second + time.Duration(int64(len(data))/(512*1024))*time.Second
		if putTimeout > 150*time.Second {
			putTimeout = 150 * time.Second
		}
	}
	for round := 0; round < 3; round++ {
		nodes := assign.Nodes
		if round > 0 {
			assign, err = c.reassignChunk(stagingID, index, len(data), replicas, crc)
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

// reassignChunk 请求 master 强制换一组节点。
func (c *Client) reassignChunk(stagingID uint64, index int, size int, replicas int, checksum uint32) (chunkAssignOut, error) {
	var out chunkAssignOut
	err := c.postJSON("/files/chunks", map[string]any{
		"inode_id": stagingID, "index": index, "size": size, "replicas": replicas, "reassign": true, "checksum": checksum,
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

	chunkID := types.ChunkID(inodeID, ch.Index)
	var lastErr error
	for _, id := range candidates {
		a, ok := addr[id]
		if !ok || a == "" {
			lastErr = fmt.Errorf("节点 %d 地址未知", id)
			continue
		}
		resp, err := c.HTTP.Get(fmt.Sprintf("%s://%s/objects/%d", c.scheme(), a, chunkID))
		if err != nil {
			lastErr = fmt.Errorf("节点 %s: %w", a, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("节点 %s 返回 %d", a, resp.StatusCode)
			continue
		}
		// 先整块读入内存再校验后写出：块 ≤64MB，可整块驻留。必须校验后才写，
		// 否则损坏块已落到输出文件、故障转移重写会导致内容重复错位。
		buf, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
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
			continue
		}
		if _, err := w.Write(buf); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("全部副本失败: %w", lastErr)
}

// putObject 向节点写入对象数据。
func (c *Client) putObject(nodeAddr string, inodeID uint64, r io.Reader) error {
	// io.NopCloser 包裹：http transport 上传完成后会关闭 req.Body，
	// 若直接传 *os.File 会被关掉句柄，导致同一写句柄后续 Write 报 EIO
	// （实机覆盖写 bug 根因：FLUSH 上传后 transport 关文件 → 再 WRITE 失败）。
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s://%s/objects/%d", c.scheme(), nodeAddr, inodeID), io.NopCloser(r))
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
