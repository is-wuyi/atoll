// Package mount 把 atoll 集群通过 FUSE 挂载为本地目录。
//
// 架构：动态节点——本地不维护目录树状态，节点路径由内核树推导（Path()），
// 每个操作实时访问 master/存储节点。内核的 EntryTimeout/AttrTimeout 提供秒级缓存。
//
// 读路径：Open 时从 master 拿副本地址列表，Read 按偏移发起 HTTP Range 请求，
// 不整文件下载；副本故障时自动切换下一个地址。
// 写路径：Create/写打开 先落本地临时文件，Flush 时整体上传（复用整文件 PUT 协议），
// 适合中小文件场景。
package mount

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"atoll/client"
	"atoll/pkg/types"
)

// Mount 是一次挂载会话：集群访问入口与写缓冲管理。
type Mount struct {
	client   *client.Client
	replicas int    // 新写入文件的副本数
	cacheDir string // 写缓冲临时文件目录

	mu     sync.Mutex
	writes map[string]*writeHandle // 远程路径 → 进行中的本地写入
}

func New(c *client.Client, cacheDir string, replicas int) (*Mount, error) {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &Mount{
		client:   c,
		replicas: replicas,
		cacheDir: cacheDir,
		writes:   make(map[string]*writeHandle),
	}, nil
}

// Root 返回挂载根节点。
func (m *Mount) Root() fs.InodeEmbedder {
	return &node{m: m}
}

// ---- 动态节点 ----

type node struct {
	fs.Inode
	m *Mount
}

var (
	_ fs.NodeGetattrer = (*node)(nil)
	_ fs.NodeLookuper  = (*node)(nil)
	_ fs.NodeReaddirer = (*node)(nil)
	_ fs.NodeMkdirer   = (*node)(nil)
	_ fs.NodeUnlinker  = (*node)(nil)
	_ fs.NodeRmdirer   = (*node)(nil)
	_ fs.NodeRenamer   = (*node)(nil)
	_ fs.NodeCreater   = (*node)(nil)
	_ fs.NodeOpener    = (*node)(nil)
	_ fs.NodeSetattrer = (*node)(nil)
)

// path 返回该节点对应的集群路径（根节点为 "/"）。
func (n *node) path() string {
	p := n.Path(nil)
	if p == "" {
		return "/"
	}
	return "/" + p
}

// remotePath 拼子路径。
func (n *node) remotePath(name string) string {
	base := n.path()
	return strings.TrimSuffix(base, "/") + "/" + name
}

// newChildNode 构造子节点（动态节点无自身状态）。
func (n *node) newChildNode(ctx context.Context, ino uint64, mode uint32) *fs.Inode {
	return n.NewInode(ctx, &node{m: n.m}, fs.StableAttr{Ino: ino, Mode: mode})
}

// fillEntry 把 master 的 inode 属性填入 EntryOut/AttrOut。
func fillEntry(a *fuse.Attr, in *types.Inode) {
	if in.Type == types.TypeDir {
		a.Mode = fuse.S_IFDIR | 0o755
	} else {
		a.Mode = fuse.S_IFREG | 0o644
		a.Size = uint64(in.Size)
	}
	a.Ino = in.ID
	a.Mtime = uint64(in.Mtime.Unix())
}

// ---- 属性 ----

func (n *node) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	remote := n.path()
	// 写入中的文件：属性来自本地缓冲。
	n.m.mu.Lock()
	w := n.m.writes[remote]
	n.m.mu.Unlock()
	if w != nil {
		w.attr(&out.Attr)
		return 0
	}
	in, _, err := n.m.client.Lookup(remote)
	if err != nil {
		return syscall.ENOENT
	}
	fillEntry(&out.Attr, &in)
	return 0
}

// ---- 目录操作 ----

func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	remote := n.remotePath(name)
	n.m.mu.Lock()
	w := n.m.writes[remote]
	n.m.mu.Unlock()
	if w != nil {
		w.attr(&out.Attr)
		return n.newChildNode(ctx, 0, fuse.S_IFREG), 0
	}
	in, _, err := n.m.client.Lookup(remote)
	if err != nil {
		return nil, syscall.ENOENT
	}
	fillEntry(&out.Attr, &in)
	mode := uint32(fuse.S_IFREG)
	if in.Type == types.TypeDir {
		mode = fuse.S_IFDIR
	}
	return n.newChildNode(ctx, in.ID, mode), 0
}

func (n *node) Readdir(_ context.Context) (fs.DirStream, syscall.Errno) {
	kids, err := n.m.client.Ls(n.path())
	if err != nil {
		return nil, syscall.ENOENT
	}
	entries := make([]fuse.DirEntry, 0, len(kids))
	for _, k := range kids {
		mode := uint32(fuse.S_IFREG)
		if k.Type == types.TypeDir {
			mode = fuse.S_IFDIR
		}
		entries = append(entries, fuse.DirEntry{Name: k.Name, Mode: mode, Ino: k.ID})
	}
	return &sliceDirStream{entries: entries}, 0
}

func (n *node) Mkdir(ctx context.Context, name string, _ uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	dir, err := n.m.client.Mkdir(n.remotePath(name))
	if err != nil {
		return nil, mapErrno(err)
	}
	fillEntry(&out.Attr, &dir)
	return n.newChildNode(ctx, dir.ID, fuse.S_IFDIR), 0
}

func (n *node) Unlink(_ context.Context, name string) syscall.Errno {
	// 删除写入中的文件：同时清掉本地缓冲。
	remote := n.remotePath(name)
	n.m.mu.Lock()
	w := n.m.writes[remote]
	delete(n.m.writes, remote)
	n.m.mu.Unlock()
	if w != nil {
		w.discard()
	}
	if err := n.m.client.Rm(remote); err != nil {
		return mapErrno(err)
	}
	return 0
}

func (n *node) Rmdir(_ context.Context, name string) syscall.Errno {
	if err := n.m.client.Rm(n.remotePath(name)); err != nil {
		return mapErrno(err)
	}
	return 0
}

// Rename 只支持同目录改名；跨目录返回 EXDEV（编辑器保存通常走同目录 rename）。
func (n *node) Rename(_ context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if flags != 0 {
		return syscall.ENOTSUP
	}
	np, ok := newParent.(*node)
	if !ok {
		return syscall.EXDEV
	}
	oldRemote := n.remotePath(name)
	newRemote := np.remotePath(newName)
	if parentOf(oldRemote) != parentOf(newRemote) {
		return syscall.EXDEV
	}
	if err := n.m.client.Rename(oldRemote, newName); err != nil {
		return mapErrno(err)
	}
	// 写入中的缓冲文件跟随改名。
	n.m.mu.Lock()
	if w, ok := n.m.writes[oldRemote]; ok {
		delete(n.m.writes, oldRemote)
		w.remote = newRemote
		n.m.writes[newRemote] = w
	}
	n.m.mu.Unlock()
	return 0
}

func parentOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

// ---- 文件打开 ----

// Open 读打开返回 Range 流式读句柄；写打开返回本地缓冲句柄。
func (n *node) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	remote := n.path()
	writeIntent := flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0 || flags&syscall.O_TRUNC != 0
	if writeIntent {
		if _, _, err := n.m.client.Lookup(remote); err != nil {
			return nil, 0, syscall.ENOENT
		}
		w, err := n.m.newWriteHandle(remote, flags&syscall.O_TRUNC != 0)
		if err != nil {
			return nil, 0, syscall.EIO
		}
		return w, 0, 0
	}
	in, reps, err := n.m.client.Lookup(remote)
	if err != nil {
		return nil, 0, syscall.ENOENT
	}
	addrs := candidateAddrs(reps)
	if len(addrs) == 0 {
		return nil, 0, syscall.EIO
	}
	return &readHandle{
		ino:   in.ID,
		size:  in.Size,
		addrs: addrs,
		http:  &http.Client{Timeout: 30 * time.Second},
	}, 0, 0
}

// Create 新建文件：本地缓冲，Flush 时上传。
func (n *node) Create(ctx context.Context, name string, _ uint32, _ uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	w, err := n.m.newWriteHandle(n.remotePath(name), true)
	if err != nil {
		return nil, nil, 0, syscall.EIO
	}
	w.attr(&out.Attr)
	return n.newChildNode(ctx, 0, fuse.S_IFREG), w, 0, 0
}

// Setattr 处理 truncate（打开的写句柄）；其余属性修改忽略。
// 内核对 O_TRUNC 的实现：OPEN(WRONLY) 后发不带句柄的 SETATTR(size=0)
// （未协商 ATOMIC_O_TRUNC 时），此时 f 为 nil——按路径查活跃写缓冲。
func (n *node) Setattr(_ context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if sz, ok := in.GetSize(); ok {
		w, _ := f.(*writeHandle)
		if w == nil {
			n.m.mu.Lock()
			w = n.m.writes[n.path()]
			n.m.mu.Unlock()
		}
		if w == nil {
			return syscall.ENOTSUP
		}
		if errno := w.truncate(sz); errno != 0 {
			return errno
		}
		w.attr(&out.Attr)
		return 0
	}
	// 其余（mtime/chmod）接受但不动集群元数据。
	in2, _, err := n.m.client.Lookup(n.path())
	if err == nil {
		fillEntry(&out.Attr, &in2)
	}
	return 0
}

// candidateAddrs 从副本列表构造读取候选：done 优先，组内随机打散做负载均衡。
func candidateAddrs(reps []client.Replica) []string {
	var done, pending []string
	for _, r := range reps {
		if r.Done {
			done = append(done, r.Addr)
		} else {
			pending = append(pending, r.Addr)
		}
	}
	rand.Shuffle(len(done), func(i, j int) { done[i], done[j] = done[j], done[i] })
	return append(done, pending...)
}

// mapErrno 把 client 错误映射为 errno。
func mapErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return syscall.ENOENT
	case strings.Contains(msg, "already exists"):
		return syscall.EEXIST
	case strings.Contains(msg, "not empty"):
		return syscall.ENOTEMPTY
	default:
		return syscall.EIO
	}
}

// ---- 读句柄：按 Range 请求读取，故障切换 ----

type readHandle struct {
	ino   uint64
	size  int64
	addrs []string
	next  int
	http  *http.Client
}

var _ fs.FileReader = (*readHandle)(nil)

// readRange 读取 [start, end] 闭区间；失败轮换地址重试一轮。
func (rh *readHandle) readRange(start, end int64) ([]byte, syscall.Errno) {
	want := end - start + 1
	var lastErr error
	for i := 0; i < len(rh.addrs); i++ {
		addr := rh.addrs[(rh.next+i)%len(rh.addrs)]
		req, err := http.NewRequest(http.MethodGet,
			fmt.Sprintf("http://%s/objects/%d", addr, rh.ino), nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
		resp, err := rh.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("node %s: status %d", addr, resp.StatusCode)
			continue
		}
		buf := make([]byte, want)
		n, err := io.ReadFull(resp.Body, buf)
		resp.Body.Close()
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			lastErr = err
			continue
		}
		rh.next = (rh.next + i + 1) % len(rh.addrs) // 记住可用地址
		return buf[:n], 0
	}
	_ = lastErr
	return nil, syscall.EIO
}

func (rh *readHandle) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off >= rh.size {
		return fuse.ReadResultData(nil), 0 // EOF
	}
	end := off + int64(len(dest)) - 1
	if end >= rh.size {
		end = rh.size - 1
	}
	data, errno := rh.readRange(off, end)
	if errno != 0 {
		return nil, errno
	}
	return fuse.ReadResultData(data), 0
}

// ---- 写句柄：本地缓冲，Flush 整传 ----

type writeHandle struct {
	m       *Mount
	remote  string
	local   string
	f       *os.File
	mu      sync.Mutex
	dirty   bool
	dropped bool
}

var (
	_ fs.FileWriter  = (*writeHandle)(nil)
	_ fs.FileFlusher = (*writeHandle)(nil)
	_ fs.FileReleaser = (*writeHandle)(nil)
)

// newWriteHandle 建立写缓冲。trunc=true 从空文件开始；否则先下载现有内容（就地编辑）。
func (m *Mount) newWriteHandle(remote string, trunc bool) (*writeHandle, error) {
	tmp, err := os.CreateTemp(m.cacheDir, "w-*")
	if err != nil {
		return nil, err
	}
	w := &writeHandle{
		m:      m,
		remote: remote,
		local:  tmp.Name(),
		f:      tmp,
	}
	if !trunc {
		if err := m.client.Get(remote, tmp.Name()); err == nil {
			// Get 用完会关闭文件句柄，重新以读写模式打开。
			f, err := os.OpenFile(tmp.Name(), os.O_RDWR, 0o600)
			if err == nil {
				tmp.Close()
				w.f = f
			}
		}
		// 下载失败（如文件不存在）视为从空开始。
	}
	m.mu.Lock()
	m.writes[remote] = w
	m.mu.Unlock()
	return w, nil
}

func (w *writeHandle) Write(_ context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.f.WriteAt(data, off)
	if err != nil {
		return 0, syscall.EIO
	}
	w.dirty = true
	return uint32(n), 0
}

// Flush 上传缓冲文件到集群。可能被多次调用（每次 close），有变更才重传。
func (w *writeHandle) Flush(_ context.Context) syscall.Errno {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.dirty || w.dropped {
		return 0
	}
	st, err := w.f.Stat()
	if err != nil {
		return syscall.EIO
	}
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return syscall.EIO
	}
	if err := w.m.client.PutReader(w.remote, st.Size(), w.f, w.m.replicas); err != nil {
		return syscall.EIO
	}
	w.dirty = false
	return 0
}

// Release 清理本地缓冲与注册表（只执行一次）。
func (w *writeHandle) Release(_ context.Context) syscall.Errno {
	w.mu.Lock()
	if w.dropped {
		w.mu.Unlock()
		return 0
	}
	w.dropped = true
	w.mu.Unlock()
	w.f.Close()
	os.Remove(w.local)
	w.m.mu.Lock()
	if cur, ok := w.m.writes[w.remote]; ok && cur == w {
		delete(w.m.writes, w.remote)
	}
	w.m.mu.Unlock()
	return 0
}

// discard 丢弃缓冲（Unlink 写入中文件时用），不触发上传。
func (w *writeHandle) discard() {
	w.mu.Lock()
	if w.dropped {
		w.mu.Unlock()
		return
	}
	w.dropped = true
	w.dirty = false
	w.mu.Unlock()
	w.f.Close()
	os.Remove(w.local)
}

func (w *writeHandle) truncate(size uint64) syscall.Errno {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.f.Truncate(int64(size)); err != nil {
		return syscall.EIO
	}
	w.dirty = true
	return 0
}

// attr 把本地缓冲文件的属性填入 fuse.Attr。
func (w *writeHandle) attr(a *fuse.Attr) {
	st, err := os.Stat(w.local)
	if err != nil {
		a.Mode = fuse.S_IFREG | 0o644
		return
	}
	a.Ino = 0
	a.Size = uint64(st.Size())
	a.Mode = fuse.S_IFREG | 0o644
	a.Mtime = uint64(st.ModTime().Unix())
}

// ---- DirStream 简单切片实现 ----

type sliceDirStream struct {
	entries []fuse.DirEntry
	pos     int
}

var _ fs.DirStream = (*sliceDirStream)(nil)

func (s *sliceDirStream) HasNext() bool { return s.pos < len(s.entries) }

func (s *sliceDirStream) Next() (fuse.DirEntry, syscall.Errno) {
	e := s.entries[s.pos]
	s.pos++
	return e, 0
}

func (s *sliceDirStream) Close() {}
