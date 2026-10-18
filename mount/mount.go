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
	"crypto/tls"
	"errors"
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
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

// Mount 是一次挂载会话：集群访问入口与写缓冲管理。
type Mount struct {
	client   *client.Client
	replicas int    // 新写入文件的副本数
	cacheDir string // 写缓冲临时文件目录
	token    auth.Token
	tlsCfg   *tls.Config  // 读句柄直连节点的 TLS 配置（nil = 普通 HTTP）
	readHTTP *http.Client // 读句柄共享的 HTTP 客户端（连接池复用；此前每次 Open 新建）

	// chunkVerifySem 限制跨所有 chunked 读句柄同时进行的整块校验读取数（每个在飞
	// 校验至多缓冲 ChunkSize+1 字节），校验飞行内存有界，见 chunk_read_handle.go。
	chunkVerifySem chan struct{}
	// chunkCache 是 Mount 级共享的已校验整块缓存：全局字节预算有界（不随句柄数放大），
	// LRU 淘汰 + 跨句柄 singleflight，见 chunk_read_handle.go。
	chunkCache *mountChunkCache
	// verifyHTTP 整块校验 GET 专用：与 readHTTP 共享同一 Transport（连接池复用），
	// 无全程 Timeout——deadline 由按字节数缩放的 per-request ctx 给（chunkVerifyTimeout）。
	verifyHTTP *http.Client

	// NoSmallPath 测试钩子：禁用小文件单请求通道，强制走 chunked/流式路径。
	// 专测分块/流式机制的测试用（真实负载恒为 false）。
	NoSmallPath bool

	mu     sync.Mutex
	writes map[string]*writeHandle // 远程路径 → 进行中的本地写入

	// 属性缓存：Readdir 用一次 /dirs/children 批量填充整目录的子项属性，
	// 随后内核 readdirplus 对每个条目发的 Lookup/Getattr 命中缓存，不再逐个打 master。
	// 高延迟网络下把 `ls` 从 1+N 次往返压成 1 次（实测 4 文件目录 43 往返 → 1）。
	// TTL 短（与内核 1s 缓存同量级），有界陈旧；写类操作显式失效。
	attrMu  sync.Mutex
	attrTTL time.Duration
	attrs   map[string]attrCacheEntry // 远程路径 → 缓存的 inode

	// statfs 缓存：Finder 拷贝每个文件都发多次 STATFS，每次 ClusterCapacity() 打一趟
	// master /admin/overview——跨公网下又是每文件几趟无谓往返。容量非实时数据，短 TTL 够用。
	statfsMu   sync.Mutex
	statfsAt   time.Time
	statfsTot  int64
	statfsUsed int64

	// st_ino 注册表：路径 → 稳定本地 inode 号（与远端 ID 解耦，见 inode.go）。
	inoMu     sync.Mutex
	inoByPath map[string]uint64
	nextIno   uint64
}

type attrCacheEntry struct {
	in  types.Inode
	exp time.Time
}

func New(c *client.Client, cacheDir string, replicas int) (*Mount, error) {
	return NewWithToken(c, cacheDir, replicas, "")
}

// NewWithToken 创建带认证的挂载会话：读句柄的节点直连请求也注入 token。
func NewWithToken(c *client.Client, cacheDir string, replicas int, token auth.Token) (*Mount, error) {
	return NewWithTLS(c, cacheDir, replicas, token, nil)
}

// NewWithTLS 创建带认证 + TLS 的挂载会话。tlsCfg 为空等价于 NewWithToken。
//
// secure 会话客户端（NewSecure 创建）下，读句柄的节点直连请求不复用 auth.HTTPTransport
// （静态 token 会无差别发往节点、且完全绕过 client 的票据协议）：统一换用
// client.ObjectTransport() 共享的 secure transport——节点 GET 自动向 master 换短期
// 票据，用户会话绝不外发；重定向一律拒跨源。30s 全程 Timeout / verify 的 ctx deadline
// 语义保持不变。
func NewWithTLS(c *client.Client, cacheDir string, replicas int, token auth.Token, tlsCfg *tls.Config) (*Mount, error) {
	if _, err := c.WritePlanning(context.Background()); err != nil {
		return nil, fmt.Errorf("discover write protocol: %w", err)
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	// 两个 Client 共享同一 Transport（连接池一处复用）：readHTTP 有 30s 全程 Timeout
	// 服务 Range/小请求，verifyHTTP 无全程 Timeout、deadline 按整块字节数缩放。
	var readTransport http.RoundTripper = auth.HTTPTransport(token, tlsCfg, nil)
	secure := false
	if ot := c.ObjectTransport(); ot != nil {
		readTransport = ot
		secure = true
	}
	readHTTP := &http.Client{Timeout: 30 * time.Second, Transport: readTransport}
	verifyHTTP := &http.Client{Transport: readTransport}
	if secure {
		// 30x 不得把请求（连带票据/数据）引到其它主机（secure client 的 c.HTTP 同规）。
		readHTTP.CheckRedirect = client.SecureRedirectPolicy
		verifyHTTP.CheckRedirect = client.SecureRedirectPolicy
	}
	// secure 模式禁用已校验块缓存（预算 0，singleflight 保留）：缓存命中会绕过
	// master 对每次节点读的在线权限裁决——每次读重新取票据即重新鉴权，权限回收后
	// 新网络请求立即被拒。已读进内核页缓存的字节不可撤（文档既定边界），fd 语义不动。
	cacheBytes := int64(defaultChunkCacheBytes)
	if secure {
		cacheBytes = 0
	}
	m := &Mount{
		client:         c,
		replicas:       replicas,
		cacheDir:       cacheDir,
		token:          token,
		tlsCfg:         tlsCfg,
		readHTTP:       readHTTP,
		chunkVerifySem: make(chan struct{}, chunkVerifyInFlight),
		chunkCache:     newMountChunkCache(cacheBytes),
		verifyHTTP:     verifyHTTP,
		writes:         make(map[string]*writeHandle),
		attrTTL:        2 * time.Second,
		attrs:          make(map[string]attrCacheEntry),
		inoByPath:      make(map[string]uint64),
		nextIno:        localInoBase,
	}
	if secure {
		// secure 模式关掉小文件单请求通道：非空上传统一走 chunked（节点 PUT 持票据，
		// master 对 /objects/* 数据面按 ObjectID/ACL 裁决），不再把数据面 body 交给
		// master 代理，票据 body 绑定面也更小。PutSmall 接口保留给直接调用方。
		m.NoSmallPath = true
	}
	return m, nil
}

// lookupCached 查路径 inode，命中未过期缓存则直接返回，否则打 master 并回填。
func (m *Mount) lookupCached(path string) (types.Inode, error) {
	m.attrMu.Lock()
	if e, ok := m.attrs[path]; ok && time.Now().Before(e.exp) {
		m.attrMu.Unlock()
		return e.in, nil
	}
	m.attrMu.Unlock()
	in, _, err := m.client.Lookup(path)
	if err != nil {
		return types.Inode{}, err
	}
	m.attrPut(path, in)
	return in, nil
}

// attrPut 写入/刷新一条属性缓存。
func (m *Mount) attrPut(path string, in types.Inode) {
	m.attrMu.Lock()
	m.attrs[path] = attrCacheEntry{in: in, exp: time.Now().Add(m.attrTTL)}
	m.attrMu.Unlock()
}

// attrInvalidate 失效一条属性缓存（写类操作后调用，避免读到旧属性）。
func (m *Mount) attrInvalidate(path string) {
	m.attrMu.Lock()
	delete(m.attrs, path)
	m.attrMu.Unlock()
}

// scheme 返回读句柄直连节点用的 URL scheme，从 client.MasterURL 推导。
func (m *Mount) scheme() string {
	if strings.HasPrefix(m.client.MasterURL, "https://") {
		return "https"
	}
	return "http"
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
	_ fs.NodeGetattrer   = (*node)(nil)
	_ fs.NodeLookuper    = (*node)(nil)
	_ fs.NodeReaddirer   = (*node)(nil)
	_ fs.NodeMkdirer     = (*node)(nil)
	_ fs.NodeUnlinker    = (*node)(nil)
	_ fs.NodeRmdirer     = (*node)(nil)
	_ fs.NodeRenamer     = (*node)(nil)
	_ fs.NodeCreater     = (*node)(nil)
	_ fs.NodeOpener      = (*node)(nil)
	_ fs.NodeSetattrer   = (*node)(nil)
	_ fs.NodeSymlinker   = (*node)(nil)
	_ fs.NodeReadlinker  = (*node)(nil)
	_ fs.NodeGetxattrer  = (*node)(nil)
	_ fs.NodeSetxattrer  = (*node)(nil)
	_ fs.NodeListxattrer = (*node)(nil)
	_ fs.NodeStatfser    = (*node)(nil)
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

// fillEntry 把 master 的 inode 属性填入 EntryOut/AttrOut。st_ino 由调用方传入（inoFor，
// 与远端 ID 解耦，覆盖写/改名不翻转，见 inode.go）；远端 ID 只用于数据寻址、不作 st_ino。
func fillEntry(a *fuse.Attr, in *types.Inode, ino uint64) {
	switch in.Type {
	case types.TypeDir:
		a.Mode = fuse.S_IFDIR | 0o755
	case types.TypeSymlink:
		// 符号链接：S_IFLNK + 0777（POSIX 对链接权限不敏感），st_size=目标长度，
		// 内核 readlink 用它分配缓冲。链接本体无数据对象。
		a.Mode = fuse.S_IFLNK | 0o777
		a.Size = uint64(len(in.Target))
	default:
		a.Mode = fuse.S_IFREG | 0o644
		a.Size = uint64(in.Size)
	}
	a.Ino = ino
	a.Mtime = uint64(in.Mtime.Unix())
	// 报告挂载进程的 uid/gid：否则内核视为 root 所有，
	// 普通用户在挂载点上无写权限（曾导致 mac 上写入 permission denied）。
	a.Uid = uint32(os.Getuid())
	a.Gid = uint32(os.Getgid())
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
	in, err := n.m.lookupCached(remote)
	if err != nil {
		return mapErrno(err)
	}
	fillEntry(&out.Attr, &in, n.m.inoFor(remote))
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
		return n.newChildNode(ctx, n.m.inoFor(remote), fuse.S_IFREG), 0
	}
	in, err := n.m.lookupCached(remote)
	if err != nil {
		return nil, mapErrno(err)
	}
	fillEntry(&out.Attr, &in, n.m.inoFor(remote))
	mode := uint32(fuse.S_IFREG)
	if in.Type == types.TypeDir {
		mode = fuse.S_IFDIR
	} else if in.Type == types.TypeSymlink {
		mode = fuse.S_IFLNK
	}
	return n.newChildNode(ctx, n.m.inoFor(remote), mode), 0
}

func (n *node) Readdir(_ context.Context) (fs.DirStream, syscall.Errno) {
	dir := n.path()
	kids, err := n.m.client.Ls(dir)
	if err != nil {
		// 网络抖动/瞬时故障不是"目录不存在"。此前一律返回 ENOENT，会让内核把目录
		// 判为消失（并对 ENOENT 走负缓存），复制中的目录内容整段变空。按错误类型映射：
		// 真 404 才 ENOENT，传输错误/5xx → EIO（可重试），语义正确。
		return nil, mapErrno(err)
	}
	// 关键优化：/dirs/children 已返回每个子项的完整 inode，趁机批量填进属性缓存。
	// 内核紧接着对每个条目发的 Lookup/Getattr 就直接命中，省掉 N 次跨网 /meta 往返。
	entries := make([]fuse.DirEntry, 0, len(kids))
	seen := make(map[string]bool, len(kids))
	for i := range kids {
		k := kids[i]
		seen[k.Name] = true
		mode := uint32(fuse.S_IFREG)
		if k.Type == types.TypeDir {
			mode = fuse.S_IFDIR
		} else if k.Type == types.TypeSymlink {
			mode = fuse.S_IFLNK
		}
		entries = append(entries, fuse.DirEntry{Name: k.Name, Mode: mode, Ino: n.m.inoFor(strings.TrimSuffix(dir, "/") + "/" + k.Name)})
		n.m.attrPut(strings.TrimSuffix(dir, "/")+"/"+k.Name, k)
	}
	// 流式上传中的文件（活跃写句柄）合并进目录列表：staging 在 master 目录里
	// 不可见，不合并的话 Finder 刷新一变就"消失"（400MB 事故现场：文件闪现→
	// Finder 收尾时找不到自己的文件→不弹进度条→最终弹"设备已消失"）。
	// 内核对它的后续 Lookup/Getattr 走 writes 表，属性=本地缓冲实时大小。
	prefix := strings.TrimSuffix(dir, "/") + "/"
	n.m.mu.Lock()
	for remote := range n.m.writes {
		if !strings.HasPrefix(remote, prefix) {
			continue
		}
		name := remote[len(prefix):]
		if name == "" || strings.ContainsRune(name, '/') {
			continue // 只合并该目录的直接子项
		}
		if seen[name] {
			continue
		}
		entries = append(entries, fuse.DirEntry{Name: name, Mode: fuse.S_IFREG, Ino: n.m.inoFor(remote)})
	}
	n.m.mu.Unlock()
	return &sliceDirStream{entries: entries}, 0
}

func (n *node) Mkdir(ctx context.Context, name string, _ uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	dir, err := n.m.client.Mkdir(n.remotePath(name))
	if err != nil {
		return nil, mapErrno(err)
	}
	n.m.attrPut(n.remotePath(name), dir)
	fillEntry(&out.Attr, &dir, n.m.inoFor(n.remotePath(name)))
	return n.newChildNode(ctx, n.m.inoFor(n.remotePath(name)), fuse.S_IFDIR), 0
}

func (n *node) Unlink(_ context.Context, name string) syscall.Errno {
	remote := n.remotePath(name)
	n.m.mu.Lock()
	w := n.m.writes[remote]
	n.m.mu.Unlock()
	// 先删远端，成功后再丢本地缓冲——顺序不能反：此前先 discard 再 Rm，
	// 删一个"刚 create 尚未 close"（远端还不存在）的文件时 Rm 返回 ENOENT，
	// 但本地缓冲已经没了——数据丢失且报错不对。现在只有 Rm 真正成功、或该文件
	// 本就只存在于本地缓冲（远端 ENOENT 但有活跃写句柄）时才清缓冲。
	errno := mapErrno(n.m.client.Rm(remote))
	if errno != 0 && !(errno == syscall.ENOENT && w != nil) {
		return errno
	}
	n.m.attrInvalidate(remote)
	n.m.dropIno(remote) // 删后重建视为新文件（新 inode 号，符合 POSIX）
	n.m.mu.Lock()
	if cur, ok := n.m.writes[remote]; ok && cur == w {
		delete(n.m.writes, remote)
	}
	n.m.mu.Unlock()
	if w != nil {
		w.discard()
	}
	return 0
}

func (n *node) Rmdir(_ context.Context, name string) syscall.Errno {
	if err := n.m.client.Rm(n.remotePath(name)); err != nil {
		return mapErrno(err)
	}
	n.m.attrInvalidate(n.remotePath(name))
	n.m.dropIno(n.remotePath(name))
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
	n.m.attrInvalidate(oldRemote)
	n.m.attrInvalidate(newRemote)
	n.m.renameIno(oldRemote, newRemote) // inode 号随文件迁到新路径，改名不翻转 st_ino
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

// Symlink 创建符号链接（Finder 拷贝含链接的目录必走；此前未实现回 ENOTSUP 导致整个
// 拷贝以「不支持此操作」中止——rustfs 事故）。target 原样存 master。
func (n *node) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	remote := n.remotePath(name)
	in, err := n.m.client.CreateSymlink(remote, target)
	if err != nil {
		return nil, mapErrno(err)
	}
	n.m.attrPut(remote, in)
	fillEntry(&out.Attr, &in, n.m.inoFor(remote))
	return n.newChildNode(ctx, n.m.inoFor(remote), fuse.S_IFLNK), 0
}

// Readlink 读取符号链接目标。内核解析路径时先 LOOKUP（得 S_IFLNK）再 READLINK，
// 跟随动作在 VFS 完成——master 无需支持"穿过符号链接"的路径解析。
func (n *node) Readlink(_ context.Context) ([]byte, syscall.Errno) {
	in, err := n.m.lookupCached(n.path())
	if err != nil {
		return nil, mapErrno(err)
	}
	if in.Type != types.TypeSymlink {
		return nil, syscall.EINVAL
	}
	return []byte(in.Target), 0
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
// 分块文件（Chunked=true）返回 chunkedReadHandle：按块表换算对象 ID 与块内偏移。
func (n *node) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	remote := n.path()
	writeIntent := flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0 || flags&syscall.O_TRUNC != 0
	// 正在写入（staging，未提交）的文件：master 命名空间里还查不到。任何进程
	// 此刻只读打开它（Finder 拷贝后回读校验、Spotlight/QuickLook 索引）都会因
	// master Lookup 查无而 ENOENT——Finder 遂判拷贝失败、删文件、报「设备已消失」。
	// 故 in-progress 文件的读打开直接从本地缓冲文件伺服。
	n.m.mu.Lock()
	w := n.m.writes[remote]
	n.m.mu.Unlock()
	if w != nil && !writeIntent {
		f, err := os.Open(w.local)
		if err != nil {
			return nil, 0, syscall.EIO
		}
		return &localReadHandle{f: f}, 0, 0
	}
	if writeIntent {
		if w == nil {
			if _, _, err := n.m.client.Lookup(remote); err != nil {
				return nil, 0, mapErrno(err)
			}
		}
		w, err := n.m.newWriteHandle(remote, flags&syscall.O_TRUNC != 0)
		if err != nil {
			return nil, 0, mapErrno(err)
		}
		return w, 0, 0
	}
	in, reps, err := n.m.client.Lookup(remote)
	if err != nil {
		return nil, 0, mapErrno(err)
	}
	hc := n.m.readHTTP
	scheme := n.m.scheme()
	if in.Chunked {
		addr := make(map[uint64]string)
		for _, r := range reps {
			addr[r.ID] = r.Addr
		}
		if len(addr) == 0 && in.Size != 0 {
			return nil, 0, syscall.EIO
		}
		return &chunkedReadHandle{
			ino:        in.ID,
			size:       in.Size,
			generation: in.Generation,
			chunks:     in.Chunks,
			addr:       addr,
			next:       make(map[int]int),
			http:       hc,
			scheme:     scheme,
			m:          n.m,
		}, 0, 0
	}
	healthy, suspects := candidateReplicas(reps, in.SuspectReplicas)
	// 0 字节文件（secure /auth/files/empty 建档）无副本节点也无数据对象：Read 在
	// off>=size 即 EOF，绝不触网——空候选列表合法。非空文件零副本才是元数据故障。
	if len(healthy) == 0 && len(suspects) == 0 && in.Size != 0 {
		return nil, 0, syscall.EIO
	}
	return &readHandle{
		// ino 保持逻辑 FileID（suspect 上报按文件身份+版本比对，见 read_handle.go）；
		// objID 是本次打开时快照的内容对象 ID：物理读只打这个对象，后续覆盖写换了
		// 对象也不影响本句柄寻址（旧对象回收后本句柄自然读失败，绝不读成新版本）。
		ino:        in.ID,
		objID:      types.ObjIDFor(in),
		size:       in.Size,
		checksum:   in.Checksum,
		generation: in.Generation,
		cands:      healthy,
		suspects:   suspects,
		http:       hc,
		scheme:     scheme,
		m:          n.m,
	}, 0, 0
}

// Create 新建文件：本地缓冲，Flush 时上传。
func (n *node) Create(ctx context.Context, name string, _ uint32, _ uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	w, err := n.m.newWriteHandle(n.remotePath(name), true)
	if err != nil {
		return nil, nil, 0, syscall.EIO
	}
	// 标记为新建：Finder 拷贝先 CREATE 空文件占位、再写内容，若中途它 stat 发现
	// 这个空文件不存在（我们没上传 0 字节文件）就判定失败弹 -43。故新建的空文件也要上传。
	w.created = true
	w.streamOn = true
	w.attr(&out.Attr)
	return n.newChildNode(ctx, n.m.inoFor(n.remotePath(name)), fuse.S_IFREG), w, 0, 0
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
		n.m.attrInvalidate(n.path())
		w.attr(&out.Attr)
		return 0
	}
	// 其余（mtime/chmod）接受但不落集群元数据。关键：不能每次 SETATTR 都打 master——
	// Finder 拷贝每个文件会连发好几次 chmod/mtime，每次一趟 /meta 往返，跨公网下光这
	// 一项每文件就多花一两秒。写入中文件用本地缓冲属性；已提交文件走属性缓存，都不产生
	// 新的 /meta 往返。
	remote := n.path()
	n.m.mu.Lock()
	w, _ := f.(*writeHandle)
	if w == nil {
		w = n.m.writes[remote]
	}
	n.m.mu.Unlock()
	if w != nil {
		w.attr(&out.Attr)
		return 0
	}
	if in2, err := n.m.lookupCached(remote); err == nil {
		fillEntry(&out.Attr, &in2, n.m.inoFor(remote))
	}
	return 0
}

// ---- 扩展属性（xattr）----
//
// atoll 不持久化扩展属性，但必须"接受"写入、并对读/列返回"空"而非"不支持"。
// 原因：macOS Finder 拷贝文件时会写 com.apple.FinderInfo / com.apple.quarantine 等
// xattr，若挂载层未实现这些接口，go-fuse 默认回 ENOATTR/ENOSYS，Finder 收到后整体
// 中止并弹「错误代码 -43（找不到项目）」。这里让写操作静默成功（不落盘）、读返回
// 「无此属性」、列返回空——Finder 拿到"成功/无"即继续，文件内容照常上传。
// 代价仅是 Finder 标签/隔离标记不持久，对分布式文件存储无实质影响。

func (n *node) Setxattr(_ context.Context, _ string, _ []byte, _ uint32) syscall.Errno {
	return 0 // 接受但不持久化
}

func (n *node) Getxattr(_ context.Context, _ string, _ []byte) (uint32, syscall.Errno) {
	// 必须返回 ENOATTR（macOS=93）表示"无此属性"。此前误用 ENODATA（macOS=96），
	// 被 macFUSE 当成真 I/O 错误，Finder 收到后中止拷贝并弹「错误代码 -43」。
	// Linux 上 ENODATA==ENOATTR==61，此常量在两平台都语义正确。
	return 0, xattrNotFound
}

func (n *node) Listxattr(_ context.Context, _ []byte) (uint32, syscall.Errno) {
	return 0, 0 // 空属性列表
}

// clusterCapacityCached 缓存存活节点的物理容量。取不到数据就返回错误，不能把
// 零个存活节点或请求失败转换成凭空存在的可用空间。
func (m *Mount) clusterCapacityCached() (total, used int64, err error) {
	m.statfsMu.Lock()
	defer m.statfsMu.Unlock()
	if !m.statfsAt.IsZero() && time.Since(m.statfsAt) < 2*time.Second {
		return m.statfsTot, m.statfsUsed, nil
	}
	total, used, err = m.client.ClusterCapacity()
	if err != nil {
		return 0, 0, err
	}
	m.statfsTot, m.statfsUsed, m.statfsAt = total, used, time.Now()
	return total, used, nil
}

func (n *node) Statfs(_ context.Context, out *fuse.StatfsOut) syscall.Errno {
	const bsize = 4096
	total, used, err := n.m.clusterCapacityCached()
	if err != nil {
		return mapErrno(err)
	}
	total = max(total, 0)
	used = min(max(used, 0), total)
	out.Bsize = bsize
	out.Frsize = bsize
	out.Blocks = uint64(total / bsize)
	free := uint64((total - used) / bsize)
	out.Bfree = free
	out.Bavail = free
	out.NameLen = 255
	return 0
}

// candidateReplicas 拆分副本读取候选：healthy 为健康副本（done 在前、组内随机打散
// 做负载均衡），suspects 为 master 标记内容待修的副本（固定殿后兜底，不参与轮转，
// 保证轮转永远不会把请求直接带进 suspect 段）。保留节点 ID（读端发现内容损坏时
// 上报自愈用）。
func candidateReplicas(reps []client.Replica, suspect []uint64) (healthy, suspects []client.Replica) {
	var done, pending []client.Replica
	for _, r := range reps {
		if types.ContainsUint64(suspect, r.ID) {
			suspects = append(suspects, r)
		} else if r.Done {
			done = append(done, r)
		} else {
			pending = append(pending, r)
		}
	}
	rand.Shuffle(len(done), func(i, j int) { done[i], done[j] = done[j], done[i] })
	healthy = append(done, pending...)
	return healthy, suspects
}

// mapErrno 把 client 错误映射为 errno。
// mapErrno 把 client 错误映射成 errno。优先按 HTTP 状态码判定（权威），传输层/未知错误
// 一律 EIO——绝不臆断成 ENOENT：网络瞬断报 ENOENT 会让内核对该路径走负缓存、文件"消失"。
func mapErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var he *client.HTTPError
	if errors.As(err, &he) {
		switch he.StatusCode {
		case http.StatusNotFound:
			return syscall.ENOENT
		case http.StatusConflict:
			if strings.Contains(he.Message, "not empty") {
				return syscall.ENOTEMPTY
			}
			return syscall.EEXIST
		case http.StatusBadRequest:
			if strings.Contains(he.Message, "not empty") {
				return syscall.ENOTEMPTY
			}
			return syscall.EIO
		case http.StatusUnauthorized, http.StatusForbidden:
			return syscall.EACCES
		case http.StatusInsufficientStorage:
			return syscall.ENOSPC
		default:
			return syscall.EIO
		}
	}
	// 传输层错误（超时/dial 失败/连接重置等）：瞬时故障，EIO 让内核可重试，不负缓存。
	return syscall.EIO
}

// smallConflictErrno 判定 PutSmall 的失败是否属于“服务端明确拒绝、禁止回退”：
//   - 409：目标状态冲突（并发修改/同 op_id 不同内容等）——回退到通用覆盖路径会重传
//     整个文件、绕过 small 通道事务里的目标状态校验（CAS），必须把冲突如实暴露；
//   - 401/403：权限拒绝——换一条路径重试同样无权，且会掩盖真实的访问控制问题；
//   - 426：master 要求特性协商（旧 master 拒收新写法）——此时旧写法同样不被新 master
//     支持，落回旧路径只会制造第二轮错误。
//
// 其余错误（网络失败、5xx 可重试、旧 master 未实现该通道的 404/405/501）不禁止回退。
func smallConflictErrno(err error) (syscall.Errno, bool) {
	if client.IsPlannedWriteError(err) {
		return mapErrno(err), true
	}
	var he *client.HTTPError
	if !errors.As(err, &he) {
		return 0, false
	}
	switch he.StatusCode {
	case http.StatusConflict:
		return mapErrno(err), true
	case http.StatusUnauthorized, http.StatusForbidden:
		return syscall.EACCES, true
	case http.StatusUpgradeRequired:
		return syscall.EIO, true
	}
	return 0, false
}

// ---- 分块读句柄：实现见 chunk_read_handle.go ----
// （整块校验 + per-Mount 有界缓存 + 严格 legacy Range；此前 readChunkRange 对
// 200/206 一律接受、不验 Content-Range/CRC 的缺陷在该文件修复。）

// ---- 写句柄：本地缓冲 + 流式分块上传 ----
//
// 流式模式（方案 B）：写打开即建 staging；WRITE 攒满一个块（64MB）就投给
// StreamUploader 后台上传（并发 ≤2）；Flush 只传最后不满一块的尾巴 + commit。
// close 秒级返回，Finder 不再因等待整个文件上传而"设备已消失"。
//
// 就地编辑（trunc=false）依旧先下载现有内容到本地缓冲——编辑通常改动小，
// Flush 走旧的整传路径（复用覆盖写原子换名），不值得为罕见场景拆块。

type writeHandle struct {
	m          *Mount
	remote     string
	local      string
	f          *os.File
	mu         sync.Mutex
	dirty      bool
	created    bool // 经 Create 新建：即使 0 字节也要上传（否则 Finder 建的空占位文件凭空消失→-43）
	dropped    bool
	plannedErr error
	refs       int   // 引用计数：并发写同一路径共享一个句柄，最后一个 Release 才清理
	size       int64 // 缓冲的逻辑大小；attr 在本地文件已被删/关时用它兜底，避免误报 0 字节

	// 流式上传会话（仅新建/截断写入时启用；trunc=false 就地编辑为 nil 走旧整传）。
	// 整块从本地缓冲文件按"连续写入水位"读出后推入，对 FUSE 并发/乱序写鲁棒
	// （旧版按到达的 data 攒块 + off==sentIdx 判定，一旦写乱序就漏块→commit 死等）。
	stream    *client.StreamUploader
	streamOn  bool
	ino       uint64          // = staging ID（= 提交后 inode ID）；写入中/提交后 st_ino 一致
	sentIdx   int64           // 已作为整块从本地文件推入的字节数（ChunkSize 整数倍）
	contigEnd int64           // 从 0 起连续已写入的字节数（含已推与待推）
	ooo       map[int64]int64 // 越过 contigEnd 的乱序写片段 start→end（FUSE 写页对齐不重叠）
}

var (
	_ fs.FileWriter   = (*writeHandle)(nil)
	_ fs.FileReader   = (*writeHandle)(nil)
	_ fs.FileFlusher  = (*writeHandle)(nil)
	_ fs.FileReleaser = (*writeHandle)(nil)
)

// Read 从本地缓冲文件读：让 O_RDWR / r+ 打开（就地读改写、rsync --inplace 等）能读到
// 当前内容。此前 writeHandle 只实现 FileWriter，go-fuse 对读句柄回 ENOTSUP，读全失败。
func (w *writeHandle) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dropped {
		return nil, syscall.EIO
	}
	nr, err := w.f.ReadAt(dest, off)
	if err != nil && err != io.EOF {
		return nil, syscall.EIO
	}
	return fuse.ReadResultData(dest[:nr]), 0
}

// dropStreamingLocked 放弃流式会话、回退整传（调用方须持 w.mu）。并发写同一路径共享句柄时，
// 多写者交错让"连续写入水位"不再可靠，故降级为 Flush 整传；已推 staging 块由 GC/TTL 回收。
func (w *writeHandle) dropStreamingLocked() {
	if w.stream != nil {
		if err := w.stream.Err(); w.plannedErr == nil && client.IsPlannedWriteError(err) {
			w.plannedErr = err
		}
		_ = w.stream.Close()
		if err := w.stream.Err(); w.plannedErr == nil && client.IsPlannedWriteError(err) {
			w.plannedErr = err
		}
		w.stream = nil
	}
	w.streamOn = false
	w.sentIdx = 0
	w.contigEnd = 0
	w.ooo = nil
}

// newWriteHandle 建立写缓冲。trunc=true 从空文件开始（启用流式）；
// 否则先下载现有内容（就地编辑，走旧整传）。同一路径已有活跃写句柄时共享它（引用计数），
// 而非覆盖 registry——否则旧句柄从 registry 消失：Getattr/Readdir 读到新空缓冲 size 归零、
// 两句柄各自 commit 后写静默丢失、旧临时文件/staging 泄漏。
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
		if err := m.client.Get(remote, tmp.Name()); err != nil {
			// 关键：只有"文件确实不存在"才当空文件开始。其它错误（网络抖动/节点不可达）
			// 若也当空处理，后续 Flush 会用空/截断内容覆盖掉远端好文件（就地编辑丢数据）。
			// 调用方（Open 写打开）已 Lookup 确认文件存在，故非 ENOENT 一律失败。
			if mapErrno(err) != syscall.ENOENT {
				tmp.Close()
				os.Remove(tmp.Name())
				return nil, err
			}
			// 不存在：从空开始（同样能走流式）。
		} else {
			// Get 用完会关闭文件句柄，重新以读写模式打开。
			f, err := os.OpenFile(tmp.Name(), os.O_RDWR, 0o600)
			if err == nil {
				tmp.Close()
				w.f = f
			}
		}
	}
	m.mu.Lock()
	if existing, ok := m.writes[remote]; ok {
		existing.mu.Lock()
		if !existing.dropped {
			existing.refs++
			existing.dropStreamingLocked() // 共享后降级整传，交错写不漏块
			if trunc {
				_ = existing.f.Truncate(0)
				existing.size = 0
				existing.dirty = true
			}
			existing.mu.Unlock()
			m.mu.Unlock()
			w.f.Close()
			os.Remove(w.local) // 丢弃本次多建的临时文件
			return existing, nil
		}
		existing.mu.Unlock()
	}
	w.refs = 1
	if st, serr := w.f.Stat(); serr == nil {
		w.size = st.Size()
	}
	m.writes[remote] = w
	m.mu.Unlock()
	return w, nil
}

// startStream 惰性启动流式会话：首次 WRITE 攒块前调用。
// 已有同路径 staging 的并发写者场景：两个会话各自 staging，commit 时
// 单事务原子换名，后 commit 者胜——与旧路径语义一致。
func (w *writeHandle) startStream() error {
	if w.stream != nil {
		return nil
	}
	u, err := w.m.client.BeginStreamUpload(w.remote, w.m.replicas)
	if err != nil {
		return err
	}
	w.stream = u
	w.streamOn = true
	w.sentIdx = 0
	w.ino = u.StagingID()
	return nil
}

func (w *writeHandle) Write(_ context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dropped {
		return 0, syscall.EIO // 句柄已被 Unlink/Release 丢弃：拒绝对已关闭 fd 写入
	}
	if w.plannedErr != nil {
		return 0, mapErrno(w.plannedErr)
	}
	if w.stream != nil && client.IsPlannedWriteError(w.stream.Err()) {
		w.plannedErr = w.stream.Err()
		return 0, mapErrno(w.plannedErr)
	}
	n, err := w.f.WriteAt(data, off)
	if err != nil {
		return 0, syscall.EIO
	}
	w.dirty = true
	if off+int64(n) > w.size {
		w.size = off + int64(n)
	}
	// 回写到"已作为整块推送过"的区域（off < sentIdx）：推出去的块内容已过期、且无法
	// 重推 → 放弃流式，回退整传（Flush 从完整本地文件重传），绝不提交旧数据。
	if w.streamOn && w.stream != nil && off < w.sentIdx {
		w.dropStreamingLocked()
		if w.plannedErr != nil {
			return 0, mapErrno(w.plannedErr)
		}
		return uint32(n), 0
	}
	if !w.streamOn {
		return uint32(n), 0
	}
	// 更新"从 0 起连续写入水位"。FUSE 并发/乱序投递下，data 的到达顺序不可靠，
	// 故只据水位从本地文件读整块推送——写到哪、按文件真实内容推到哪。
	end := off + int64(n)
	if off <= w.contigEnd {
		if end > w.contigEnd {
			w.contigEnd = end
		}
		for { // 吸收此前乱序、现在能接上的片段
			e, ok := w.ooo[w.contigEnd]
			if !ok {
				break
			}
			delete(w.ooo, w.contigEnd)
			if e > w.contigEnd {
				w.contigEnd = e
			}
		}
	} else {
		if w.ooo == nil {
			w.ooo = make(map[int64]int64)
		}
		if e, ok := w.ooo[off]; !ok || end > e {
			w.ooo[off] = end
		}
	}
	// 小文件留给 Flush 单请求提交；整块可推送时才需要远端会话。
	if w.stream == nil && w.contigEnd >= types.ChunkSize && (w.m.NoSmallPath || w.size > types.SmallFileMax) {
		if err := w.startStream(); err != nil {
			if client.IsPlannedWriteError(err) {
				w.plannedErr = err
			}
			return 0, mapErrno(err)
		}
	}
	// 连续区每够一整块，从文件读出推入（并发 ≤2，满则在此背压等待）。
	if w.stream != nil {
		for w.contigEnd-w.sentIdx >= types.ChunkSize {
			blk := make([]byte, types.ChunkSize)
			if _, err := w.f.ReadAt(blk, w.sentIdx); err != nil {
				return 0, syscall.EIO
			}
			if err := w.stream.Push(blk); err != nil {
				if client.IsPlannedWriteError(err) {
					w.plannedErr = err
				}
				return 0, mapErrno(err)
			}
			w.sentIdx += types.ChunkSize
		}
	}
	return uint32(n), 0
}

// Flush 完成上传。小文件通道（v2-2a）：≤ SmallFileMax 的内容单请求完成（1 次往返）；
// 流式会话：传尾巴 + commit；旧路径（就地编辑/空文件）：整传。可能被多次调用
// （每次 close），成功后幂等。
func (w *writeHandle) Flush(_ context.Context) syscall.Errno {
	w.mu.Lock()
	defer w.mu.Unlock()
	if (!w.dirty && !w.created) || w.dropped {
		return 0
	}
	if w.plannedErr != nil {
		return mapErrno(w.plannedErr)
	}
	if w.stream != nil && client.IsPlannedWriteError(w.stream.Err()) {
		w.plannedErr = w.stream.Err()
		return mapErrno(w.plannedErr)
	}
	st, err := w.f.Stat()
	if err != nil {
		return syscall.EIO
	}

	// v2-2a 小文件单请求通道：数据内联进一个 POST，master 服务端写节点+提交，
	// 客户端 1 次往返（对比流式/整传的 4-5 次）。先放弃流式会话（未推块，abort 无副作用）；
	// 失败则落回下方通用路径重试（网络抖动不放弃写入）。
	if !w.m.NoSmallPath && st.Size() > 0 && st.Size() <= types.SmallFileMax {
		w.dropStreamingLocked()
		if w.plannedErr != nil {
			return mapErrno(w.plannedErr)
		}
		data, rerr := os.ReadFile(w.local)
		if rerr == nil {
			if _, serr := w.m.client.PutSmall(w.remote, data, w.m.replicas, true); serr == nil {
				w.dirty = false
				w.created = false
				w.m.attrInvalidate(w.remote)
				return 0
			} else if errno, blocked := smallConflictErrno(serr); blocked {
				if client.IsPlannedWriteError(serr) {
					w.plannedErr = serr
				}
				return errno
			}
		}
		// 其余失败（网络抖动/5xx 可重试；旧 master 无此通道 404/405/501）→ 继续走
		// 原路径（该路径自会 abort/重建会话）。
	}

	// 流式路径：整块已在 WRITE 期间陆续上传，这里只读尾巴 + commit。
	if w.streamOn && w.stream != nil {
		size := st.Size()
		if size == 0 {
			// 0 字节文件（如 Finder 的空占位）：放弃流式会话，走下方整传的
			// 0 字节路径提交（提交 0 块的 chunked staging 语义不稳，避开）。
			w.dropStreamingLocked()
			if w.plannedErr != nil {
				return mapErrno(w.plannedErr)
			}
		} else if w.contigEnd < size {
			// 文件尾部存在未连续覆盖的空洞（乱序/稀疏写未闭合）：放弃流式、
			// 回退到下方整传路径，从完整的本地文件重传，保证正确性。
			w.dropStreamingLocked()
			if w.plannedErr != nil {
				return mapErrno(w.plannedErr)
			}
		} else {
			var tail []byte
			if size > w.sentIdx { // [sentIdx, size) 必 < 一整块（WRITE 已推完所有整块）
				tail = make([]byte, size-w.sentIdx)
				if _, err := w.f.ReadAt(tail, w.sentIdx); err != nil && err != io.EOF {
					w.plannedErr = err
					w.dropStreamingLocked()
					return syscall.EIO
				}
			}
			if err := w.stream.Finish(tail, size); err != nil {
				if client.IsPlannedWriteError(err) {
					w.plannedErr = err
				}
				w.stream = nil
				return mapErrno(err)
			}
			w.stream = nil
			w.streamOn = false
			w.dirty = false
			w.created = false
			w.m.attrInvalidate(w.remote)
			return 0
		}
	}

	// 旧整传路径（就地编辑、或从未启用流式的小文件）。
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return syscall.EIO
	}
	// commit 前等待的持久性下限：只等主副本（1 份）落盘即返回。
	// 跨公网（EasyTier）环境下节点间复制远慢于写入，等第 2 份 Done 常凑不齐，
	// 阻塞到 15 分钟再 EIO（cp 卡死）。改为主副本落盘即成功，第 2、3 份由后台
	// 复制 + 修复扫描异步补齐——写入即时完成，持久性最终收敛。
	minCopies := w.m.replicas
	if minCopies > 1 {
		minCopies = 1
	}
	var err2 error
	if st.Size() > 0 {
		err2 = w.m.client.PutChunkedReaderWithMinCopies(w.remote, st.Size(), w.f, w.m.replicas, minCopies, true)
	} else {
		err2 = w.m.client.PutReaderOverwrite(w.remote, st.Size(), w.f, w.m.replicas, true)
	}
	if err2 != nil {
		if client.IsPlannedWriteError(err2) {
			w.plannedErr = err2
		}
		return mapErrno(err2)
	}
	w.dirty = false
	w.created = false // 已上传一次，后续 Flush 只在再次 dirty 时重传
	// 上传改变了该路径的大小/存在性——失效缓存，下次 Lookup 拿到真实新属性。
	w.m.attrInvalidate(w.remote)
	return 0
}

// Release 清理本地缓冲与注册表。并发写共享句柄时用引用计数：仅最后一个 Release 真正清理；
// 流式会话若未 Finish（异常关闭）则 abort——staging 由 master TTL 兜底回收，已传块对象由
// GC 两轮确认清理。关文件与删临时文件在 w.mu 内完成，避免与并发 Write/attr 竞争已关 fd。
func (w *writeHandle) Release(_ context.Context) syscall.Errno {
	w.mu.Lock()
	if w.dropped {
		w.mu.Unlock()
		return 0
	}
	if w.refs > 1 {
		w.refs-- // 还有其他 fd 共享该句柄，暂不清理
		w.mu.Unlock()
		return 0
	}
	w.dropped = true
	if w.stream != nil {
		_ = w.stream.Close() // 未 Finish 的会话：abort staging
		w.stream = nil
	}
	w.f.Close()
	os.Remove(w.local)
	w.mu.Unlock()
	w.m.mu.Lock()
	if cur, ok := w.m.writes[w.remote]; ok && cur == w {
		delete(w.m.writes, w.remote)
	}
	w.m.mu.Unlock()
	return 0
}

// discard 丢弃缓冲（Unlink 写入中文件时用），不触发上传。unlink 是破坏性意图，
// 无视引用计数直接丢弃；其他共享 fd 的后续读写会被 dropped 守卫挡回 EIO。
func (w *writeHandle) discard() {
	w.mu.Lock()
	if w.dropped {
		w.mu.Unlock()
		return
	}
	w.dropped = true
	w.dirty = false
	if w.stream != nil {
		_ = w.stream.Close() // abort staging（预建 staging 后被 unlink：别泄漏）
		w.stream = nil
	}
	w.f.Close()
	os.Remove(w.local)
	w.mu.Unlock()
}

func (w *writeHandle) truncate(size uint64) syscall.Errno {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dropped {
		return syscall.EIO
	}
	sz := int64(size)
	// Finder 拷贝会先 ftruncate 到完整大小做预分配，再顺序写。这属于"增长/预分配"，
	// 与流式并不冲突——若在此放弃流式，整份文件就退回 close 时整传、大文件必然把
	// Finder 的 close 拖超时（「设备已消失」）。因此：只有截断到"已推整块之下"才
	// 真冲突（会孤立已推块），才放弃流式回退整传；否则保留流式，按新大小夹逼水位。
	if w.stream != nil && sz < w.sentIdx {
		w.dropStreamingLocked()
		if w.plannedErr != nil {
			return mapErrno(w.plannedErr)
		}
	} else if w.streamOn && sz < w.contigEnd {
		w.contigEnd = sz
		for k := range w.ooo {
			if k >= sz {
				delete(w.ooo, k)
			}
		}
	}
	if err := w.f.Truncate(sz); err != nil {
		return syscall.EIO
	}
	w.size = sz
	w.dirty = true
	return 0
}

// localReadHandle 伺服"写入中(staging)文件"的只读打开：直接读本地缓冲文件，
// 不经 master（此时 master 里还没有这个文件）。允许 Finder 回读校验、预览等。
type localReadHandle struct{ f *os.File }

var (
	_ fs.FileReader   = (*localReadHandle)(nil)
	_ fs.FileReleaser = (*localReadHandle)(nil)
	_ fs.FileFlusher  = (*localReadHandle)(nil)
)

func (h *localReadHandle) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	nr, err := h.f.ReadAt(dest, off)
	if err != nil && err != io.EOF {
		return nil, syscall.EIO
	}
	return fuse.ReadResultData(dest[:nr]), 0
}

func (h *localReadHandle) Flush(_ context.Context) syscall.Errno { return 0 }

func (h *localReadHandle) Release(_ context.Context) syscall.Errno {
	h.f.Close()
	return 0
}

// attr 把本地缓冲文件的属性填入 fuse.Attr。st_ino 用 inoFor（与远端 ID 解耦）。
// 在 w.mu 内取属性：本地文件已被并发 Release/discard 关闭删除时，退回记录的逻辑大小 w.size，
// 而不是让 os.Stat 失败后误报 0 字节（Finder "文件突然变 0 字节" 的来源）。
func (w *writeHandle) attr(a *fuse.Attr) {
	w.mu.Lock()
	defer w.mu.Unlock()
	a.Uid = uint32(os.Getuid())
	a.Gid = uint32(os.Getgid())
	a.Ino = w.m.inoFor(w.remote)
	a.Mode = fuse.S_IFREG | 0o644
	if st, err := os.Stat(w.local); err == nil && !w.dropped {
		a.Size = uint64(st.Size())
		a.Mtime = uint64(st.ModTime().Unix())
	} else {
		a.Size = uint64(w.size)
	}
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

// Seekdir 实现 fs.FileSeekdirer：内核对已读过的目录回卷/跳位（Finder 刷新窗口实测
// 会发 offset 回 0 的 READDIR）时按偏移重定位。此前未实现 → go-fuse 回 ENOTSUP。
// 偏移语义 = 已消费条目数（bridge 为每个条目分配 1 起的递增 Off）。
func (s *sliceDirStream) Seekdir(_ context.Context, off uint64) syscall.Errno {
	if off > uint64(len(s.entries)) {
		off = uint64(len(s.entries)) // 越界按 EOF，下一次 Next 即 HasNext=false
	}
	s.pos = int(off)
	return 0
}

func (s *sliceDirStream) Close() {}
