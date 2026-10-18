// Package edgeidentity 提供边缘节点的持久 Ed25519 身份。
//
// 设计边界：
//   - NodeID 是自有版本化格式 "nid1-"+base32(sha256(pubkey))，明确不是 libp2p
//     PeerID（PeerID 是公钥 protobuf 编码的 multihash，两者不可互换、不可互推）。
//   - 签名只绑定 caller 明确定义的 typed Challenge（含域分隔协议版本），不构造
//     通用万能 token；防重放由上层对 Challenge.Nonce 做一次性登记，本库的验证
//     不声称阻止重放。
//   - 稳定身份（NodeID，从公钥派生）与可变地址（IP/端口等）分离：本库只产出前者。
//   - 私钥文件损坏时绝不重新生成覆盖——宁可拒绝启动，由运维显式介入。
package edgeidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// IdentityProtocolVersion 是身份与签名的域分隔串，进所有签名输入，防跨协议重放。
const IdentityProtocolVersion = "atoll-edge-identity-v1"

// NodeIDPrefix 是节点 ID 体系版本前缀；换派生算法时必须换前缀。
const NodeIDPrefix = "nid1"

const (
	fileFormatVersion = 1
	fileMagicLen      = 4
	// keyFileLen = magic(4) + version(1) + ed25519 私钥(64)。
	keyFileLen = fileMagicLen + 1 + ed25519.PrivateKeySize
)

// fileMagic 私钥文件魔数，读取时严格比对。
var fileMagic = [fileMagicLen]byte{'A', 'T', 'I', 'D'}

// publicationWindow 内允许把“文件存在但长度不足”视为他方正在原子发布中并重试；
// 超窗仍不完整则按损坏拒绝（绝不重生成）。测试可缩短。
var (
	publicationWindow     = 2 * time.Second
	publicationRetryDelay = 25 * time.Millisecond
	// disableLinkForTest 仅供测试注入：跳过 link 尝试，模拟不支持 hard link
	// 的文件系统，使 fail-closed 与退化发布路径在任意卷上可确定性测试。
	disableLinkForTest = false
	// injectTempWriteFailureForTest 仅供测试注入：create 写 temp 文件时返回
	// 该错误，用于验证 temp 失败路径的清理（无残留）与绝不触碰 final 路径。
	injectTempWriteFailureForTest error
	// injectPublishWriteFailureForTest 仅供测试注入：publishDirect 在 O_EXCL
	// 创建成功后的写入阶段返回该错误，用于确定性验证退化发布中段失败的
	// fail-stop 语义（残片保留、绝不盲删 final 路径）。
	injectPublishWriteFailureForTest error
)

// errPublicationInProgress 表示文件存在但尚未写完整：可能是并发发布中，
// 也可能是进程崩溃留下的残片。两者都不允许重生成，前者重试，后者报错待人处理。
var errPublicationInProgress = errors.New("edgeidentity: 私钥文件不完整（正在发布或为崩溃残片）")

// ErrNonAtomicFS 表示所在文件系统不支持 hard link，默认 fail-closed 拒绝创建。
// 身份应放在本地文件系统；确需在不支持 hard link 的卷上运行时，显式用
// WithAllowNonAtomicFallback 接受非原子发布语义。
var ErrNonAtomicFS = errors.New("edgeidentity: 文件系统不支持 hard link，无法原子发布持久身份")

// loadOrCreateConfig 承载 LoadOrCreate 的显式选项。
type loadOrCreateConfig struct {
	allowNonAtomicFallback bool
}

// Option 是 LoadOrCreate 的可选项。
type Option func(*loadOrCreateConfig)

// WithAllowNonAtomicFallback 显式 opt-in：在不支持 hard link 的文件系统上改用
// O_EXCL 独占直写发布。该路径**不是原子发布**：崩溃可能把不完整文件留在最终
// 路径上，此后 LoadOrCreate 只会有界重试后报错待人处理（绝不重生成）；窗口期
// 并发读者可能失败。默认 fail-closed，本选项不应在生产正常拓扑中使用。
func WithAllowNonAtomicFallback() Option {
	return func(c *loadOrCreateConfig) { c.allowNonAtomicFallback = true }
}

// NodeID 是从公钥 SHA-256 派生的稳定节点标识，格式
// "nid1-"+base32(RFC 4648 标准字母表，大写)无填充(sha256(pubkey))
// （256bit 全长，不截断）。
// 大小写敏感：小写变体是不同的字符串，一律按精确字节比较。
// 明确不是 libp2p PeerID：PeerID 基于公钥 protobuf 的 multihash，无法互推。
type NodeID string

func (n NodeID) String() string { return string(n) }

// DeriveNodeID 从 Ed25519 公钥派生版本化节点 ID。
//
// 编码固定为 base32 标准字母表（RFC 4648，大写 A-Z/2-7）无填充：小写变体
// 只改大小写不改比特，容易让人误以为 NodeID 大小写不敏感。本实现选择大写
// 并由测试钉死，比较 NodeID 一律用精确字节比较，大小写不同即不同节点。
func DeriveNodeID(pub ed25519.PublicKey) NodeID {
	sum := sha256Sum(pub)
	return NodeID(NodeIDPrefix + "-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum))
}

// Identity 是一个已加载的节点身份。私钥字段绝不通过任何导出方法或
// String()/Format()/GoString() 泄漏；把 *Identity 当 fmt 参数用（含 %#v）
// 也只会看到 NodeID。
//
// 注意：Go 的可导出字段为零（全部私有），值拷贝 *id 或包外组合不会泄漏；
// 唯一能拿到私钥字节的途径是本包代码。仍应避免把 Identity 值传来传去——
// 按惯例一律用 *Identity。
type Identity struct {
	nodeID NodeID
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
}

// NodeID 返回稳定节点标识。
func (id *Identity) NodeID() NodeID { return id.nodeID }

// PublicKey 返回公钥副本。
func (id *Identity) PublicKey() ed25519.PublicKey {
	out := make(ed25519.PublicKey, len(id.pub))
	copy(out, id.pub)
	return out
}

// String 只返回 NodeID，绝不包含私钥材料。
func (id Identity) String() string { return id.nodeID.String() }

func (id Identity) GoString() string {
	return "edgeidentity.Identity(" + id.nodeID.String() + ")"
}

func (id Identity) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		fmt.Fprint(f, id.GoString())
		return
	}
	if verb == 'q' {
		fmt.Fprintf(f, "%q", id.nodeID.String())
		return
	}
	fmt.Fprint(f, id.nodeID.String())
}

// LoadOrCreate 从 path 加载持久身份；不存在则以原子发布方式创建。
//
// 安全约束：
//   - 发布：先写唯一 temp（0600）并 fsync，再 os.Link 原子不替换发布，最后
//     父目录 fsync。文件系统不支持 hard link 时默认 fail-closed（ErrNonAtomicFS），
//     绝不悄悄降级；显式 WithAllowNonAtomicFallback 才走非原子退化路径。
//   - 坏文件（magic/版本/长度/两半不一致）一律报错且原文件不动，绝不重生成。
//   - symlink、非普通文件、权限含 group/other 位一律拒绝（不自动 chmod）。
//   - 并发 LoadOrCreate 在原子发布路径下经不替换发布仲裁：恰好一个身份胜出，
//     其余读到同一份，永不读半钥匙、永不换身份。退化路径无此保证（见选项说明）。
//
// 加载现有密钥也同步文件和父目录，避免并发创建者尚未同步目录时提前
// 确认一个崩溃后可能消失的身份。文件系统必须正确实现同步语义。
func LoadOrCreate(path string, opts ...Option) (*Identity, error) {
	if path == "" {
		return nil, errors.New("edgeidentity: path 为空")
	}
	cfg := &loadOrCreateConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	deadline := time.Now().Add(publicationWindow)
	for {
		id, err := load(path)
		switch {
		case err == nil:
			return id, nil
		case errors.Is(err, fs.ErrNotExist):
			created, cerr := create(path, cfg)
			if cerr == nil {
				return created, nil
			}
			if errors.Is(cerr, fs.ErrExist) {
				// 他方先发布了；读对方写好的完整文件。
				if time.Now().After(deadline) {
					// EEXIST 说明文件此刻一定存在：最后一次 load 要么成功，
					// 要么给出真实原因（损坏/权限），比返回裸 link 错误有用。
					if id, lerr := load(path); lerr == nil {
						return id, nil
					}
					return nil, fmt.Errorf("edgeidentity: 并发发布后仍无法读取 %s: %w", path, cerr)
				}
				time.Sleep(publicationRetryDelay)
				continue
			}
			return nil, cerr
		case errors.Is(err, errPublicationInProgress) && time.Now().Before(deadline):
			time.Sleep(publicationRetryDelay)
		default:
			return nil, err
		}
	}
}

// load 只通过已打开句柄检查并读取，防 Lstat→open 之间路径被换成 symlink 的竞态。
func load(path string) (*Identity, error) {
	f, err := os.OpenFile(path, os.O_RDWR|openKeyFlags, 0)
	if err != nil {
		if isSymlinkOpenErr(err) {
			return nil, fmt.Errorf("edgeidentity: %s 是符号链接，拒绝", path)
		}
		return nil, err
	}
	defer f.Close()

	// 校验句柄指向的真实对象，而非路径。
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("edgeidentity: %s 不是普通文件（%v），拒绝", path, fi.Mode().Type())
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("edgeidentity: %s 权限 %04o 过宽（要求仅属主可读写），拒绝；请手动 chmod 600", path, perm)
	}
	if fi.Size() < keyFileLen {
		return nil, errPublicationInProgress
	}
	buf := make([]byte, keyFileLen+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	if n < keyFileLen {
		return nil, errPublicationInProgress
	}
	if n > keyFileLen {
		return nil, fmt.Errorf("edgeidentity: %s 比预期格式长（至少 %d 字节），拒绝", path, n)
	}
	priv, err := parseKeyFile(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("edgeidentity: %s: %w", path, err)
	}
	// Another creator may have linked the key but not synced its directory yet.
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := fsyncDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return newIdentity(priv), nil
}

// parseKeyFile 严格解析：magic、版本、定长，且必须用 seed 重导出公钥并与
// 文件后半段一致——64 字节随机值长度合法但两半不一致，同样拒绝。
func parseKeyFile(blob []byte) (ed25519.PrivateKey, error) {
	if len(blob) != keyFileLen {
		return nil, fmt.Errorf("长度 %d 不符（期望 %d）", len(blob), keyFileLen)
	}
	if !bytes.Equal(blob[:fileMagicLen], fileMagic[:]) {
		return nil, errors.New("magic 不符，疑似损坏或异构文件；绝不重新生成覆盖")
	}
	if blob[fileMagicLen] != fileFormatVersion {
		return nil, fmt.Errorf("文件格式版本 %d 不支持（本库为 %d）", blob[fileMagicLen], fileFormatVersion)
	}
	priv := ed25519.PrivateKey(blob[fileMagicLen+1:])
	// 注意：ed25519.PrivateKey.Public() 只会原样返回 priv[32:]，不做重导出，
	// 不能用来校验一致性；必须用 NewKeyFromSeed 从 seed 真正重导出公钥再比对。
	derived := ed25519.NewKeyFromSeed(priv[:32])
	if !bytes.Equal(derived[32:], priv[32:]) {
		return nil, errors.New("私钥两半不一致（损坏或伪造），拒绝")
	}
	return priv, nil
}

func newIdentity(priv ed25519.PrivateKey) *Identity {
	pub := priv.Public().(ed25519.PublicKey)
	return &Identity{nodeID: DeriveNodeID(pub), pub: pub, priv: priv}
}

// create 生成新私钥并发布到 path。返回 fs.ErrExist 表示并发他方已发布。
func create(path string, cfg *loadOrCreateConfig) (*Identity, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("edgeidentity: 生成密钥失败: %w", err)
	}
	blob := make([]byte, 0, keyFileLen)
	blob = append(blob, fileMagic[:]...)
	blob = append(blob, fileFormatVersion)
	blob = append(blob, priv...)

	tmp, err := os.CreateTemp(dir, ".edgeidentity-tmp-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	// 失败路径清理 temp；成功路径把 tmpName 置空避免重复删除。
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	werr := error(nil)
	if injectTempWriteFailureForTest != nil {
		werr = injectTempWriteFailureForTest
	} else if _, err := tmp.Write(blob); err != nil {
		werr = err
	}
	if werr != nil {
		tmp.Close()
		return nil, werr
	}
	// 数据先 fsync 再发布，保证他方（或重启后的进程）link 后读到的一定是完整内容。
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	if !disableLinkForTest {
		switch linkErr := os.Link(tmpName, path); {
		case linkErr == nil:
			os.Remove(tmpName) // 同一 inode 的第二名字；目录一致性由下面 fsync 兜底
			tmpName = ""
			if err := fsyncDir(dir); err != nil {
				return nil, err
			}
			return newIdentity(priv), nil
		case errors.Is(linkErr, fs.ErrExist):
			return nil, linkErr
		case !linkUnsupported(linkErr):
			return nil, linkErr
		}
	}
	// 走到这里 = 不支持 hard link（或测试注入）。默认 fail-closed，绝不悄悄
	// 弱化“原子发布持久身份”契约；只有显式 opt-in 才走非原子退化路径。
	if !cfg.allowNonAtomicFallback {
		return nil, fmt.Errorf("%w: 把身份放到本地文件系统，或显式用 WithAllowNonAtomicFallback 接受非原子发布语义", ErrNonAtomicFS)
	}
	return publishDirect(path, blob, priv, dir)
}

// publishDirect 是无 hard link 文件系统上的退化发布：O_EXCL 独占创建后一次性
// 写入并 fsync。窗口期并发读者会看到不完整文件并按“发布中”重试。
//
// 失败语义 fail-stop：任何写入/sync/close 失败都保留 final 路径上的残片并
// 返回错误，**绝不 os.Remove(path)**。原因：O_EXCL 只保证“创建那一刻”的独占，
// 之后他方（另一进程/线程）完全可能合法地发布了同名文件；盲目删除会删掉
// 陌生人的合法替换。残片留给运维确认处理，与“崩溃残片不重生成”语义一致。
func publishDirect(path string, blob []byte, priv ed25519.PrivateKey, dir string) (*Identity, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	werr := error(nil)
	if injectPublishWriteFailureForTest != nil {
		werr = injectPublishWriteFailureForTest
	} else if _, err := f.Write(blob); err != nil {
		werr = err
	}
	if werr != nil {
		f.Close()
		return nil, fmt.Errorf("edgeidentity: 非原子直写失败，残片保留在 %s 待人工处理: %w", path, werr)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("edgeidentity: 非原子直写 fsync 失败，残片保留在 %s 待人工处理: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("edgeidentity: 非原子直写 close 失败，残片保留在 %s 待人工处理: %w", path, err)
	}
	if err := fsyncDir(dir); err != nil {
		return nil, err
	}
	return newIdentity(priv), nil
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
