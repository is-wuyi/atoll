package meta

// 安全账号系统（bucketSecurity）：用户 / 会话 / 个人与团队空间。
//
// 范围约束（与 device/ticket/upload 的 security_* 文件分工）：
//   - 本文件只负责账号、会话、空间记录与成员 ACL 的持久化；设备、在线票据、
//     上传归属由主流程的 security_devices / security_tickets / security_uploads 实现，
//     各文件仅共享 bucketSecurity 桶，key 前缀互不重叠。
//   - 启用安全模式（BootstrapSecurity）时在 RootID 下创建受保护空间树
//     （.atoll-spaces/personal|teams），独立于旧 legacy 根内容：不迁移、不自动暴露。
//   - 所有持久变更走 s.write + w.put(bcSecurity, …) 进 WAL；对外成功返回前 EnsureDurable
//     （幂等重放不产生帧时也不例外）。
//   - 认证面失败（口令错误/未知用户/会话过期或吊销/邀请失效、禁用、越权）统一返回
//     ErrAuthentication，不做原因枚举，避免用户/空间枚举侧信道。

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

// ---- 常量与错误 ----

const (
	// SpacesRootName 是受保护空间树的根目录名（RootID 下）。冲突即拒绝，不收编旧目录。
	SpacesRootName    = ".atoll-spaces"
	dirPersonalSpaces = "personal"
	dirTeamSpaces     = "teams"

	// SessionTTL 是会话固定有效期。
	SessionTTL = 24 * time.Hour
	// maxInviteTTL 限制邀请最长有效期，避免永久有效邀请长期挂在库里。
	maxInviteTTL = 30 * 24 * time.Hour

	// maxParentChainDepth 限制 ParentID 链回溯深度：正常树远小于该值；
	// 超限按"不在空间内"拒绝（覆盖成环与异常深链）。
	maxParentChainDepth = 4096

	usernameMaxLen = 64
	teamNameMaxLen = 64
	// bcrypt 硬上限 72 字节；下限拒绝弱口令。
	passwordMinLen = 12
	passwordMaxLen = 72
)

var (
	// ErrAuthentication 统一认证/授权失败：不区分口令错误、账号禁用、会话失效、
	// 邀请失效、非成员/非 owner 越权等，避免枚举。
	ErrAuthentication = errors.New("authentication failed")
	// ErrSecurityEnabled 安全系统已启用（Bootstrap 重复调用）。
	ErrSecurityEnabled = errors.New("security already enabled")
	// ErrSecurityDisabled 安全系统未启用。
	ErrSecurityDisabled = errors.New("security not enabled")
	// ErrSpaceRootConflict RootID 下已存在 SpacesRootName 同名条目——拒绝启动，
	// 绝不收编旧用户目录为空间根。
	ErrSpaceRootConflict = errors.New("spaces root name already exists")
	// ErrOutsideSpace inode/object 的 ParentID 链未到达目标空间根（含成环、断链）。
	ErrOutsideSpace = errors.New("outside space subtree")
)

// passwordHashCost 是账号口令的 bcrypt 代价。var 仅为测试可降速；生产恒为 DefaultCost。
var passwordHashCost = bcrypt.DefaultCost

// ---- 类型 ----

// Role 是空间成员角色。owner 只属于创建者（个人空间恒为 owner；
// 团队空间仅 owner 可管理成员），成员只有读写两档。
type Role string

const (
	RoleOwner Role = "owner"
	RoleRead  Role = "read"
	RoleWrite Role = "write"
)

// SpaceKind 区分个人空间与团队空间。
type SpaceKind string

const (
	SpacePersonal SpaceKind = "personal"
	SpaceTeam     SpaceKind = "team"
)

// PublicUser 是对外的用户视图。字段刻意收敛：绝不含口令散列等敏感内容。
type PublicUser struct {
	ID              uint64 `json:"id"`
	Username        string `json:"username"`
	PlatformAdmin   bool   `json:"platform_admin"`
	Disabled        bool   `json:"disabled"`
	PersonalSpaceID uint64 `json:"personal_space_id"`
}

// UserRecord 是落库的完整用户记录；PasswordHash 只存在于 bucketSecurity，
// 对外一律经 PublicUser 公开（见 public()）。
type UserRecord struct {
	ID              uint64    `json:"id"`
	Username        string    `json:"username"`
	PasswordHash    string    `json:"password_hash"`
	PlatformAdmin   bool      `json:"platform_admin"`
	Disabled        bool      `json:"disabled"`
	CreatedAt       time.Time `json:"created_at"`
	PersonalSpaceID uint64    `json:"personal_space_id"`
}

func (r UserRecord) public() PublicUser {
	return PublicUser{
		ID:              r.ID,
		Username:        r.Username,
		PlatformAdmin:   r.PlatformAdmin,
		Disabled:        r.Disabled,
		PersonalSpaceID: r.PersonalSpaceID,
	}
}

// Space 即空间记录（公开与落库同形：不含敏感字段）。
// InternalPath 是空间根相对文件系统根的持久化路径（如 /.atoll-spaces/personal/alice），
// 路径翻译由 master 包装层完成，本层只提供落库值。
type Space struct {
	ID           uint64    `json:"id"`
	Name         string    `json:"name"`
	Kind         SpaceKind `json:"kind"`
	OwnerID      uint64    `json:"owner_id"`
	RootID       uint64    `json:"root_id"`
	InternalPath string    `json:"internal_path"`
}

// Session 是登录结果：Token 只在本次响应出现一次，库里只存其散列。
type Session struct {
	Token     string     `json:"token"`
	User      PublicUser `json:"user"`
	ExpiresAt time.Time  `json:"expires_at"`
}

// SessionRecord 落库会话：只有 token 散列（作为 key）与归属。
type SessionRecord struct {
	UserID    uint64    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// InviteRecord 是一次性邀请（TTL 内单次使用）。
type InviteRecord struct {
	CreatorID uint64    `json:"creator_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	UsedBy    uint64    `json:"used_by,omitempty"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

// securityConfig 是安全系统的启用标记与空间树锚点。
type securityConfig struct {
	EnabledAt     time.Time `json:"enabled_at"`
	SpacesRootID  uint64    `json:"spaces_root_id"`
	PersonalDirID uint64    `json:"personal_dir_id"`
	TeamsDirID    uint64    `json:"teams_dir_id"`
}

type memberRecord struct {
	Role Role `json:"role"`
}

// ---- key 编码（bucketSecurity 内，前缀互不重叠）----

var (
	keySecConfig    = []byte("cfg/security")
	keySecNextUser  = []byte("cnt/user")
	keySecNextSpace = []byte("cnt/space")

	secPrefixUser    = []byte("user/")  // + u64be(id)
	secPrefixUname   = []byte("uname/") // + username
	secPrefixSession = []byte("sess/")  // + sha256(token)
	secPrefixInvite  = []byte("inv/")   // + sha256(code)
	secPrefixSpace   = []byte("spc/")   // + u64be(id)
	secPrefixMember  = []byte("mem/")   // + u64be(userID) + u64be(spaceID)
)

func secKeyUser(id uint64) []byte    { return append(append([]byte{}, secPrefixUser...), u64be(id)...) }
func secKeyUname(name string) []byte { return append(append([]byte{}, secPrefixUname...), name...) }
func secKeySession(h []byte) []byte  { return append(append([]byte{}, secPrefixSession...), h...) }
func secKeyInvite(h []byte) []byte   { return append(append([]byte{}, secPrefixInvite...), h...) }
func secKeySpace(id uint64) []byte   { return append(append([]byte{}, secPrefixSpace...), u64be(id)...) }
func secKeyMember(user, space uint64) []byte {
	k := append(append([]byte{}, secPrefixMember...), u64be(user)...)
	return append(k, u64be(space)...)
}

// ---- 散列 / 随机凭据 ----

// hashOpaqueToken / newOpaqueToken 只服务账号层的会话与邀请码；device/ticket 层
// 自带独立命名实现，避免跨文件耦合。
func hashOpaqueToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func newOpaqueToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// burnPasswordTiming 在用户不存在时也执行一次同代价 bcrypt，抹平
// "未知用户立即返回 vs 已知用户跑散列" 的响应时间差（用户名枚举侧信道）。
var (
	timingPadMu   sync.Mutex
	timingPadHash []byte
	timingPadCost int
)

func burnPasswordTiming(password string) {
	timingPadMu.Lock()
	defer timingPadMu.Unlock()
	if timingPadHash == nil || timingPadCost != passwordHashCost {
		h, err := bcrypt.GenerateFromPassword([]byte("atoll-timing-pad"), passwordHashCost)
		if err == nil {
			timingPadHash, timingPadCost = h, passwordHashCost
		}
	}
	if timingPadHash != nil {
		_ = bcrypt.CompareHashAndPassword(timingPadHash, []byte(password))
	}
}

// ---- 输入校验 ----

// normalizeUsername 统一小写后校验：1..64 字节 ASCII [a-z0-9._-]。
// 注册与认证同走此函数，"Alice" 与 "alice" 是同一账号，无大小写歧义。
func normalizeUsername(name string) (string, error) {
	name = strings.ToLower(name)
	if name == "" || name == "." || name == ".." || len(name) > usernameMaxLen {
		return "", fmt.Errorf("%w: username length or shape", ErrBadName)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return "", fmt.Errorf("%w: username charset", ErrBadName)
		}
	}
	return name, nil
}

func validatePassword(password string) error {
	if len(password) < passwordMinLen || len(password) > passwordMaxLen {
		return fmt.Errorf("password must be %d..%d bytes", passwordMinLen, passwordMaxLen)
	}
	return nil
}

func validateTeamName(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if len(name) > teamNameMaxLen {
		return fmt.Errorf("%w: team name too long", ErrBadName)
	}
	return nil
}

// ---- bucketSecurity 读写原语 ----

func putSecurityJSON(w *txw, key []byte, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return w.put(bcSecurity, bucketSecurity, key, raw)
}

func getSecurityJSON(tx *bolt.Tx, key []byte, out any) (bool, error) {
	raw := tx.Bucket(bucketSecurity).Get(key)
	if raw == nil {
		return false, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false, err
	}
	return true, nil
}

func walkSecurity(tx *bolt.Tx, prefix []byte, visit func(key, value []byte) error) error {
	c := tx.Bucket(bucketSecurity).Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		if err := visit(k, v); err != nil {
			return err
		}
	}
	return nil
}

// nextSecurityID 分配 user/space 等安全域 ID（计数器自增记 WAL，恢复后延续）。
func nextSecurityID(w *txw, key []byte) (uint64, error) {
	cur := uint64(1)
	if v := w.tx.Bucket(bucketSecurity).Get(key); v != nil {
		cur = beU64(v)
	}
	if cur == ^uint64(0) {
		return 0, errors.New("security id space exhausted")
	}
	if err := w.put(bcSecurity, bucketSecurity, key, u64be(cur+1)); err != nil {
		return 0, err
	}
	return cur, nil
}

// createDirTx 在记录型事务内新建目录（putInode + children，进 WAL）。已存在即拒绝。
func createDirTx(w *txw, parentID uint64, name string) (types.Inode, error) {
	if err := validateName(name); err != nil {
		return types.Inode{}, err
	}
	if hasChild(w.tx, parentID, name) {
		return types.Inode{}, ErrExist
	}
	id, err := w.nextID(keyNextInode)
	if err != nil {
		return types.Inode{}, err
	}
	in := types.Inode{ID: id, ParentID: parentID, Name: name, Type: types.TypeDir, Mtime: time.Now()}
	if err := w.putInode(&in); err != nil {
		return types.Inode{}, err
	}
	if err := w.putChild(parentID, name, id); err != nil {
		return types.Inode{}, err
	}
	return in, nil
}

// ---- 事务内读取助手（device/ticket/upload 事务可复用）----

func securityEnabledTx(tx *bolt.Tx) (bool, error) {
	_, ok, err := securityConfigTx(tx)
	return ok, err
}

func securityConfigTx(tx *bolt.Tx) (securityConfig, bool, error) {
	var cfg securityConfig
	ok, err := getSecurityJSON(tx, keySecConfig, &cfg)
	if err != nil {
		return cfg, false, fmt.Errorf("invalid security configuration: %w", err)
	}
	if !ok {
		// Missing configuration is legacy only if no initialized account state remains.
		for _, prefix := range [][]byte{secPrefixUser, secPrefixSpace, keySecNextUser, keySecNextSpace} {
			k, _ := tx.Bucket(bucketSecurity).Cursor().Seek(prefix)
			if bytes.HasPrefix(k, prefix) {
				return cfg, false, errors.New("security configuration missing from initialized database")
			}
		}
		return cfg, false, nil
	}
	if cfg.EnabledAt.IsZero() || cfg.SpacesRootID <= RootID || cfg.PersonalDirID <= RootID || cfg.TeamsDirID <= RootID ||
		cfg.SpacesRootID == cfg.PersonalDirID || cfg.SpacesRootID == cfg.TeamsDirID || cfg.PersonalDirID == cfg.TeamsDirID {
		return cfg, false, errors.New("invalid security configuration anchors")
	}
	return cfg, true, nil
}

func userByIDTx(tx *bolt.Tx, userID uint64) (UserRecord, bool, error) {
	var rec UserRecord
	ok, err := getSecurityJSON(tx, secKeyUser(userID), &rec)
	if !ok {
		return UserRecord{}, false, err
	}
	return rec, true, err
}

func userByNameTx(tx *bolt.Tx, username string) (UserRecord, bool, error) {
	raw := tx.Bucket(bucketSecurity).Get(secKeyUname(username))
	if raw == nil {
		return UserRecord{}, false, nil
	}
	return userByIDTx(tx, beU64(raw))
}

func spaceTx(tx *bolt.Tx, spaceID uint64) (Space, bool, error) {
	var spc Space
	ok, err := getSecurityJSON(tx, secKeySpace(spaceID), &spc)
	if !ok {
		return Space{}, false, err
	}
	return spc, true, err
}

func memberRoleTx(tx *bolt.Tx, userID, spaceID uint64) (Role, bool, error) {
	var mr memberRecord
	ok, err := getSecurityJSON(tx, secKeyMember(userID, spaceID), &mr)
	if !ok {
		return "", false, err
	}
	return mr.Role, true, err
}

// sessionUserHashTx 是会话校验的散列入口：sessionHash = sha256(token) 原始 32 字节
// （库内 key = "sess/" 前缀 + 该散列，非 hex）。ticket/device 记录只落散列、
// 每次核验经此函数实时判定登出/禁用/过期状态。
func sessionUserHashTx(tx *bolt.Tx, sessionHash []byte, now time.Time) (UserRecord, error) {
	if len(sessionHash) != sha256.Size {
		return UserRecord{}, ErrAuthentication
	}
	var sr SessionRecord
	ok, err := getSecurityJSON(tx, secKeySession(sessionHash), &sr)
	if err != nil {
		return UserRecord{}, err
	}
	if !ok || !now.Before(sr.ExpiresAt) {
		return UserRecord{}, ErrAuthentication
	}
	rec, ok, err := userByIDTx(tx, sr.UserID)
	if err != nil {
		return UserRecord{}, err
	}
	if !ok || rec.Disabled {
		return UserRecord{}, ErrAuthentication
	}
	return rec, nil
}

// sessionUserTx 校验会话（token 明文 → 散列查库 → 未过期 → 用户存在且未禁用），
// 返回内部用户记录。供在线授权组合事务复用；外层公开入口是 UserForSession。
func sessionUserTx(tx *bolt.Tx, token string, now time.Time) (UserRecord, error) {
	if token == "" {
		return UserRecord{}, ErrAuthentication
	}
	return sessionUserHashTx(tx, hashOpaqueToken(token), now)
}

// authorizeSpaceTx 在事务内做空间授权判定：用户存在未禁用；platformAdmin 通吃；
// 否则须为成员且角色覆盖所需权限。失败统一 ErrAuthentication（不区分空间不存在）。
func authorizeSpaceTx(tx *bolt.Tx, userID, spaceID uint64, write bool) (Space, error) {
	user, ok, err := userByIDTx(tx, userID)
	if err != nil {
		return Space{}, err
	}
	if !ok || user.Disabled {
		return Space{}, ErrAuthentication
	}
	spc, ok, err := spaceTx(tx, spaceID)
	if err != nil {
		return Space{}, err
	}
	if !ok {
		return Space{}, ErrAuthentication
	}
	if !user.PlatformAdmin {
		role, isMember, err := memberRoleTx(tx, userID, spaceID)
		if err != nil {
			return Space{}, err
		}
		allowed := isMember && (role == RoleOwner || role == RoleWrite || (role == RoleRead && !write))
		if !allowed {
			return Space{}, ErrAuthentication
		}
	}
	return spc, nil
}

// inodeInSpaceTx 判断 inode 是否位于空间子树内：沿 ParentID 链回溯
// （staging inode 的 ParentID 同样指向树内，天然覆盖），须先到达空间根；
// 到达 fs 根、断链、成环、超深一律拒绝。
func inodeInSpaceTx(tx *bolt.Tx, spaceID, inodeID uint64) error {
	spc, ok, err := spaceTx(tx, spaceID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotExist
	}
	if inodeID == RootID {
		return ErrOutsideSpace // fs 根不属于任何空间
	}
	cur, err := getInodeTx(tx, inodeID)
	if err != nil {
		return err
	}
	for depth := 0; depth < maxParentChainDepth; depth++ {
		if cur.ID == spc.RootID {
			return nil
		}
		if cur.ID == RootID || cur.ParentID == 0 {
			return fmt.Errorf("%w: chain reached fs root at inode %d", ErrOutsideSpace, cur.ID)
		}
		parent, err := getInodeTx(tx, cur.ParentID)
		if err != nil {
			return fmt.Errorf("%w: parent chain broken at inode %d", ErrOutsideSpace, cur.ID)
		}
		cur = parent
	}
	return fmt.Errorf("%w: parent chain too deep from inode %d", ErrOutsideSpace, inodeID)
}

// objectAnchorTx 解析内容对象的归属锚点 inode：
//   - ObjectIDBase 以上的 registry 对象：pending 且未发布 → 归属 Target.ParentID
//     （发布校验同一父目录）；其余归属 FileID。
//   - 旧式整对象/块对象 ID：经 integrityTx 反查所属文件 inode（含采纳式替换后的
//     staging 派生 ID 全表兜底）。
func objectAnchorTx(tx *bolt.Tx, objectID uint64) (uint64, error) {
	if objectID >= types.ObjectIDBase {
		obj, err := objectTx(tx, objectID)
		if err != nil {
			return 0, err
		}
		if obj.State != objectLive && obj.State != objectPending {
			return 0, ErrNotExist
		}
		if obj.State == objectPending && obj.Target != nil && obj.Target.ParentID != 0 {
			return obj.Target.ParentID, nil
		}
		if obj.FileID == 0 {
			return 0, ErrNotExist
		}
		return obj.FileID, nil
	}
	d, err := integrityTx(tx, objectID)
	if err != nil {
		return 0, err
	}
	if d.InodeID == 0 {
		return 0, ErrNotExist
	}
	return d.InodeID, nil
}

// ---- 用户与空间创建（单事务原语）----

// createUserWithSpaceTx 在一个记录型事务内创建用户及其个人空间：
// 分配 user/space ID → 建 personal/<username> 根目录（putInode/children 进 WAL）→
// 落 user 记录 + 用户名索引 + space 记录 + owner 成员关系。
func createUserWithSpaceTx(w *txw, personalDirID uint64, uname, passwordHash string, platformAdmin bool, now time.Time) (UserRecord, Space, error) {
	userID, err := nextSecurityID(w, keySecNextUser)
	if err != nil {
		return UserRecord{}, Space{}, err
	}
	spaceID, err := nextSecurityID(w, keySecNextSpace)
	if err != nil {
		return UserRecord{}, Space{}, err
	}
	rootIno, err := createDirTx(w, personalDirID, uname)
	if err != nil {
		return UserRecord{}, Space{}, err
	}
	rec := UserRecord{
		ID: userID, Username: uname, PasswordHash: passwordHash,
		PlatformAdmin: platformAdmin, CreatedAt: now, PersonalSpaceID: spaceID,
	}
	if err := putSecurityJSON(w, secKeyUser(userID), rec); err != nil {
		return UserRecord{}, Space{}, err
	}
	if err := w.put(bcSecurity, bucketSecurity, secKeyUname(uname), u64be(userID)); err != nil {
		return UserRecord{}, Space{}, err
	}
	spc := Space{
		ID: spaceID, Name: uname, Kind: SpacePersonal, OwnerID: userID,
		RootID:       rootIno.ID,
		InternalPath: internalSpacePath(SpacesRootName, dirPersonalSpaces, uname),
	}
	if err := putSecurityJSON(w, secKeySpace(spaceID), spc); err != nil {
		return UserRecord{}, Space{}, err
	}
	if err := putSecurityJSON(w, secKeyMember(userID, spaceID), memberRecord{Role: RoleOwner}); err != nil {
		return UserRecord{}, Space{}, err
	}
	return rec, spc, nil
}

func internalSpacePath(parts ...string) string {
	return "/" + strings.Join(parts, "/")
}

// ---- 公开 API：启用与状态 ----

// BootstrapSecurity 启用安全用户系统并创建首位平台管理员及其个人空间。
// 单事务原子：启用标记 + .atoll-spaces 树（personal/teams 容器）+ 管理员 + 空间。
// RootID 下已存在 SpacesRootName 同名条目时拒绝（绝不收编旧目录）；已启用时拒绝。
func (s *Store) BootstrapSecurity(username, password string, now time.Time) (PublicUser, Space, error) {
	if now.IsZero() {
		now = time.Now()
	}
	uname, err := normalizeUsername(username)
	if err != nil {
		return PublicUser{}, Space{}, err
	}
	if err := validatePassword(password); err != nil {
		return PublicUser{}, Space{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		return PublicUser{}, Space{}, fmt.Errorf("hash password: %w", err)
	}
	var user PublicUser
	var space Space
	err = s.write(func(w *txw) error {
		if _, ok, err := securityConfigTx(w.tx); err != nil {
			return err
		} else if ok {
			return ErrSecurityEnabled
		}
		if hasChild(w.tx, RootID, SpacesRootName) {
			return ErrSpaceRootConflict
		}
		rootIno, err := createDirTx(w, RootID, SpacesRootName)
		if err != nil {
			return err
		}
		personalIno, err := createDirTx(w, rootIno.ID, dirPersonalSpaces)
		if err != nil {
			return err
		}
		teamsIno, err := createDirTx(w, rootIno.ID, dirTeamSpaces)
		if err != nil {
			return err
		}
		rec, spc, err := createUserWithSpaceTx(w, personalIno.ID, uname, string(hash), true, now)
		if err != nil {
			return err
		}
		cfg := securityConfig{
			EnabledAt: now, SpacesRootID: rootIno.ID,
			PersonalDirID: personalIno.ID, TeamsDirID: teamsIno.ID,
		}
		if err := putSecurityJSON(w, keySecConfig, cfg); err != nil {
			return err
		}
		user, space = rec.public(), spc
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	if err != nil {
		return PublicUser{}, Space{}, err
	}
	return user, space, nil
}

// SecurityEnabled 报告安全用户系统是否已启用。
func (s *Store) SecurityEnabled() (bool, error) {
	enabled := false
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		enabled, err = securityEnabledTx(tx)
		return err
	})
	return enabled, err
}

// ---- 公开 API：邀请与注册 ----

// CreateUserInvite 创建一次性注册邀请（仅平台管理员），返回邀请码（只出现一次，
// 库里只存散列）。expiresAt 必须在 (now, now+maxInviteTTL] 内。
func (s *Store) CreateUserInvite(actorUserID uint64, expiresAt, now time.Time) (string, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return "", errors.New("invite expiry must be in the future")
	}
	if expiresAt.After(now.Add(maxInviteTTL)) {
		return "", fmt.Errorf("invite expiry beyond %v", maxInviteTTL)
	}
	code, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	err = s.write(func(w *txw) error {
		actor, ok, err := userByIDTx(w.tx, actorUserID)
		if err != nil {
			return err
		}
		if !ok || actor.Disabled || !actor.PlatformAdmin {
			return ErrAuthentication
		}
		rec := InviteRecord{CreatorID: actorUserID, CreatedAt: now, ExpiresAt: expiresAt}
		return putSecurityJSON(w, secKeyInvite(hashOpaqueToken(code)), rec)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	if err != nil {
		return "", err
	}
	return code, nil
}

// RegisterInvitedUser 用一次性邀请注册新用户并创建其个人空间。
// 并发同名注册在同一写事务内裁决：一个赢家，其余统一 ErrAuthentication。
// 邀请未知/已用/过期与用户名冲突不做区分。
func (s *Store) RegisterInvitedUser(invite, username, password string, now time.Time) (PublicUser, Space, error) {
	if now.IsZero() {
		now = time.Now()
	}
	uname, err := normalizeUsername(username)
	if err != nil {
		return PublicUser{}, Space{}, ErrAuthentication
	}
	if err := validatePassword(password); err != nil {
		return PublicUser{}, Space{}, ErrAuthentication
	}
	if invite == "" {
		return PublicUser{}, Space{}, ErrAuthentication
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		return PublicUser{}, Space{}, ErrAuthentication
	}
	inviteHash := hashOpaqueToken(invite)
	var user PublicUser
	var space Space
	err = s.write(func(w *txw) error {
		cfg, ok, err := securityConfigTx(w.tx)
		if err != nil {
			return err
		}
		if !ok {
			return ErrSecurityDisabled
		}
		var inv InviteRecord
		ok, err = getSecurityJSON(w.tx, secKeyInvite(inviteHash), &inv)
		if err != nil {
			return err
		}
		if !ok || inv.Used || !inv.ExpiresAt.After(now) {
			return ErrAuthentication
		}
		if _, ok, err := userByNameTx(w.tx, uname); err != nil {
			return err
		} else if ok {
			return ErrAuthentication
		}
		rec, spc, err := createUserWithSpaceTx(w, cfg.PersonalDirID, uname, string(hash), false, now)
		if err != nil {
			return err
		}
		inv.Used, inv.UsedBy, inv.UsedAt = true, rec.ID, now
		if err := putSecurityJSON(w, secKeyInvite(inviteHash), inv); err != nil {
			return err
		}
		user, space = rec.public(), spc
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	if err != nil {
		return PublicUser{}, Space{}, err
	}
	return user, space, nil
}

// ---- 公开 API：认证与会话 ----

// AuthenticateUser 校验口令并签发会话（随机 32 字节 token 只返回一次，落库为散列）。
// 未知用户也跑一次等代价比较，抹平时序差。
func (s *Store) AuthenticateUser(username, password string, now time.Time) (Session, error) {
	if now.IsZero() {
		now = time.Now()
	}
	uname, err := normalizeUsername(username)
	if err != nil {
		burnPasswordTiming(password)
		return Session{}, ErrAuthentication
	}
	var sess Session
	err = s.write(func(w *txw) error {
		rec, ok, err := userByNameTx(w.tx, uname)
		if err != nil {
			return err
		}
		if !ok {
			burnPasswordTiming(password)
			return ErrAuthentication
		}
		if rec.Disabled {
			burnPasswordTiming(password)
			return ErrAuthentication
		}
		if bcrypt.CompareHashAndPassword([]byte(rec.PasswordHash), []byte(password)) != nil {
			return ErrAuthentication
		}
		token, err := newOpaqueToken()
		if err != nil {
			return err
		}
		expiresAt := now.Add(SessionTTL)
		sr := SessionRecord{UserID: rec.ID, CreatedAt: now, ExpiresAt: expiresAt}
		if err := putSecurityJSON(w, secKeySession(hashOpaqueToken(token)), sr); err != nil {
			return err
		}
		sess = Session{Token: token, User: rec.public(), ExpiresAt: expiresAt}
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	if err != nil {
		return Session{}, err
	}
	return sess, nil
}

// UserForSession 校验会话令牌并返回脱敏用户视图（禁用账号即时拒绝）。
func (s *Store) UserForSession(token string, now time.Time) (PublicUser, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var pub PublicUser
	err := s.db.View(func(tx *bolt.Tx) error {
		rec, err := sessionUserTx(tx, token, now)
		if err != nil {
			return err
		}
		pub = rec.public()
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	if err != nil {
		return PublicUser{}, err
	}
	return pub, nil
}

// RevokeSession 吊销会话（登出）。未知/已吊销令牌统一 ErrAuthentication。
func (s *Store) RevokeSession(token string) error {
	if token == "" {
		return ErrAuthentication
	}
	key := secKeySession(hashOpaqueToken(token))
	err := s.write(func(w *txw) error {
		if w.tx.Bucket(bucketSecurity).Get(key) == nil {
			return ErrAuthentication
		}
		return w.del(bcSecurity, bucketSecurity, key)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}

// ---- 公开 API：账号管理 ----

// revokeUserSessionsTx 在记录型事务内删除某用户全部会话（先收集后删，避免游标中变更桶）。
// 停用与改密共用：旧令牌不得跨账号状态变更存活。
func revokeUserSessionsTx(w *txw, userID uint64) error {
	var victims [][]byte
	if err := walkSecurity(w.tx, secPrefixSession, func(k, v []byte) error {
		var sr SessionRecord
		if json.Unmarshal(v, &sr) == nil && sr.UserID == userID {
			victims = append(victims, append([]byte{}, k...))
		}
		return nil
	}); err != nil {
		return err
	}
	for _, k := range victims {
		if err := w.del(bcSecurity, bucketSecurity, k); err != nil {
			return err
		}
	}
	return nil
}

// DisableUser 停用/恢复账号（仅平台管理员，不能停用自己）。停用即时生效：
// 该用户全部会话同事务删除，auth/access 路径亦即时拒绝。
func (s *Store) DisableUser(actorUserID, targetUserID uint64, disabled bool) error {
	err := s.write(func(w *txw) error {
		actor, ok, err := userByIDTx(w.tx, actorUserID)
		if err != nil {
			return err
		}
		if !ok || actor.Disabled || !actor.PlatformAdmin {
			return ErrAuthentication
		}
		target, ok, err := userByIDTx(w.tx, targetUserID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotExist
		}
		if disabled && target.ID == actor.ID {
			return errors.New("cannot disable own account")
		}
		if target.Disabled == disabled {
			return nil // 幂等
		}
		target.Disabled = disabled
		if err := putSecurityJSON(w, secKeyUser(target.ID), target); err != nil {
			return err
		}
		if !disabled {
			return nil
		}
		return revokeUserSessionsTx(w, target.ID)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}

// ChangePassword 校验旧口令并更新散列（不扩大 bcrypt 代价，后续如需再升）。
// 成功即同事务吊销该用户全部旧会话（含发起本次调用的会话）——泄露令牌不得跨改密存活，
// 客户端以新口令重新登录即可。
func (s *Store) ChangePassword(userID uint64, oldPassword, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), passwordHashCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	err = s.write(func(w *txw) error {
		rec, ok, err := userByIDTx(w.tx, userID)
		if err != nil {
			return err
		}
		if !ok || rec.Disabled {
			burnPasswordTiming(oldPassword)
			return ErrAuthentication
		}
		if bcrypt.CompareHashAndPassword([]byte(rec.PasswordHash), []byte(oldPassword)) != nil {
			return ErrAuthentication
		}
		rec.PasswordHash = string(hash)
		if err := putSecurityJSON(w, secKeyUser(rec.ID), rec); err != nil {
			return err
		}
		return revokeUserSessionsTx(w, rec.ID)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}

// ---- 公开 API：空间与成员 ----

// CreateTeam 由任意未禁用用户创建独立团队空间。团队名不全局唯一（避免借重名探测
// 他人团队存在）：同名团队各自持有独立 space ID，目录名以 "-<spaceID>" 后缀消歧，
// 归属以 RootID/OwnerID 记录为准。
func (s *Store) CreateTeam(actorUserID uint64, name string) (Space, error) {
	if err := validateTeamName(name); err != nil {
		return Space{}, err
	}
	var space Space
	err := s.write(func(w *txw) error {
		cfg, ok, err := securityConfigTx(w.tx)
		if err != nil {
			return err
		}
		if !ok {
			return ErrSecurityDisabled
		}
		actor, ok, err := userByIDTx(w.tx, actorUserID)
		if err != nil {
			return err
		}
		if !ok || actor.Disabled {
			return ErrAuthentication
		}
		spaceID, err := nextSecurityID(w, keySecNextSpace)
		if err != nil {
			return err
		}
		teamIno, err := createDirTx(w, cfg.TeamsDirID, teamDirName(name, spaceID))
		if err != nil {
			return err
		}
		spc := Space{
			ID: spaceID, Name: name, Kind: SpaceTeam, OwnerID: actorUserID,
			RootID:       teamIno.ID,
			InternalPath: internalSpacePath(SpacesRootName, dirTeamSpaces, teamDirName(name, spaceID)),
		}
		if err := putSecurityJSON(w, secKeySpace(spaceID), spc); err != nil {
			return err
		}
		if err := putSecurityJSON(w, secKeyMember(actorUserID, spaceID), memberRecord{Role: RoleOwner}); err != nil {
			return err
		}
		space = spc
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	if err != nil {
		return Space{}, err
	}
	return space, nil
}

// teamDirName 生成 teams 容器下的目录名：空间 ID 全局唯一，故 "<name>-<id>" 恒唯一。
func teamDirName(name string, spaceID uint64) string {
	return fmt.Sprintf("%s-%d", name, spaceID)
}

// ListUserSpaces 返回用户可见空间：普通用户为个人空间 + 成员团队；
// 平台管理员可见全部空间。
func (s *Store) ListUserSpaces(userID uint64) ([]Space, error) {
	var out []Space
	err := s.db.View(func(tx *bolt.Tx) error {
		user, ok, err := userByIDTx(tx, userID)
		if err != nil {
			return err
		}
		if !ok || user.Disabled {
			return ErrAuthentication
		}
		if user.PlatformAdmin {
			return walkSecurity(tx, secPrefixSpace, func(_, v []byte) error {
				var spc Space
				if err := json.Unmarshal(v, &spc); err != nil {
					return err
				}
				out = append(out, spc)
				return nil
			})
		}
		// 成员前缀 = "mem/" + u64be(userID)（不含 space 段），按序扫描该用户全部成员关系。
		prefix := append(append([]byte{}, secPrefixMember...), u64be(userID)...)
		return walkSecurity(tx, prefix, func(k, _ []byte) error {
			spaceID := beU64(k[len(prefix):])
			spc, ok, err := spaceTx(tx, spaceID)
			if err != nil {
				return err
			}
			if ok {
				out = append(out, spc)
			}
			return nil // 悬空成员关系（空间记录缺失）跳过
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetTeamMember 由团队 owner 增改成员角色（read/write）。个人空间成员不可改；
// owner 角色不可授予或变更；目标用户必须存在且未禁用。
func (s *Store) SetTeamMember(actorUserID, spaceID, targetUserID uint64, role Role) error {
	if role != RoleRead && role != RoleWrite {
		return fmt.Errorf("invalid role %q", role)
	}
	err := s.write(func(w *txw) error {
		spc, ok, err := spaceTx(w.tx, spaceID)
		if err != nil {
			return err
		}
		if !ok || spc.Kind != SpaceTeam || spc.OwnerID != actorUserID {
			return ErrAuthentication
		}
		actor, ok, err := userByIDTx(w.tx, actorUserID)
		if err != nil {
			return err
		}
		if !ok || actor.Disabled {
			return ErrAuthentication
		}
		if targetUserID == spc.OwnerID {
			return ErrAuthentication
		}
		target, ok, err := userByIDTx(w.tx, targetUserID)
		if err != nil {
			return err
		}
		if !ok || target.Disabled {
			return ErrNotExist // 缺失与停用不做区分
		}
		if existing, isMember, err := memberRoleTx(w.tx, targetUserID, spaceID); err != nil {
			return err
		} else if isMember && existing == role {
			return nil // 幂等重放：不占帧
		}
		return putSecurityJSON(w, secKeyMember(targetUserID, spaceID), memberRecord{Role: role})
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}

// RemoveTeamMember 由团队 owner 移除成员。owner 自身不可移除，个人空间无成员操作。
// 目标本就非成员时幂等成功。
func (s *Store) RemoveTeamMember(actorUserID, spaceID, targetUserID uint64) error {
	err := s.write(func(w *txw) error {
		spc, ok, err := spaceTx(w.tx, spaceID)
		if err != nil {
			return err
		}
		if !ok || spc.Kind != SpaceTeam || spc.OwnerID != actorUserID {
			return ErrAuthentication
		}
		actor, ok, err := userByIDTx(w.tx, actorUserID)
		if err != nil {
			return err
		}
		if !ok || actor.Disabled {
			return ErrAuthentication
		}
		if targetUserID == spc.OwnerID {
			return ErrAuthentication
		}
		return w.del(bcSecurity, bucketSecurity, secKeyMember(targetUserID, spaceID))
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}

// AuthorizeSpace 判定用户对空间的当前读/写权限并返回空间记录。
// 失败统一 ErrAuthentication（空间不存在与无权不做区分）。
func (s *Store) AuthorizeSpace(userID, spaceID uint64, write bool) (Space, error) {
	var spc Space
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		spc, err = authorizeSpaceTx(tx, userID, spaceID, write)
		return err
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	if err != nil {
		return Space{}, err
	}
	return spc, nil
}

// InodeInSpace 校验 inode（含 staging）位于空间子树内。
// inode 缺失返回 ErrNotExist；不在空间内/断链/成环返回 ErrOutsideSpace。
func (s *Store) InodeInSpace(spaceID, inodeID uint64) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return inodeInSpaceTx(tx, spaceID, inodeID)
	})
}

// ObjectInSpace 判断内容对象是否归属空间：解析归属锚点（pending 小文件取
// Target.ParentID，live 取 FileID，旧式对象经 integrityTx 反查）后走 ParentID 链。
// 对象缺失返回 (false, err)；存在但在空间外返回 (false, nil)。
func (s *Store) ObjectInSpace(spaceID, objectID uint64) (bool, error) {
	var anchor uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		anchor, err = objectAnchorTx(tx, objectID)
		return err
	})
	if err != nil {
		return false, err
	}
	if err := s.InodeInSpace(spaceID, anchor); err != nil {
		if errors.Is(err, ErrOutsideSpace) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
