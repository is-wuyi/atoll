package console

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role 控制台角色。admin 可执行破坏性操作（GC/触发修复），readonly 仅观测。
// 用 scope×action 会更细，但当前只有两级需求——先做够用的，多用户时再扩。
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleReadonly Role = "readonly"
)

// User 是一个控制台账号（与 master 集群无关，独立于 atoll 文件用户）。
type User struct {
	Username string `json:"username"`
	Hash     string `json:"hash"` // bcrypt
	Role     Role   `json:"role"`
}

// userStore 持久化控制台账号到 data-dir/users.json（0600）。
type userStore struct {
	path  string
	mu    sync.RWMutex
	users map[string]User
}

func openUserStore(dataDir string) (*userStore, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	s := &userStore{path: filepath.Join(dataDir, "users.json"), users: map[string]User{}}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var list []User
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parse users.json: %w", err)
	}
	for _, u := range list {
		s.users[u.Username] = u
	}
	return s, nil
}

func (s *userStore) save() error {
	list := make([]User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	// 先写临时文件再改名：避免写一半崩溃留下损坏的 users.json。
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *userStore) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// Count / Add 是给 CLI（atoll console useradd）用的导出封装。
func (s *userStore) Count() int { return s.count() }

func (s *userStore) Add(username, password string, role Role) error {
	if role != RoleAdmin && role != RoleReadonly {
		return fmt.Errorf("invalid role %q (want admin|readonly)", role)
	}
	return s.add(username, password, role)
}

var errUserExists = errors.New("user already exists")

func (s *userStore) add(username, password string, role Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; ok {
		return errUserExists
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.users[username] = User{Username: username, Hash: string(hash), Role: role}
	return s.save()
}

// list 返回全部账号（按用户名升序），供管理 UI 展示。Hash 字段不会出现在模板里。
func (s *userStore) list() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// adminCount 统计 admin 角色账号数（在锁内调用）。
func (s *userStore) adminCount() int {
	n := 0
	for _, u := range s.users {
		if u.Role == RoleAdmin {
			n++
		}
	}
	return n
}

var (
	errUserNotFound = errors.New("user not found")
	errLastAdmin    = errors.New("cannot remove or demote the last admin")
)

// remove 删除账号。拒绝删掉最后一个 admin（否则控制台会永久锁死）。
func (s *userStore) remove(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return errUserNotFound
	}
	if u.Role == RoleAdmin && s.adminCount() == 1 {
		return errLastAdmin
	}
	delete(s.users, username)
	return s.save()
}

// setRole 改角色。把最后一个 admin 降级为 readonly 同样会锁死，拒绝。
func (s *userStore) setRole(username string, role Role) error {
	if role != RoleAdmin && role != RoleReadonly {
		return fmt.Errorf("invalid role %q (want admin|readonly)", role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return errUserNotFound
	}
	if u.Role == RoleAdmin && role == RoleReadonly && s.adminCount() == 1 {
		return errLastAdmin
	}
	u.Role = role
	s.users[username] = u
	return s.save()
}

// verify 校验用户名+密码，成功返回用户。bcrypt 比较本身是常数时间的。
func (s *userStore) verify(username, password string) (User, bool) {
	s.mu.RLock()
	u, ok := s.users[username]
	s.mu.RUnlock()
	if !ok {
		// 仍跑一次 bcrypt 消除"用户是否存在"的时序差异。
		bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali"), []byte(password))
		return User{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) != nil {
		return User{}, false
	}
	return u, true
}

// ---- 会话 ----

type session struct {
	Username string
	Role     Role
	CSRF     string
	Expires  time.Time
}

// sessionStore 内存会话表（进程重启即失效——控制台是运维工具，重登可接受）。
type sessionStore struct {
	mu  sync.Mutex
	m   map[string]session
	ttl time.Duration
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{m: map[string]session{}, ttl: ttl}
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

func (s *sessionStore) create(u User) (sid string, sess session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sid = randToken()
	sess = session{Username: u.Username, Role: u.Role, CSRF: randToken(), Expires: time.Now().Add(s.ttl)}
	s.m[sid] = sess
	return sid, sess
}

func (s *sessionStore) get(sid string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[sid]
	if !ok {
		return session{}, false
	}
	if time.Now().After(sess.Expires) {
		delete(s.m, sid)
		return session{}, false
	}
	return sess, true
}

func (s *sessionStore) destroy(sid string) {
	s.mu.Lock()
	delete(s.m, sid)
	s.mu.Unlock()
}

const sessionCookie = "atoll_console_session"

// currentSession 从请求 Cookie 取回有效会话。
func (srv *Server) currentSession(r *http.Request) (session, bool) {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	return srv.sessions.get(ck.Value)
}
