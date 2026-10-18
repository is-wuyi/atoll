package meta

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

// securityFastHash 把 bcrypt 降到 MinCost，避免测试套件被 KDF 拖慢。
// meta 包测试无 t.Parallel，串行执行下全局代价切换安全。
func securityFastHash(t *testing.T) {
	t.Helper()
	old := passwordHashCost
	passwordHashCost = bcrypt.MinCost
	t.Cleanup(func() { passwordHashCost = old })
}

func bootstrapAdmin(t *testing.T, s *Store) (PublicUser, Space) {
	t.Helper()
	user, space, err := s.BootstrapSecurity("admin", "admin-password-123", time.Now())
	if err != nil {
		t.Fatalf("BootstrapSecurity: %v", err)
	}
	return user, space
}

func inviteAndRegister(t *testing.T, s *Store, adminID uint64, username string, at time.Time) (PublicUser, Space) {
	t.Helper()
	code, err := s.CreateUserInvite(adminID, at.Add(time.Hour), at)
	if err != nil {
		t.Fatalf("CreateUserInvite: %v", err)
	}
	user, space, err := s.RegisterInvitedUser(code, username, "invited-password-1", at)
	if err != nil {
		t.Fatalf("RegisterInvitedUser(%s): %v", username, err)
	}
	return user, space
}

func TestBootstrapSecurityCreatesProtectedTree(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	// legacy 根内容先存在：启用安全系统不得迁移、不得触碰。
	if _, err := s.CreateDir(RootID, "legacy-stuff"); err != nil {
		t.Fatalf("CreateDir legacy: %v", err)
	}
	admin, space := bootstrapAdmin(t, s)
	if !admin.PlatformAdmin {
		t.Fatal("首位用户应为平台管理员")
	}
	enabled, err := s.SecurityEnabled()
	if err != nil || !enabled {
		t.Fatalf("SecurityEnabled = %v, %v", enabled, err)
	}
	root, err := s.ResolvePath("/" + SpacesRootName + "/personal/admin")
	if err != nil || root.ID != space.RootID {
		t.Fatalf("空间根不可解析: %v %v vs %d", root, err, space.RootID)
	}
	if space.Kind != SpacePersonal || space.OwnerID != admin.ID || space.Name != "admin" {
		t.Fatalf("空间记录不符: %+v", space)
	}
	if space.InternalPath != "/"+SpacesRootName+"/personal/admin" {
		t.Fatalf("InternalPath = %q", space.InternalPath)
	}
	if _, err := s.ResolvePath("/legacy-stuff"); err != nil {
		t.Fatalf("legacy 内容被改动: %v", err)
	}
	// 重复启用拒绝。
	if _, _, err := s.BootstrapSecurity("other", "other-password-12", time.Now()); !errors.Is(err, ErrSecurityEnabled) {
		t.Fatalf("重复 Bootstrap err = %v", err)
	}
	// PublicUser 不得携带敏感字段。
	raw, _ := json.Marshal(admin)
	if strings.Contains(strings.ToLower(string(raw)), "password") || strings.Contains(string(raw), "hash") {
		t.Fatalf("PublicUser 泄漏敏感字段: %s", raw)
	}
}

func TestBootstrapRejectsConflictingSpacesRoot(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	if _, err := s.CreateDir(RootID, SpacesRootName); err != nil {
		t.Fatal(err)
	}
	// 同名条目已存在：拒绝且不收编。
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", time.Now()); !errors.Is(err, ErrSpaceRootConflict) {
		t.Fatalf("err = %v, want ErrSpaceRootConflict", err)
	}
	enabled, _ := s.SecurityEnabled()
	if enabled {
		t.Fatal("冲突时不得置位启用标记")
	}
	// 移除冲突条目后可启用（证明是拒绝而非静默采纳旧目录内容）。
	conflict, err := s.Lookup(RootID, SpacesRootName)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDir(conflict.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", time.Now()); err != nil {
		t.Fatalf("清除冲突后 Bootstrap: %v", err)
	}
}

func TestInviteRegistrationFlow(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	base := time.Now()

	// 非管理员不能发邀请（先造一个普通用户）。
	alice, _ := inviteAndRegister(t, s, admin.ID, "alice", base)
	if alice.PlatformAdmin {
		t.Fatal("邀请注册的用户不得默认授予管理员")
	}
	if _, err := s.CreateUserInvite(alice.ID, base.Add(time.Hour), base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("非管理员发邀请 err = %v", err)
	}
	// 过期边界与超长 TTL。
	if _, err := s.CreateUserInvite(admin.ID, base, base); err == nil {
		t.Fatal("expiresAt 必须晚于 now")
	}
	if _, err := s.CreateUserInvite(admin.ID, base.Add(31*24*time.Hour), base); err == nil {
		t.Fatal("超出 maxInviteTTL 应拒绝")
	}

	code, err := s.CreateUserInvite(admin.ID, base.Add(time.Hour), base)
	if err != nil {
		t.Fatal(err)
	}
	// 用户名大小写归一：注册 "Bob" 落库 "bob"。
	user, space, err := s.RegisterInvitedUser(code, "Bob", "invited-password-1", base)
	if err != nil {
		t.Fatalf("注册: %v", err)
	}
	if user.Username != "bob" || space.Name != "bob" || space.Kind != SpacePersonal {
		t.Fatalf("注册结果: %+v %+v", user, space)
	}
	if _, err := s.ResolvePath("/" + SpacesRootName + "/personal/bob"); err != nil {
		t.Fatalf("个人空间根: %v", err)
	}
	// 同一邀请一次性。
	if _, _, err := s.RegisterInvitedUser(code, "carol", "invited-password-1", base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("重用邀请 err = %v", err)
	}
	// 过期邀请。
	expCode, _ := s.CreateUserInvite(admin.ID, base.Add(time.Hour), base)
	if _, _, err := s.RegisterInvitedUser(expCode, "carol", "invited-password-1", base.Add(2*time.Hour)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("过期邀请 err = %v", err)
	}
	// 未知邀请与非法输入。
	for _, tc := range []struct{ code, name, pw string }{
		{"bogus-code", "carol", "invited-password-1"},
		{"", "carol", "invited-password-1"},
	} {
		if _, _, err := s.RegisterInvitedUser(tc.code, tc.name, tc.pw, base); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("邀请 %q err = %v", tc.code, err)
		}
	}
	// 用户名冲突统一 ErrAuthentication（不暴露他人用户名）。
	dup, _ := s.CreateUserInvite(admin.ID, base.Add(time.Hour), base)
	if _, _, err := s.RegisterInvitedUser(dup, "ALICE", "invited-password-1", base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("同名注册 err = %v", err)
	}
}

func TestSignupRaceSameUsername(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	base := time.Now()
	codes := make([]string, 2)
	for i := range codes {
		c, err := s.CreateUserInvite(admin.ID, base.Add(time.Hour), base)
		if err != nil {
			t.Fatal(err)
		}
		codes[i] = c
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, code := range codes {
		wg.Add(1)
		go func(code string) {
			defer wg.Done()
			_, _, err := s.RegisterInvitedUser(code, "racer", "invited-password-1", base)
			errs <- err
		}(code)
	}
	wg.Wait()
	close(errs)
	wins, losses := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrAuthentication):
			losses++
		default:
			t.Fatalf("竞态注册异常错误: %v", err)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatalf("并发同名注册 wins=%d losses=%d, want 1/1", wins, losses)
	}
}

func TestAuthenticateAndSessionLifecycle(t *testing.T) {
	// 本测试保留 DefaultCost：验证真实代价下的散列与校验路径。
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	base := time.Now()
	// 密文落库：bucketSecurity 存 bcrypt 散列而非明文。
	err := s.db.View(func(tx *bolt.Tx) error {
		rec, ok, err := userByNameTx(tx, "admin")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("用户记录缺失")
		}
		if strings.Contains(rec.PasswordHash, "admin-password-123") {
			return errors.New("口令明文落库")
		}
		if !strings.HasPrefix(rec.PasswordHash, "$2") {
			return errors.New("落库口令不是 bcrypt 散列")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// 失败路径统一 ErrAuthentication。
	for _, tc := range []struct{ name, pw string }{
		{"admin", "wrong-password-99"},
		{"ghost", "whatever-password"},
		{"has space", "whatever-password"},
		{"", "whatever-password"},
	} {
		if _, err := s.AuthenticateUser(tc.name, tc.pw, base); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("Authenticate(%q) err = %v", tc.name, err)
		}
	}
	sess, err := s.AuthenticateUser("admin", "admin-password-123", base)
	if err != nil {
		t.Fatalf("认证: %v", err)
	}
	if sess.Token == "" || !sess.ExpiresAt.After(base) {
		t.Fatalf("会话内容: %+v", sess)
	}
	// 大小写归一登录。
	if _, err := s.AuthenticateUser("ADMIN", "admin-password-123", base); err != nil {
		t.Fatalf("大写用户名登录: %v", err)
	}
	pub, err := s.UserForSession(sess.Token, base.Add(time.Minute))
	if err != nil || pub.ID != admin.ID {
		t.Fatalf("UserForSession: %+v %v", pub, err)
	}
	// 固定 TTL 到期。
	if _, err := s.UserForSession(sess.Token, base.Add(SessionTTL+time.Second)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("过期会话 err = %v", err)
	}
	// 吊销（登出）后立即失效，重复吊销同样 ErrAuthentication。
	if err := s.RevokeSession(sess.Token); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := s.UserForSession(sess.Token, base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("吊销后 err = %v", err)
	}
	if err := s.RevokeSession(sess.Token); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("重复吊销 err = %v", err)
	}
	// 换口令：旧口令失效、新口令可用、既有会话同事务全部吊销；新口令长度约束。
	pre, err := s.AuthenticateUser("admin", "admin-password-123", base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserForSession(pre.Token, base); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(admin.ID, "wrong-password-99", "new-password-456"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("旧口令校验 err = %v", err)
	}
	if err := s.ChangePassword(admin.ID, "admin-password-123", "short"); err == nil {
		t.Fatal("过短新口令应拒绝")
	}
	if err := s.ChangePassword(admin.ID, "admin-password-123", "new-password-456"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if _, err := s.UserForSession(pre.Token, base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("改密后旧会话 err = %v", err)
	}
	if _, err := s.AuthenticateUser("admin", "new-password-456", base); err != nil {
		t.Fatalf("新口令登录: %v", err)
	}
}

func TestDisabledUserImmediateRejection(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, adminSpace := bootstrapAdmin(t, s)
	base := time.Now()
	alice, aliceSpace := inviteAndRegister(t, s, admin.ID, "alice", base)
	sess, err := s.AuthenticateUser("alice", "invited-password-1", base)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DisableUser(admin.ID, admin.ID, true); err == nil {
		t.Fatal("不得停用自己")
	}
	if err := s.DisableUser(alice.ID, admin.ID, true); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("非管理员停用 err = %v", err)
	}
	if err := s.DisableUser(admin.ID, 424242, true); !errors.Is(err, ErrNotExist) {
		t.Fatalf("未知目标 err = %v", err)
	}
	if err := s.DisableUser(admin.ID, alice.ID, true); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	// 即时拒绝：会话 / 认证 / 空间访问。
	if _, err := s.UserForSession(sess.Token, base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("禁用后会话 err = %v", err)
	}
	if _, err := s.AuthenticateUser("alice", "invited-password-1", base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("禁用后认证 err = %v", err)
	}
	if _, err := s.AuthorizeSpace(alice.ID, aliceSpace.ID, false); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("禁用后访问 err = %v", err)
	}
	// 恢复后旧会话不可复用（停用时已同事务删除）。
	if err := s.DisableUser(admin.ID, alice.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserForSession(sess.Token, base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("恢复后旧会话 err = %v", err)
	}
	if _, err := s.AuthenticateUser("alice", "invited-password-1", base); err != nil {
		t.Fatalf("恢复后认证: %v", err)
	}
	_ = adminSpace
}

func TestTeamACLMatrix(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	base := time.Now()
	owner, ownerSpace := inviteAndRegister(t, s, admin.ID, "owner", base)
	member, _ := inviteAndRegister(t, s, admin.ID, "member", base)

	team, err := s.CreateTeam(owner.ID, "devs")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if team.Kind != SpaceTeam || team.OwnerID != owner.ID ||
		team.InternalPath != "/"+SpacesRootName+"/teams/"+teamDirName("devs", team.ID) {
		t.Fatalf("团队记录: %+v", team)
	}
	if got, err := s.ResolvePath("/" + SpacesRootName + "/teams/" + teamDirName("devs", team.ID)); err != nil || got.ID != team.RootID {
		t.Fatalf("团队根: %v %v", got, err)
	}
	// 团队名不全局唯一：同名团队独立 ID/根目录，互不可见。
	team2, err := s.CreateTeam(member.ID, "devs")
	if err != nil {
		t.Fatalf("同名团队应允许: %v", err)
	}
	if team2.ID == team.ID || team2.RootID == team.RootID || team2.OwnerID != member.ID {
		t.Fatalf("同名团队应完全独立: %+v vs %+v", team2, team)
	}
	// 非成员视角：团队对其他用户不可见不可入。
	if _, err := s.AuthorizeSpace(member.ID, team.ID, false); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("非成员访问 err = %v", err)
	}
	// 仅 owner 管理成员。
	if err := s.SetTeamMember(member.ID, team.ID, member.ID, RoleWrite); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("非owner加成员 err = %v", err)
	}
	// owner 角色不可授予；个人空间不可改成员；目标缺失/停用不可区分。
	if err := s.SetTeamMember(owner.ID, team.ID, member.ID, RoleOwner); err == nil {
		t.Fatal("owner 角色不可授予")
	}
	if err := s.SetTeamMember(owner.ID, ownerSpace.ID, member.ID, RoleRead); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("个人空间加成员 err = %v", err)
	}
	if err := s.SetTeamMember(owner.ID, team.ID, 424242, RoleRead); !errors.Is(err, ErrNotExist) {
		t.Fatalf("缺失目标 err = %v", err)
	}
	if err := s.RemoveTeamMember(owner.ID, team.ID, owner.ID); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("移除 owner err = %v", err)
	}

	// read 成员：只读。
	if err := s.SetTeamMember(owner.ID, team.ID, member.ID, RoleRead); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizeSpace(member.ID, team.ID, false); err != nil {
		t.Fatalf("read 成员读: %v", err)
	}
	if _, err := s.AuthorizeSpace(member.ID, team.ID, true); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("read 成员写 err = %v", err)
	}
	// 升级 write。
	if err := s.SetTeamMember(owner.ID, team.ID, member.ID, RoleWrite); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizeSpace(member.ID, team.ID, true); err != nil {
		t.Fatalf("write 成员写: %v", err)
	}
	// 非法角色。
	if err := s.SetTeamMember(owner.ID, team.ID, member.ID, Role("sudo")); err == nil {
		t.Fatal("非法角色应拒绝")
	}
	// 平台管理员越权访问放行（无需成员关系）。
	if _, err := s.AuthorizeSpace(admin.ID, team.ID, true); err != nil {
		t.Fatalf("管理员访问: %v", err)
	}
	// 移除成员后即时失权；重复移除幂等。
	if err := s.RemoveTeamMember(owner.ID, team.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizeSpace(member.ID, team.ID, false); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("移除后访问 err = %v", err)
	}
	if err := s.RemoveTeamMember(owner.ID, team.ID, member.ID); err != nil {
		t.Fatalf("重复移除应幂等: %v", err)
	}
	// 移除停用用户同样可行（先停用后移除）。
	bob, _ := inviteAndRegister(t, s, admin.ID, "bob", base)
	if err := s.SetTeamMember(owner.ID, team.ID, bob.ID, RoleRead); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableUser(admin.ID, bob.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTeamMember(owner.ID, team.ID, bob.ID, RoleWrite); !errors.Is(err, ErrNotExist) {
		t.Fatalf("停用目标改成员 err = %v", err)
	}
	if err := s.RemoveTeamMember(owner.ID, team.ID, bob.ID); err != nil {
		t.Fatalf("移除停用成员: %v", err)
	}
	// 列表视图。
	spaces, err := s.ListUserSpaces(owner.ID)
	if err != nil || len(spaces) != 2 {
		t.Fatalf("ListUserSpaces(owner) = %+v %v", spaces, err)
	}
	all, err := s.ListUserSpaces(admin.ID)
	if err != nil || len(all) != 6 { // admin+owner+member+bob 个人 + 两个同名团队
		t.Fatalf("ListUserSpaces(admin) len=%d %v", len(all), err)
	}
}

func TestInodeInSpaceRules(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, adminSpace := bootstrapAdmin(t, s)
	base := time.Now()
	_, aliceSpace := inviteAndRegister(t, s, admin.ID, "alice", base)

	f, err := s.CreateFile(aliceSpace.RootID, "f.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InodeInSpace(aliceSpace.ID, f.ID); err != nil {
		t.Fatalf("空间内文件: %v", err)
	}
	if err := s.InodeInSpace(aliceSpace.ID, aliceSpace.RootID); err != nil {
		t.Fatalf("空间根本身: %v", err)
	}
	// 深层子目录。
	sub, err := s.CreateDir(aliceSpace.RootID, "sub")
	if err != nil {
		t.Fatal(err)
	}
	deep, err := s.CreateFile(sub.ID, "deep.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InodeInSpace(aliceSpace.ID, deep.ID); err != nil {
		t.Fatalf("深层文件: %v", err)
	}
	// staging inode（ParentID 指向空间内）计入空间。
	st, err := s.CreateStagingFile(aliceSpace.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InodeInSpace(aliceSpace.ID, st.ID); err != nil {
		t.Fatalf("staging inode: %v", err)
	}
	// 拒绝面：fs 根、他人空间内容、缺失 inode、未知空间。
	if err := s.InodeInSpace(aliceSpace.ID, RootID); !errors.Is(err, ErrOutsideSpace) {
		t.Fatalf("fs 根 err = %v", err)
	}
	foreign, err := s.CreateFile(adminSpace.RootID, "admin-file.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InodeInSpace(aliceSpace.ID, foreign.ID); !errors.Is(err, ErrOutsideSpace) {
		t.Fatalf("跨空间 err = %v", err)
	}
	if err := s.InodeInSpace(aliceSpace.ID, 987654); !errors.Is(err, ErrNotExist) {
		t.Fatalf("缺失 inode err = %v", err)
	}
	if err := s.InodeInSpace(987654, f.ID); !errors.Is(err, ErrNotExist) {
		t.Fatalf("未知空间 err = %v", err)
	}
	// 成环的孤儿链：超深/成环按空间外拒绝。
	err = s.db.Update(func(tx *bolt.Tx) error {
		a := types.Inode{ID: 9000001, ParentID: 9000002, Name: "a", Type: types.TypeDir}
		b := types.Inode{ID: 9000002, ParentID: 9000001, Name: "b", Type: types.TypeDir}
		if err := putInode(tx, &a); err != nil {
			return err
		}
		return putInode(tx, &b)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InodeInSpace(aliceSpace.ID, 9000001); !errors.Is(err, ErrOutsideSpace) {
		t.Fatalf("成环链 err = %v", err)
	}
}

func TestObjectInSpaceAnchors(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, adminSpace := bootstrapAdmin(t, s)
	base := time.Now()
	_, aliceSpace := inviteAndRegister(t, s, admin.ID, "alice", base)

	// 旧式对象（对象 ID = 文件 ID）。
	legacy, err := s.CreateFile(aliceSpace.RootID, "legacy.bin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ObjectInSpace(aliceSpace.ID, legacy.ID); err != nil || !ok {
		t.Fatalf("旧式对象 in alice space: %v %v", ok, err)
	}
	if ok, err := s.ObjectInSpace(adminSpace.ID, legacy.ID); err != nil || ok {
		t.Fatalf("旧式对象跨空间: %v %v", ok, err)
	}
	// registry 对象：pending 小文件锚 Target.ParentID。
	var pendingID uint64
	err = s.write(func(w *txw) error {
		id, err := w.nextObjectID()
		if err != nil {
			return err
		}
		pendingID = id
		return w.putObject(ObjectRecord{ID: id, State: objectPending, Size: 4, Replicas: []uint64{1},
			Target: &SmallFileTarget{ParentID: aliceSpace.RootID, Name: "pending.bin", Size: 4}})
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ObjectInSpace(aliceSpace.ID, pendingID); err != nil || !ok {
		t.Fatalf("pending 对象: %v %v", ok, err)
	}
	if ok, err := s.ObjectInSpace(adminSpace.ID, pendingID); err != nil || ok {
		t.Fatalf("pending 对象跨空间: %v %v", ok, err)
	}
	// registry 对象：live 状态锚 FileID。
	var liveID uint64
	err = s.write(func(w *txw) error {
		id, err := w.nextObjectID()
		if err != nil {
			return err
		}
		liveID = id
		return w.putObject(ObjectRecord{ID: id, State: objectLive, FileID: legacy.ID, Size: 4})
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ObjectInSpace(aliceSpace.ID, liveID); err != nil || !ok {
		t.Fatalf("live 对象: %v %v", ok, err)
	}
	// 缺失对象。
	if _, err := s.ObjectInSpace(aliceSpace.ID, 1<<63+12345); !errors.Is(err, ErrNotExist) {
		t.Fatalf("缺失 registry 对象 err = %v", err)
	}
}

func TestSecuritySnapshotWALRecovery(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	base := time.Now()
	alice, aliceSpace := inviteAndRegister(t, s, admin.ID, "alice", base)
	// 快照前状态：管理员会话 + 团队 + alice 写成员 + 空间内文件。
	sessA1, err := s.AuthenticateUser("admin", "admin-password-123", base)
	if err != nil {
		t.Fatal(err)
	}
	team1, err := s.CreateTeam(admin.ID, "infra")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTeamMember(admin.ID, team1.ID, alice.ID, RoleWrite); err != nil {
		t.Fatal(err)
	}
	file1, err := s.CreateFile(team1.RootID, "in-team.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	var snap bytes.Buffer
	if _, err := s.Snapshot(&snap); err != nil {
		t.Fatal(err)
	}
	// 快照后的增量：新会话、第二团队、授权变更、禁用与吊销。
	sessA2, err := s.AuthenticateUser("admin", "admin-password-123", base)
	if err != nil {
		t.Fatal(err)
	}
	sessAlice, err := s.AuthenticateUser("alice", "invited-password-1", base)
	if err != nil {
		t.Fatal(err)
	}
	team2, err := s.CreateTeam(admin.ID, "research")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTeamMember(admin.ID, team2.ID, alice.ID, RoleWrite); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableUser(admin.ID, alice.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(sessA1.Token); err != nil {
		t.Fatal(err)
	}
	// 改密吊销旧会话：快照后改密使 sessA2 失效，改密后新签发的 sessA3 应随 WAL 存活。
	if err := s.ChangePassword(admin.ID, "admin-password-123", "admin-password-999"); err != nil {
		t.Fatal(err)
	}
	sessA3, err := s.AuthenticateUser("admin", "admin-password-999", base)
	if err != nil {
		t.Fatal(err)
	}

	restored, err := RestoreFromReader(filepath.Join(t.TempDir(), "restore.db"), bytes.NewReader(snap.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	baseSeq, err := restored.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	frames, err := s.FramesSince(baseSeq)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatalf("ApplyFrames: %v", err)
	}
	// 启用标记与账号。
	if enabled, err := restored.SecurityEnabled(); err != nil || !enabled {
		t.Fatalf("恢复后 SecurityEnabled = %v %v", enabled, err)
	}
	if _, err := restored.AuthenticateUser("admin", "admin-password-999", base); err != nil {
		t.Fatalf("恢复后管理员新口令: %v", err)
	}
	if _, err := restored.AuthenticateUser("admin", "admin-password-123", base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("恢复后旧口令应失效: %v", err)
	}
	if _, err := restored.AuthenticateUser("alice", "invited-password-1", base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("恢复后 alice 应仍被禁用: %v", err)
	}
	// 会话：快照前被吊销的失效；改密吊销随 WAL 恢复；改密后新会话有效；禁用者会话无效。
	if _, err := restored.UserForSession(sessA1.Token, base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("吊销会话未随 WAL 恢复: %v", err)
	}
	if _, err := restored.UserForSession(sessA2.Token, base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("改密吊销未随 WAL 恢复: %v", err)
	}
	if pub, err := restored.UserForSession(sessA3.Token, base); err != nil || pub.ID != admin.ID {
		t.Fatalf("改密后新会话丢失: %+v %v", pub, err)
	}
	if _, err := restored.UserForSession(sessAlice.Token, base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("禁用用户会话应失效: %v", err)
	}
	// 空间与 ACL：增量团队存在，成员关系与禁用状态一致。
	got, err := restored.ResolvePath("/" + SpacesRootName + "/teams/" + teamDirName("research", team2.ID))
	if err != nil || got.ID != team2.RootID {
		t.Fatalf("恢复后团队根: %v %v", got, err)
	}
	if _, err := restored.AuthorizeSpace(admin.ID, team2.ID, true); err != nil {
		t.Fatalf("恢复后授权: %v", err)
	}
	if _, err := restored.AuthorizeSpace(alice.ID, team2.ID, false); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("恢复后禁用者授权 err = %v", err)
	}
	if _, err := restored.AuthorizeSpace(alice.ID, team1.ID, false); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("快照内成员关系也受禁用约束: %v", err)
	}
	if err := restored.InodeInSpace(team1.ID, file1.ID); err != nil {
		t.Fatalf("恢复后 inode 归属: %v", err)
	}
	spaces, err := restored.ListUserSpaces(admin.ID)
	if err != nil || len(spaces) != 4 {
		t.Fatalf("恢复后 ListUserSpaces len=%d %v", len(spaces), err)
	}
	_ = aliceSpace
	// WAL 重放幂等。
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatalf("重复 ApplyFrames: %v", err)
	}
}

func TestUsernamePasswordValidation(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	base := time.Now()
	admin, _ := bootstrapAdmin(t, s)
	for _, name := range []string{"has space", "slash/x", ".", "..", strings.Repeat("a", 65)} {
		code, err := s.CreateUserInvite(admin.ID, base.Add(time.Hour), base)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.RegisterInvitedUser(code, name, "invited-password-1", base); err == nil {
			t.Fatalf("用户名 %q 应拒绝", name)
		}
	}
	for _, pw := range []string{"short12abe", strings.Repeat("x", 73)} {
		if err := validatePassword(pw); err == nil {
			t.Fatalf("口令长度 %d 应拒绝", len(pw))
		}
	}
	if err := validatePassword(strings.Repeat("x", 12)); err != nil {
		t.Fatalf("12 字节口令应通过: %v", err)
	}
	// 禁用用户列表空间也被拒。
	if _, err := s.ListUserSpaces(424242); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("未知用户列表 err = %v", err)
	}
}

func TestSessionRecordIsolation(t *testing.T) {
	// Session JSON 含 Token（一次性返回体，属预期）；UserRecord 含散列但只进存储，
	// 公开类型 Space/PublicUser 均无敏感字段。
	sj, _ := json.Marshal(Session{Token: "tok"})
	if !strings.Contains(string(sj), "tok") {
		t.Fatalf("Session 应含 Token: %s", sj)
	}
	uj, _ := json.Marshal(UserRecord{PasswordHash: "h"})
	if !strings.Contains(string(uj), "password_hash") {
		t.Fatalf("UserRecord 存储格式应含散列: %s", uj)
	}
	spcj, _ := json.Marshal(Space{})
	if strings.Contains(strings.ToLower(string(spcj)), "hash") || strings.Contains(strings.ToLower(string(spcj)), "password") {
		t.Fatalf("Space 不应携带敏感字段: %s", spcj)
	}
}

func BenchmarkAuthenticateUser(b *testing.B) {
	// 降代价仅测非 KDF 开销；bcrypt 本身代价由 golang.org/x/crypto/bcrypt 基准覆盖。
	old := passwordHashCost
	passwordHashCost = bcrypt.MinCost
	defer func() { passwordHashCost = old }()
	s, err := Open(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", now); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.AuthenticateUser("admin", "admin-password-123", now); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSecurityDisabledBeforeBootstrap(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	base := time.Now()
	enabled, err := s.SecurityEnabled()
	if err != nil || enabled {
		t.Fatalf("初始应未启用: %v %v", enabled, err)
	}
	if _, _, err := s.RegisterInvitedUser("any-code", "alice", "invited-password-1", base); !errors.Is(err, ErrSecurityDisabled) {
		t.Fatalf("未启用注册 err = %v", err)
	}
	if _, err := s.CreateTeam(1, "devs"); !errors.Is(err, ErrSecurityDisabled) {
		t.Fatalf("未启用建团队 err = %v", err)
	}
	if _, err := s.AuthenticateUser("alice", "invited-password-1", base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("未启用认证 err = %v", err)
	}
}

func TestBootstrapConflictLeavesNoPartialState(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	if _, err := s.CreateDir(RootID, SpacesRootName); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BootstrapSecurity("admin", "admin-password-123", time.Now()); !errors.Is(err, ErrSpaceRootConflict) {
		t.Fatalf("err = %v", err)
	}
	// 单事务回滚：无启用标记、无用户记录、无新 inode。
	err := s.db.View(func(tx *bolt.Tx) error {
		if enabled, err := securityEnabledTx(tx); err != nil {
			return err
		} else if enabled {
			return errors.New("启用标记泄漏")
		}
		if _, ok, err := userByNameTx(tx, "admin"); err != nil {
			return err
		} else if ok {
			return errors.New("用户记录泄漏")
		}
		if _, ok, _ := securityConfigTx(tx); ok {
			return errors.New("配置泄漏")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if in, err := s.ResolvePath("/" + SpacesRootName); err != nil || in.ID == 0 {
		t.Fatalf("冲突条目应原样保留: %v %v", in, err)
	}
}

func TestFailedSignupDoesNotConsumeInvite(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	base := time.Now()
	inviteAndRegister(t, s, admin.ID, "alice", base)
	code, err := s.CreateUserInvite(admin.ID, base.Add(time.Hour), base)
	if err != nil {
		t.Fatal(err)
	}
	// 撞名失败：邀请不得被消费。
	if _, _, err := s.RegisterInvitedUser(code, "alice", "invited-password-1", base); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("撞名 err = %v", err)
	}
	user, _, err := s.RegisterInvitedUser(code, "bob", "invited-password-1", base)
	if err != nil {
		t.Fatalf("失败尝试后邀请应仍可用: %v", err)
	}
	if user.Username != "bob" {
		t.Fatalf("注册结果: %+v", user)
	}
}

func TestConcurrentLoginsDistinctSessions(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	bootstrapAdmin(t, s)
	base := time.Now()
	const n = 4
	var wg sync.WaitGroup
	tokens := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, err := s.AuthenticateUser("admin", "admin-password-123", base)
			if err != nil {
				t.Errorf("并发登录: %v", err)
				return
			}
			tokens <- sess.Token
		}()
	}
	wg.Wait()
	close(tokens)
	seen := map[string]bool{}
	for tok := range tokens {
		if seen[tok] {
			t.Fatal("会话令牌重复")
		}
		seen[tok] = true
		if _, err := s.UserForSession(tok, base); err != nil {
			t.Fatalf("并发会话应各自有效: %v", err)
		}
	}
	if len(seen) != n {
		t.Fatalf("应签发 %d 个会话, 实得 %d", n, len(seen))
	}
}

func TestSessionExpiryBoundary(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	bootstrapAdmin(t, s)
	base := time.Now()
	sess, err := s.AuthenticateUser("admin", "admin-password-123", base)
	if err != nil {
		t.Fatal(err)
	}
	// 恰在 ExpiresAt 时刻视为过期（now < ExpiresAt 才有效）。
	if _, err := s.UserForSession(sess.Token, sess.ExpiresAt); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("边界时刻 err = %v", err)
	}
	if _, err := s.UserForSession(sess.Token, sess.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("边界前一刻应有效: %v", err)
	}
}

func TestIdempotentReplayChecksDurability(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	base := time.Now()
	member, _ := inviteAndRegister(t, s, admin.ID, "member", base)
	team, err := s.CreateTeam(admin.ID, "devs")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTeamMember(admin.ID, team.ID, member.ID, RoleRead); err != nil {
		t.Fatal(err)
	}
	// 幂等重放（同角色无帧）在集群确认不可用时不得静默放行。
	s.SetPostCommitHook(func(uint64, []byte) error { return errors.New("durability unavailable") })
	defer s.SetPostCommitHook(nil)
	if err := s.SetTeamMember(admin.ID, team.ID, member.ID, RoleRead); err == nil {
		t.Fatal("重放路径绕过了 durability 确认")
	}
	// 授权读路径同样受确认约束（在线票据应走 tx helper 自行决定确认点）。
	if _, err := s.AuthorizeSpace(member.ID, team.ID, false); err == nil {
		t.Fatal("授权读在 durability 不可用时应失败")
	}
	s.SetPostCommitHook(nil)
	if _, err := s.AuthorizeSpace(member.ID, team.ID, false); err != nil {
		t.Fatalf("恢复后授权: %v", err)
	}
}

func TestPureWALRebuildWithoutSnapshot(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, adminSpace := bootstrapAdmin(t, s)
	base := time.Now()
	alice, aliceSpace := inviteAndRegister(t, s, admin.ID, "alice", base)
	sess, err := s.AuthenticateUser("alice", "invited-password-1", base)
	if err != nil {
		t.Fatal(err)
	}
	team, err := s.CreateTeam(alice.ID, "skunkworks")
	if err != nil {
		t.Fatal(err)
	}
	file, err := s.CreateFile(team.RootID, "wip.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	// 从零库纯 WAL 重放：bcSecurity 帧经 bucketByCode 完整重建账号域。
	fresh, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	frames, err := s.FramesSince(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.ApplyFrames(frames); err != nil {
		t.Fatalf("ApplyFrames: %v", err)
	}
	if enabled, err := fresh.SecurityEnabled(); err != nil || !enabled {
		t.Fatalf("纯 WAL 重建 SecurityEnabled = %v %v", enabled, err)
	}
	if pub, err := fresh.UserForSession(sess.Token, base); err != nil || pub.ID != alice.ID {
		t.Fatalf("会话未重建: %+v %v", pub, err)
	}
	if _, err := fresh.AuthenticateUser("alice", "invited-password-1", base); err != nil {
		t.Fatalf("散列未重建: %v", err)
	}
	if err := fresh.InodeInSpace(team.ID, file.ID); err != nil {
		t.Fatalf("空间树未重建: %v", err)
	}
	if _, err := fresh.AuthorizeSpace(alice.ID, adminSpace.ID, true); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("跨空间授权应拒绝: %v", err)
	}
	_ = aliceSpace
}

func TestLegacyStagingInodeAnchoredByParent(t *testing.T) {
	securityFastHash(t)
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	base := time.Now()
	_, aliceSpace := inviteAndRegister(t, s, admin.ID, "alice", base)
	// legacy 覆盖写 staging：不占 children，但 ParentID 指向空间内——归属判定须覆盖。
	st, err := s.CreateStagingFileLegacy(aliceSpace.RootID, "overwrite.bin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InodeInSpace(aliceSpace.ID, st.ID); err != nil {
		t.Fatalf("legacy staging inode: %v", err)
	}
	// 分块 staging 的块对象按 ChunkID(stagingID, index) 反查归属。
	ck, err := s.CreateStagingFile(aliceSpace.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AssignChunk(ck.ID, 0, 1024, []uint64{1}, 0); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ObjectInSpace(aliceSpace.ID, types.ChunkID(ck.ID, 0)); err != nil || !ok {
		t.Fatalf("staging 块对象归属: %v %v", ok, err)
	}
	if ok, err := s.ObjectInSpace(999999, types.ChunkID(ck.ID, 0)); !errors.Is(err, ErrNotExist) || ok {
		t.Fatalf("未知空间: %v %v", ok, err)
	}
}
