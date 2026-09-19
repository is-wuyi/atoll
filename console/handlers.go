package console

import (
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"atoll/pkg/types"
)

// pageBase 是所有已登录页面模板共享的头部字段（导航高亮、顶栏信息）。
type pageBase struct {
	Active    string
	Title     string
	Namespace string
	Username  string
	Initial   string
	CSRF      string
	IsAdmin   bool
}

func newPageBase(active, title string, sess session) pageBase {
	initial := "?"
	if sess.Username != "" {
		initial = strings.ToUpper(sess.Username[:1])
	}
	return pageBase{
		Active: active, Title: title, Namespace: "default",
		Username: sess.Username, Initial: initial, CSRF: sess.CSRF,
		IsAdmin: sess.Role == RoleAdmin,
	}
}

// ---- 登录 / 登出 ----

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// 登录页 CSRF 用一次性随机值放进表单；提交时不强校验（未登录无会话可绑），
	// 靠 SameSite Cookie + POST 表单本身防跨站。真正的 CSRF 校验在登出等已登录写操作上。
	s.render(w, "login", map[string]any{"CSRF": randToken()})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u, ok := s.users.verify(r.FormValue("username"), r.FormValue("password"))
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, "login", map[string]any{"CSRF": randToken(), "Error": "用户名或密码错误"})
		return
	}
	sid, sess := s.sessions.create(u)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sid, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure:  r.TLS != nil,
		Expires: sess.Expires,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if ok && r.FormValue("csrf") != sess.CSRF {
		http.Error(w, "csrf mismatch", http.StatusForbidden)
		return
	}
	if ck, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.destroy(ck.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) renderError(w http.ResponseWriter, sess session, msg, detail string) {
	d := newPageBase("", "出错", sess)
	s.render(w, "error", struct {
		pageBase
		Message string
		Detail  string
	}{d, msg, detail})
}

// ---- 概览 ----

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, sess session) {
	ov, err := s.mc.overview()
	if err != nil {
		s.renderError(w, sess, "无法连接 master", err.Error())
		return
	}
	nodes, err := s.mc.nodes()
	if err != nil {
		s.renderError(w, sess, "无法读取节点列表", err.Error())
		return
	}
	s.render(w, "overview", struct {
		pageBase
		O     Overview
		Nodes []NodeView
	}{newPageBase("overview", "概览", sess), ov, nodes})
}

// ---- 节点 ----

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request, sess session) {
	nodes, err := s.mc.nodes()
	if err != nil {
		s.renderError(w, sess, "无法读取节点列表", err.Error())
		return
	}
	s.render(w, "nodes", struct {
		pageBase
		Nodes []NodeView
	}{newPageBase("nodes", "节点", sess), nodes})
}

// ---- 路线图占位页 ----

// soonTopic 描述一个尚未实现的功能分区（导航占位 + 规划说明）。
type soonTopic struct {
	Active string
	Icon   string
	Title  string
	Lead   string
	Points []string
}

var soonTopics = map[string]soonTopic{
	"users": {
		Active: "users", Icon: "◔", Title: "用户与租户",
		Lead: "多用户与独立存储空间：每个用户/租户拥有隔离的命名空间与配额。",
		Points: []string{
			"用户账号与登录（区别于当前的控制台管理账号）",
			"命名空间隔离：各租户的目录树与对象互不可见",
			"每租户容量配额与用量统计",
			"顶部命名空间切换器接入真实多租户（现恒为 default）",
		},
	},
	"smb": {
		Active: "smb", Icon: "⇄", Title: "协议网关 (SMB)",
		Lead: "对外 SMB 协议网关：让 Windows/macOS 直接挂载 atoll 为网络共享。",
		Points: []string{
			"SMB 网关服务状态与连接数",
			"共享（share）的创建与权限映射",
			"网关与后端命名空间的绑定关系",
		},
	},
	"ec": {
		Active: "ec", Icon: "▚", Title: "冗余策略 (EC)",
		Lead: "纠删码（Erasure Coding）：用更低的存储开销达到同等容错。",
		Points: []string{
			"每命名空间/文件选择副本或 EC 策略（如 4+2）",
			"块×副本矩阵扩展为 EC 分片视图（数据片/校验片）",
			"冗余策略字段已在元数据预留（现为 replica ×N）",
		},
	},
}

func (s *Server) handleSoon(topic string) func(http.ResponseWriter, *http.Request, session) {
	t := soonTopics[topic]
	return func(w http.ResponseWriter, r *http.Request, sess session) {
		base := newPageBase(t.Active, t.Title, sess)
		s.render(w, "soon", struct {
			pageBase
			SoonIcon   string
			SoonTitle  string
			SoonLead   string
			SoonPoints []string
		}{base, t.Icon, t.Title, t.Lead, t.Points})
	}
}

// ---- 完整性与修复 ----

func (s *Server) handleIntegrity(w http.ResponseWriter, r *http.Request, sess session) {
	items, err := s.mc.integrity()
	if err != nil {
		s.renderError(w, sess, "无法读取完整性信息", err.Error())
		return
	}
	snap, _ := s.mc.repairs() // 修复退避概况（失败不致命，degraded 已够看）
	s.render(w, "integrity", struct {
		pageBase
		Items       []DegradedItem
		FailStreaks int
	}{newPageBase("integrity", "完整性与修复", sess), items, snap.FailStreaks})
}

// ---- 垃圾回收 ----

func (s *Server) handleGC(w http.ResponseWriter, r *http.Request, sess session) {
	reports, err := s.mc.gc(false) // dry-run
	if err != nil {
		s.renderError(w, sess, "无法读取 GC 报告", err.Error())
		return
	}
	var totalOrphans int
	var totalBytes int64
	for _, rp := range reports {
		totalOrphans += len(rp.Orphans)
		totalBytes += rp.OrphanBytes
	}
	s.render(w, "gc", struct {
		pageBase
		Reports      []GCNodeReport
		TotalOrphans int
		TotalBytes   int64
		Executed     bool
		Deleted      int
	}{newPageBase("gc", "垃圾回收", sess), reports, totalOrphans, totalBytes, false, 0})
}

// handleGCExecute POST /gc/execute —— 执行删除。仅 admin，需 CSRF。
func (s *Server) handleGCExecute(w http.ResponseWriter, r *http.Request, sess session) {
	if sess.Role != RoleAdmin {
		s.renderError(w, sess, "权限不足", "只有 admin 角色可以执行垃圾回收删除")
		return
	}
	if r.FormValue("csrf") != sess.CSRF {
		http.Error(w, "csrf mismatch", http.StatusForbidden)
		return
	}
	reports, err := s.mc.gc(true)
	if err != nil {
		s.renderError(w, sess, "GC 执行失败", err.Error())
		return
	}
	var totalOrphans, deleted int
	var totalBytes int64
	for _, rp := range reports {
		totalOrphans += len(rp.Orphans)
		totalBytes += rp.OrphanBytes
		deleted += rp.Deleted
	}
	s.render(w, "gc", struct {
		pageBase
		Reports      []GCNodeReport
		TotalOrphans int
		TotalBytes   int64
		Executed     bool
		Deleted      int
	}{newPageBase("gc", "垃圾回收", sess), reports, totalOrphans, totalBytes, true, deleted})
}

// ---- 文件浏览 ----

type crumb struct {
	Name string
	Path string
}

// crumbs 把 "/a/b" 拆成面包屑（根 + 各级），供导航回退。
func crumbs(p string) []crumb {
	out := []crumb{{Name: "根", Path: "/"}}
	p = strings.Trim(p, "/")
	if p == "" {
		return out
	}
	acc := ""
	for _, seg := range strings.Split(p, "/") {
		acc += "/" + seg
		out = append(out, crumb{Name: seg, Path: acc})
	}
	return out
}

type fileEntry struct {
	Name     string
	Path     string
	IsDir    bool
	Chunked  bool
	Size     int64
	Replicas int
	Degraded bool
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request, sess session) {
	p := r.URL.Query().Get("path")
	if p == "" {
		p = "/"
	}
	kids, err := s.mc.children(p)
	if err != nil {
		s.renderError(w, sess, "无法读取目录", err.Error())
		return
	}
	nodes, _ := s.mc.nodes()
	alive := aliveSet(nodes)

	entries := make([]fileEntry, 0, len(kids))
	for _, k := range kids {
		e := fileEntry{Name: k.Name, Path: joinPath(p, k.Name), IsDir: k.Type == types.TypeDir, Chunked: k.Chunked, Size: k.Size}
		if !e.IsDir {
			e.Replicas, e.Degraded = redundancy(k, alive)
		}
		entries = append(entries, e)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir // 目录在前
		}
		return entries[i].Name < entries[j].Name
	})

	s.render(w, "files", struct {
		pageBase
		Crumbs  []crumb
		Entries []fileEntry
	}{newPageBase("files", "文件", sess), crumbs(p), entries})
}

// ---- 文件详情（块 × 副本矩阵） ----

type matrixCol struct {
	ID    uint64
	Addr  string
	Alive bool
	Done  bool // 仅 legacy 视图用：该节点是否已落盘
}

type matrixCell struct {
	Class string // primary|replica|syncing|missing|none
	Label string
}

type matrixRow struct {
	Index int
	Cells []matrixCell
}

func (s *Server) handleFile(w http.ResponseWriter, r *http.Request, sess session) {
	p := r.URL.Query().Get("path")
	in, reps, err := s.mc.lookup(p)
	if err != nil {
		s.renderError(w, sess, "无法读取文件", err.Error())
		return
	}
	nodes, _ := s.mc.nodes()
	alive := aliveSet(nodes)
	replicaN, degraded := redundancy(in, alive)

	data := struct {
		pageBase
		Crumbs   []crumb
		Name     string
		Inode    uint64
		Size     int64
		Chunked  bool
		ReplicaN int
		Degraded bool
		Chunks   []matrixRow
		Cols     []matrixCol
	}{
		pageBase: newPageBase("files", "文件详情", sess),
		Crumbs:   crumbs(parentPath(p)),
		Name:     baseName(p),
		Inode:    in.ID,
		Size:     in.Size,
		Chunked:  in.Chunked,
		ReplicaN: replicaN,
		Degraded: degraded,
	}

	if in.Chunked {
		data.Cols, data.Chunks = buildMatrix(in, alive)
	} else {
		doneSet := map[uint64]bool{}
		for _, id := range in.DoneReplicas {
			doneSet[id] = true
		}
		for _, id := range in.Replicas {
			addr := ""
			for _, rp := range reps {
				if rp.ID == id {
					addr = rp.Addr
				}
			}
			data.Cols = append(data.Cols, matrixCol{ID: id, Addr: addr, Alive: alive[id], Done: doneSet[id]})
		}
	}
	s.render(w, "file", data)
}

// buildMatrix 把分块文件铺成"块行 × 节点列"矩阵。
// 列 = 该文件所有块用到的节点并集（去重、按 ID 升序）；
// 格子状态：主副本已落盘 / 从副本已落盘 / 同步中(在副本集未 Done 且节点存活) / 缺失(节点宕机) / 未分配。
func buildMatrix(in types.Inode, alive map[uint64]bool) ([]matrixCol, []matrixRow) {
	nodeSet := map[uint64]bool{}
	for _, c := range in.Chunks {
		for _, id := range c.Replicas {
			nodeSet[id] = true
		}
	}
	var colIDs []uint64
	for id := range nodeSet {
		colIDs = append(colIDs, id)
	}
	sort.Slice(colIDs, func(i, j int) bool { return colIDs[i] < colIDs[j] })
	cols := make([]matrixCol, len(colIDs))
	for i, id := range colIDs {
		cols[i] = matrixCol{ID: id, Alive: alive[id]}
	}

	rows := make([]matrixRow, 0, len(in.Chunks))
	for _, c := range in.Chunks {
		inReplicas := map[uint64]bool{}
		for _, id := range c.Replicas {
			inReplicas[id] = true
		}
		doneSet := map[uint64]bool{}
		for _, id := range c.Done {
			doneSet[id] = true
		}
		primary := uint64(0)
		if len(c.Replicas) > 0 {
			primary = c.Replicas[0]
		}
		cells := make([]matrixCell, len(colIDs))
		for i, id := range colIDs {
			switch {
			case !inReplicas[id]:
				cells[i] = matrixCell{Class: "none", Label: "·"}
			case doneSet[id] && !alive[id]:
				cells[i] = matrixCell{Class: "missing", Label: "失"}
			case doneSet[id] && id == primary:
				cells[i] = matrixCell{Class: "primary", Label: "主"}
			case doneSet[id]:
				cells[i] = matrixCell{Class: "replica", Label: "副"}
			case !alive[id]:
				cells[i] = matrixCell{Class: "missing", Label: "失"}
			default:
				cells[i] = matrixCell{Class: "syncing", Label: "同"}
			}
		}
		rows = append(rows, matrixRow{Index: c.Index, Cells: cells})
	}
	return cols, rows
}

// ---- 工具 ----

func aliveSet(nodes []NodeView) map[uint64]bool {
	m := make(map[uint64]bool, len(nodes))
	for _, n := range nodes {
		m[n.ID] = n.Alive
	}
	return m
}

// redundancy 返回目标副本数与是否降级（去重的健康副本数 < 目标）。
func redundancy(in types.Inode, alive map[uint64]bool) (replicaN int, degraded bool) {
	if in.Chunked {
		for _, c := range in.Chunks {
			if len(c.Replicas) > replicaN {
				replicaN = len(c.Replicas)
			}
			if healthy(c.Done, c.Replicas, alive) < len(c.Replicas) {
				degraded = true
			}
		}
		return replicaN, degraded
	}
	replicaN = len(in.Replicas)
	if replicaN > 0 && healthy(in.DoneReplicas, in.Replicas, alive) < replicaN {
		degraded = true
	}
	return replicaN, degraded
}

// healthy 统计 done 中"节点存活 ∧ 在副本集 ∧ 去重"的数量。
func healthy(done, replicas []uint64, alive map[uint64]bool) int {
	rset := map[uint64]bool{}
	for _, id := range replicas {
		rset[id] = true
	}
	seen := map[uint64]bool{}
	n := 0
	for _, id := range done {
		if alive[id] && rset[id] && !seen[id] {
			seen[id] = true
			n++
		}
	}
	return n
}

func joinPath(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return strings.TrimRight(dir, "/") + "/" + name
}

func parentPath(p string) string {
	d := path.Dir(strings.TrimRight(p, "/"))
	if d == "." || d == "" {
		return "/"
	}
	return d
}

func baseName(p string) string {
	b := path.Base(strings.TrimRight(p, "/"))
	if b == "." || b == "/" {
		return "/"
	}
	return b
}

var _ = time.Now // 预留：后续页面会用到时间格式化
