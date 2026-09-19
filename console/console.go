package console

import (
	"crypto/tls"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"time"

	"atoll/pkg/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Config 配置一个控制台实例。
type Config struct {
	MasterURL  string
	Token      auth.Token  // 集群 token（读 /admin/*、/meta 等）
	AdminToken auth.Token  // 破坏性操作 token（GC）；空则回退 Token
	TLS        *tls.Config // 出站到 master 的 TLS（nil = http）
	DataDir    string      // 控制台用户/状态目录
	SessionTTL time.Duration
}

// Server 是控制台的 HTTP 服务。
type Server struct {
	cfg      Config
	mc       *masterClient
	users    *userStore
	sessions *sessionStore
	tpl      *template.Template
}

func New(cfg Config) (*Server, error) {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	users, err := openUserStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	tpl, err := template.New("").Funcs(tplFuncs()).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Server{
		cfg:      cfg,
		mc:       newMasterClient(cfg.MasterURL, cfg.Token, cfg.AdminToken, cfg.TLS),
		users:    users,
		sessions: newSessionStore(cfg.SessionTTL),
		tpl:      tpl,
	}, nil
}

// Users 暴露用户存储，供 CLI 的 useradd 用。
func (s *Server) Users() *userStore { return s.users }

// Handler 返回全部路由。静态资源公开，其余需登录会话。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)

	mux.HandleFunc("GET /", s.requireAuth(s.handleOverview))
	mux.HandleFunc("GET /nodes", s.requireAuth(s.handleNodes))
	mux.HandleFunc("GET /files", s.requireAuth(s.handleFiles))
	mux.HandleFunc("GET /file", s.requireAuth(s.handleFile))
	mux.HandleFunc("GET /integrity", s.requireAuth(s.handleIntegrity))
	mux.HandleFunc("GET /gc", s.requireAuth(s.handleGC))
	mux.HandleFunc("POST /gc/execute", s.requireAuth(s.handleGCExecute))

	return securityHeaders(mux)
}

// requireAuth 包装需要登录的处理器。无有效会话 → 重定向登录页。
func (s *Server) requireAuth(h func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.currentSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r, sess)
	}
}

// securityHeaders 加基本安全头。CSP 收到同源——我们不引任何 CDN 脚本/样式。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// render 执行命名模板到响应；出错记日志并回 500。
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func tplFuncs() template.FuncMap {
	return template.FuncMap{
		"bytes":    humanBytes,
		"since":    humanSince,
		"pct":      pctFloat,
		"sub":      func(a, b int) int { return a - b },
		"barClass": barClass,
		"dur":      humanDur,
	}
}

// humanDur 把秒数转成中文时长（降级时长展示用）。
func humanDur(sec int64) string {
	switch {
	case sec < 60:
		return fmt.Sprintf("%d 秒", sec)
	case sec < 3600:
		return fmt.Sprintf("%d 分 %d 秒", sec/60, sec%60)
	default:
		return fmt.Sprintf("%d 小时 %d 分", sec/3600, (sec%3600)/60)
	}
}

// humanBytes 人类可读字节数。
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanSince(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < 2*time.Second:
		return "刚刚"
	case d < time.Minute:
		return fmt.Sprintf("%d 秒前", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	}
}

// pctFloat 返回 0–100 百分比（float64，供 barClass 与宽度共用一种类型）。
func pctFloat(used, total int64) float64 {
	if total <= 0 {
		return 0
	}
	p := float64(used) / float64(total) * 100
	if p > 100 {
		p = 100
	}
	return p
}

// barClass 按占用率返回容量条配色档。
func barClass(pct float64) string {
	switch {
	case pct >= 90:
		return "bad"
	case pct >= 75:
		return "warn"
	default:
		return ""
	}
}
