// atoll 是一个分布式文件存储系统（项目名：环礁）。
// 单一二进制包含三种角色：master（中心服务器）、node（存储节点），
// CLI 客户端命令 put/get/ls/mkdir/rm，以及 FUSE 挂载命令 mount。
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"atoll/client"
	"atoll/console"
	"atoll/master"
	"atoll/mount"
	"atoll/node"
	"atoll/pkg/auth"
	"atoll/pkg/keyfile"
	"atoll/pkg/types"
)

const usageText = `usage: atoll <command> [args]

服务角色:
  atoll master   启动中心服务器（元数据 + 副本调度）
                 [-write-planning 启用调度器计划写入；启用后重启须保留开关]
                 [-secure 启用安全模式：强制 TLS 证书且拒绝 -tls-skip-verify、
                 控制凭据读 -control-token-env（默认 ATOLL_CONTROL_TOKEN，≥24 字符）、
                 拒绝 -seeds 远程备份（安全模式仅本地库备份）；库未引导须先 auth init]
  atoll node     启动存储节点（对象存储 + 心跳）
                 [-secure 启用节点独立身份：首次入网需设备邀请码环境变量
                 -invite-env（默认 ATOLL_NODE_INVITE），强制 TLS；此后同一身份静默续期]

安全账号 (auth init 为离线引导；其余经 master；密码默认读 ATOLL_PASSWORD):
  atoll auth init -user <名>        引导安全库：创建首位平台管理员与个人空间
                                    （master 停止时执行，-db 指定库文件）
  atoll login -user <名>            登录，输出会话 token（24 小时有效）
  atoll logout                      登出并吊销当前会话
  atoll spaces                      列出个人与团队空间
  atoll team-create <名称>          创建团队空间
  atoll team-member -space <ID> <用户ID> read|write|remove
                                    团队 owner 增改/移除成员

客户端命令 (可用 -master 或环境变量 ATOLL_MASTER 指定 master 地址):
  atoll put <本地文件> <远程路径>    上传文件 [-replicas N] [-min-copies N] [-f]
                                    计划模式由调度器选择布局和确认；旧参数仅兼容旧 Master
                                    非空小文件直传节点；旧模式使用小文件代理通道
                                    单文件上限 16 GiB（256 × 64MiB 块）
  atoll get <远程路径> <本地文件>    下载文件（自动兼容分块/整文件格式）
  atoll ls  <远程路径>              列目录
  atoll protection <远程路径> [performance|normal|security|inherit]
                                    查询或设置目录/文件的新写保护偏好（档位仅为优化权重）
  atoll mkdir <远程路径>            建目录
  atoll rm  <远程路径>              删除文件/空目录（立即生效，无回收站）
  atoll mount <挂载点>              FUSE 挂载为本地目录 [-cache 缓冲目录 -replicas N]
  atoll gc [--execute]              垃圾回收（dry-run 默认；--execute 执行删除）
	atoll auth gen                    生成随机集群认证 token
	atoll content-key-init -path FILE  创建受保护的内容 KEK 文件（不写数据库/WAL）
	atoll keypack export|import        内容密钥恢复包离线导出/导入（与 KEK 分开保管）

认证与空间选择:
  兼容模式（默认）：全部角色支持 -token 或 ATOLL_TOKEN（集群各组件须一致；
    不设置时不校验也不注入）。
  安全模式：客户端命令与 mount 支持 -session-env（默认 ATOLL_SESSION）携带登录
    会话、-space 或 ATOLL_SPACE 选择个人/团队空间 ID；设置了会话时静态 token
    不再使用——会话只发 master，直连节点的读写自动换取短期票据并由节点逐请求
    在线核验（登出/禁用/移除成员对下一请求立即生效；内核页缓存与已开始请求除外）。
  设备入网邀请码经 ATOLL_NODE_INVITE 传给 node -secure；邀请码由平台管理员经
    HTTP 接口创建（详见 SECURITY.md）。`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "master":
		return runMaster(rest, stderr)
	case "node":
		return runNode(rest, stderr)
	case "mount":
		return runMount(rest, stderr)
	case "put", "get", "ls", "mkdir", "rm", "protection":
		return runClientCmd(cmd, rest, stdout, stderr)
	case "gc":
		return runGC(rest, stdout, stderr)
	case "console":
		return runConsole(rest, stdout, stderr)
	case "auth":
		return runAuth(rest, stdout, stderr)
	case "content-key-init":
		return runContentKeyInit(rest, stdout, stderr)
	case "keypack":
		return runKeyPack(rest, stdout, stderr)
	case "login", "logout", "spaces", "team-create", "team-member":
		return runUserSecurity(cmd, rest, stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usageText)
		return 0
	default:
		fmt.Fprintf(stderr, "atoll: unknown command %q\n\n%s\n", cmd, usageText)
		return 2
	}
}

// ---- auth ----

func runAuth(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "init" {
		return runSecurityBootstrap(args[1:], stdout, stderr)
	}
	if len(args) != 1 || args[0] != "gen" {
		fmt.Fprintln(stderr, "用法: atoll auth gen")
		return 2
	}
	tok, err := auth.Generate()
	if err != nil {
		fmt.Fprintf(stderr, "生成失败: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, tok)
	return 0
}

// ---- master ----

func runMaster(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("master", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":9420", "监听地址")
	dbPath := fs.String("db", "atoll.db", "元数据 bbolt 文件路径")
	nodeMaxAge := fs.Duration("node-max-age", 30*time.Second, "节点心跳超时阈值")
	repairIntv := fs.Duration("repair-interval", 15*time.Second, "副本修复扫描周期")
	gcIntv := fs.Duration("gc-interval", 10*time.Minute, "GC 对账扫描周期")
	autonomyMode := fs.String("autonomy", "off", "自治保护：off|observe|shadow|add（add 仅增加副本）")
	secure := fs.Bool("secure", false, "启用受邀账号、空间与节点独立身份")
	allowInsecure := fs.Bool("allow-insecure", false, "仅供隔离测试：允许安全模式使用明文 HTTP")
	controlEnv := fs.String("control-token-env", "ATOLL_CONTROL_TOKEN", "Master 私有控制凭据环境变量")
	autonomyInterval := fs.Duration("autonomy-interval", time.Minute, "自治观测与决策周期")
	autonomyBytes := fs.Int64("autonomy-bytes-per-round", 256<<20, "每轮增加副本的字节预算")
	autonomyReplicas := fs.Int("autonomy-max-replicas", 8, "自治副本候选上限，不是固定副本数")
	writePlanning := fs.Bool("write-planning", false, "由调度器规划新写入（启用状态持久化，重启须保留此开关）")
	writeReplicas := fs.Int("write-max-replicas", 8, "新写入复制布局搜索上限，不是固定副本数")
	contentKeyFile := fs.String("content-key-file", "", "secure 内容主密钥文件（加密对象功能启用时必需；不进入数据库/WAL）")
	token := fs.String("token", envDefault("ATOLL_TOKEN", ""), "集群认证 token（空 = 兼容模式不校验）")
	adminToken := fs.String("admin-token", envDefault("ATOLL_ADMIN_TOKEN", ""), "破坏性操作(/admin/gc)专用 token（空 = 回退用集群 token）")
	tlsCert := fs.String("tls-cert", "", "TLS 证书文件（配 -tls-key 后 master 走 https）")
	tlsKey := fs.String("tls-key", "", "TLS 私钥文件")
	tlsCA := fs.String("tls-ca", "", "校验节点证书用的 CA（出站到节点走 https 时）")
	tlsSkip := fs.Bool("tls-skip-verify", false, "跳过节点证书校验（自签名内网）")
	seedsFlag := fs.String("seeds", "", "元数据灾备种子节点地址（逗号分隔 host:port；配置后启用元数据备份进集群）")
	recoverFrom := fs.String("recover-from", "auto", "元数据恢复模式：auto|local|cluster（歧义时 auto 硬停等人工裁决）")
	backupIntv := fs.Duration("meta-backup-interval", 10*time.Minute, "元数据全量快照备份周期")
	backupReplicas := fs.Int("meta-backup-replicas", 3, "元数据快照/WAL 每块副本数上限 K")
	backupRetention := fs.Int("meta-backup-retention", 3, "保留最近 N 个元数据快照版本")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	outTLS, err := clientTLS(*tlsCA, *tlsSkip)
	if err != nil {
		fmt.Fprintf(stderr, "atoll master: %v\n", err)
		return 1
	}
	seeds := splitSeeds(*seedsFlag)
	if *secure && !*allowInsecure && (*tlsCert == "" || *tlsKey == "" || *tlsSkip) {
		fmt.Fprintln(stderr, "secure master requires TLS certificates and certificate verification")
		return 1
	}
	if *secure && len(os.Getenv(*controlEnv)) < 24 {
		fmt.Fprintln(stderr, "secure master requires a private control token of at least 24 characters")
		return 1
	}
	if *secure && len(seeds) > 0 {
		fmt.Fprintln(stderr, "secure recovery from node backups is not enabled yet; use a local database backup")
		return 1
	}

	// 元数据备份器：既做恢复决策，也跑后台备份循环。
	backup := master.NewMetaBackup(nil, *nodeMaxAge, master.MetaBackupConfig{
		Replicas: *backupReplicas, Retention: *backupRetention, Interval: *backupIntv,
	})
	backup.SetToken(auth.Token(*token))
	backup.SetTLS(outTLS)

	// 恢复决策（fail-stop）：本地 vs 集群，歧义硬停。未配种子则退化为直接打开本地库。
	store, err := backup.Recover(*dbPath, seeds, master.RecoverMode(*recoverFrom))
	if err != nil {
		fmt.Fprintf(stderr, "atoll master: %v\n", err)
		return 1
	}
	enabled, err := store.SecurityEnabled()
	if err != nil || enabled != *secure {
		store.Close()
		fmt.Fprintln(stderr, "security mode must match the database bootstrap state; use auth init before secure startup")
		return 1
	}
	if initialized, err := store.WritePlanningEnabled(); err != nil || (initialized && !*writePlanning) {
		store.Close()
		fmt.Fprintln(stderr, "write planning database requires -write-planning and intact configuration")
		return 1
	}
	backup.SetStore(store)
	backup.InstallSyncHook() // 同步旋钮：开启时写元数据 ack 前先落集群（钩子内按配置决定）

	var autonomy *master.Autonomy
	if *autonomyMode != "off" {
		autonomy, err = master.NewAutonomy(store, *nodeMaxAge, master.AutonomyConfig{
			Mode: *autonomyMode, Interval: *autonomyInterval, MaxBytesPerRound: *autonomyBytes, MaxReplicas: *autonomyReplicas,
		})
		if err != nil {
			store.Close()
			fmt.Fprintf(stderr, "atoll master: %v\n", err)
			return 1
		}
		autonomy.SetTransport(auth.Token(*token), outTLS)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	scanner := master.NewScanner(store, *nodeMaxAge, *repairIntv, *gcIntv)
	scanner.SetToken(auth.Token(*token))
	scanner.SetTLS(outTLS)
	scanner.SetAdditiveOnly(*autonomyMode == master.AutonomyAdd)
	// Transport configuration must precede every background worker.
	// 配了种子才跑备份循环（否则退化为纯本地，无灾备）。
	if len(seeds) > 0 {
		backup.StartLoop(ctx, 0) // walIntv=0 → 内部取 Interval/5
		log.Printf("元数据备份进集群已启用：种子 %v，快照周期 %v，K=%d", seeds, *backupIntv, *backupReplicas)
	}
	// 关闭顺序：等扫描器 + 备份 goroutine 全部退出后再关 store，避免关库时仍在读写。
	defer func() {
		cancel()
		scanner.Wait()
		backup.Wait()
		if autonomy != nil {
			autonomy.Wait()
		}
		store.Close()
	}()

	srv := master.NewServer(store, *nodeMaxAge)
	srv.SetScanner(scanner)
	srv.SetMetaBackup(backup)
	srv.SetToken(auth.Token(*token))
	srv.SetAdminToken(auth.Token(*adminToken))
	srv.SetTLS(outTLS)
	if *secure {
		if *contentKeyFile != "" {
			kek, keyErr := keyfile.Load(*contentKeyFile)
			if keyErr != nil {
				store.Close()
				fmt.Fprintln(stderr, "secure master content key file:", keyErr)
				return 1
			}
			srv.SetContentKEK(kek)
		}
		if err := srv.EnableSecurity(master.SecurityConfig{ControlToken: auth.Token(os.Getenv(*controlEnv)), AllowInsecure: *allowInsecure}); err != nil {
			fmt.Fprintln(stderr, "secure master:", err)
			return 1
		}
	} else if *contentKeyFile != "" {
		store.Close()
		fmt.Fprintln(stderr, "content key file requires -secure")
		return 1
	}
	if *writePlanning {
		if err := srv.EnableWritePlanning(master.WritePlanningConfig{MaxReplicas: *writeReplicas}); err != nil {
			fmt.Fprintln(stderr, "write planning:", err)
			return 1
		}
	}
	if autonomy != nil {
		srv.SetAutonomy(autonomy)
	}
	if *secure {
		srv.AttachSecureTransports()
		srv.StartSecurity(ctx)
		defer func() { cancel(); srv.WaitSecurity() }()
	}
	scanner.Start(ctx)
	if autonomy != nil {
		autonomy.Start(ctx)
		log.Printf("autonomy mode=%s interval=%s (add-only, EC disabled)", *autonomyMode, *autonomyInterval)
	}
	httpSrv := &http.Server{Addr: *listen, Handler: srv.Handler()}
	go func() {
		<-ctx.Done() // SIGTERM/SIGINT：NotifyContext 拦截了默认终止行为，必须显式退出
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
	}()
	serveErr := serve(httpSrv, *tlsCert, *tlsKey, stderr, fmt.Sprintf("atoll master listening on %s (db=%s)", *listen, *dbPath))
	if serveErr != nil {
		fmt.Fprintf(stderr, "atoll master: %v\n", serveErr)
		return 1
	}
	return 0
}

// serve 启动 HTTP 或 HTTPS 服务：cert+key 都非空则 ListenAndServeTLS。
// 返回非 ErrServerClosed 的错误；正常关闭返回 nil。
func serve(srv *http.Server, certFile, keyFile string, stderr io.Writer, banner string) error {
	var err error
	if certFile != "" && keyFile != "" {
		log.Printf("%s [TLS]", banner)
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		log.Printf("%s", banner)
		err = srv.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// ---- node ----

func runNode(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("node", flag.ContinueOnError)
	fs.SetOutput(stderr)
	masterURL := fs.String("master", envDefault("ATOLL_MASTER", "http://127.0.0.1:9420"), "master 地址")
	listen := fs.String("listen", ":9421", "监听地址")
	advertise := fs.String("advertise", "", "注册到 master 供客户端直连的地址；跨机部署必须显式指定（如 203.0.113.5:9421）")
	dataDir := fs.String("data-dir", "./node-data", "对象存储目录")
	secureNode := fs.Bool("secure", false, "启用节点独立身份与访问票据")
	identityPath := fs.String("identity", "", "节点私钥文件（默认 data-dir/identity.key）")
	inviteEnv := fs.String("invite-env", "ATOLL_NODE_INVITE", "节点加入邀请码环境变量")
	allowInsecureNode := fs.Bool("allow-insecure", false, "仅供隔离测试：允许明文或跳过证书验证")
	totalBytes := fs.Int64("total-bytes", 100<<30, "声明容量（字节）")
	token := fs.String("token", envDefault("ATOLL_TOKEN", ""), "集群认证 token（空 = 兼容模式不校验）")
	tlsCert := fs.String("tls-cert", "", "TLS 证书文件（配 -tls-key 后 node 走 https）")
	tlsKey := fs.String("tls-key", "", "TLS 私钥文件")
	tlsCA := fs.String("tls-ca", "", "校验 master/对等节点证书用的 CA")
	tlsSkip := fs.Bool("tls-skip-verify", false, "跳过证书校验（自签名内网）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	outTLS, err := clientTLS(*tlsCA, *tlsSkip)
	if err != nil {
		fmt.Fprintf(stderr, "atoll node: %v\n", err)
		return 1
	}
	adv := *advertise
	if adv == "" {
		if strings.HasPrefix(*listen, ":") {
			adv = "127.0.0.1" + *listen // ":9421" → "127.0.0.1:9421"，仅本机测试场景够用
		} else {
			adv = *listen
		}
	}
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "atoll node: %v\n", err)
		return 1
	}
	n := node.New(*dataDir, *masterURL, adv, *totalBytes)
	n.SetToken(auth.Token(*token))
	n.SetTLS(outTLS)
	if *secureNode {
		if !*allowInsecureNode && (*tlsCert == "" || *tlsKey == "" || *tlsSkip) {
			fmt.Fprintln(stderr, "secure node requires TLS certificates and certificate verification")
			return 1
		}
		keyPath := *identityPath
		if keyPath == "" {
			keyPath = filepath.Join(*dataDir, "identity.key")
		}
		if err := n.EnableSecurity(keyPath, os.Getenv(*inviteEnv), *allowInsecureNode); err != nil {
			fmt.Fprintln(stderr, "secure node:", err)
			return 1
		}
	}
	if err := n.InitUsedBytes(); err != nil {
		fmt.Fprintf(stderr, "atoll node: %v\n", err)
		return 1
	}
	if err := n.Register(); err != nil {
		fmt.Fprintf(stderr, "atoll node: 注册 master 失败: %v\n", err)
		return 1
	}
	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           n.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
	}()
	if err := serve(httpSrv, *tlsCert, *tlsKey, stderr, fmt.Sprintf("atoll node listening on %s (data=%s)", *listen, *dataDir)); err != nil {
		fmt.Fprintf(stderr, "atoll node: %v\n", err)
		return 1
	}
	return 0
}

// ---- FUSE 挂载 ----

func runMount(args []string, stderr io.Writer) int {
	fset := flag.NewFlagSet("mount", flag.ContinueOnError)
	fset.SetOutput(stderr)
	masterURL := fset.String("master", envDefault("ATOLL_MASTER", "http://127.0.0.1:9420"), "master 地址")
	replicas := fset.Int("replicas", 2, "新写入文件的副本数")
	cacheDir := fset.String("cache", filepath.Join(os.TempDir(), "atoll-cache"), "写缓冲临时目录")
	debug := fset.Bool("debug", false, "输出 FUSE 调试日志")
	token := fset.String("token", envDefault("ATOLL_TOKEN", ""), "集群认证 token")
	sessionEnv := fset.String("session-env", "ATOLL_SESSION", "安全用户会话环境变量")
	space := fset.Uint64("space", securitySpaceEnv(), "安全用户空间 ID")
	allowInsecure := fset.Bool("allow-insecure", false, "仅供隔离测试：允许安全会话明文 HTTP")
	tlsCA := fset.String("tls-ca", "", "校验服务端证书用的 CA（master 走 https 时）")
	tlsSkip := fset.Bool("tls-skip-verify", false, "跳过证书校验（自签名内网）")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if fset.NArg() != 1 {
		fmt.Fprintln(stderr, "用法: atoll mount [-cache 目录] <挂载点>")
		return 2
	}
	tlsCfg, err := clientTLS(*tlsCA, *tlsSkip)
	if err != nil {
		fmt.Fprintf(stderr, "atoll mount: %v\n", err)
		return 1
	}
	mountPoint := fset.Arg(0)
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		fmt.Fprintf(stderr, "atoll mount: %v\n", err)
		return 1
	}

	c, err := configuredClient(*masterURL, auth.Token(*token), tlsCfg, os.Getenv(*sessionEnv), *space, *allowInsecure)
	if err != nil {
		fmt.Fprintln(stderr, "atoll mount:", err)
		return 1
	}
	m, err := mount.NewWithTLS(c, *cacheDir, *replicas, auth.Token(*token), tlsCfg)
	if err != nil {
		fmt.Fprintf(stderr, "atoll mount: %v\n", err)
		return 1
	}
	// 内核缓存：master 短暂不可达时避免每个路径访问都实时打 master
	// （无缓存 + 网络失败 → ENOENT → 内核立即重试的热循环曾致 90% CPU 空转）。
	// 正存在缓存 1s；负缓存（不存在的路径）1s 防止扫描类负载打爆 master。
	entryT, attrT, negT := 1*time.Second, 1*time.Second, 3*time.Second
	mountOpts := fuse.MountOptions{Name: "atoll", Debug: *debug}
	if runtime.GOOS == "darwin" {
		// macFUSE 默认 daemon_timeout=60s：任一 FUSE 操作（跨公网慢上传的 Write/Flush）
		// 超 60s 未返回，内核就判进程失联、驱逐挂载 → Finder「设备已消失」。网络文件
		// 系统本就慢，调大到 600s 让内核有耐心（sshfs 等同样做法）。
		mountOpts.Options = append(mountOpts.Options, "daemon_timeout=600")
		// noappledouble：让内核别再对每个文件探测 ._xxx AppleDouble 伴随文件。跨公网下
		// 这些注定 ENOENT 的探测每文件好几趟 /meta 往返，是小文件奇慢的一大来源。
		mountOpts.Options = append(mountOpts.Options, "noappledouble")
	}
	server, err := fs.Mount(mountPoint, m.Root(), &fs.Options{
		MountOptions:    mountOpts,
		EntryTimeout:    &entryT,
		AttrTimeout:     &attrT,
		NegativeTimeout: &negT,
	})
	if err != nil {
		fmt.Fprintf(stderr, "atoll mount: %v\n", err)
		return 1
	}

	// Ctrl-C / SIGTERM 时卸载退出。
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	fmt.Fprintf(stderr, "atoll 已挂载到 %s（Ctrl-C 卸载）\n", mountPoint)
	go func() {
		<-sig
		server.Unmount()
	}()
	server.Wait()
	return 0
}

// ---- 客户端命令 ----

func runClientCmd(cmd string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	masterURL := fs.String("master", envDefault("ATOLL_MASTER", "http://127.0.0.1:9420"), "master 地址")
	replicas := fs.Int("replicas", 2, "兼容模式副本数（计划模式由调度器决定）")
	minCopies := fs.Int("min-copies", 0, "兼容模式提交确认下限（计划模式不采用此参数）")
	force := fs.Bool("f", false, "强制覆盖远程已存在的同名文件（仅 put 使用）")
	sessionEnv := fs.String("session-env", "ATOLL_SESSION", "安全用户会话环境变量")
	space := fs.Uint64("space", securitySpaceEnv(), "安全用户空间 ID")
	allowInsecure := fs.Bool("allow-insecure", false, "仅供隔离测试：允许安全会话明文 HTTP")
	token := fs.String("token", envDefault("ATOLL_TOKEN", ""), "集群认证 token")
	tlsCA := fs.String("tls-ca", "", "校验服务端证书用的 CA（master 走 https 时）")
	tlsSkip := fs.Bool("tls-skip-verify", false, "跳过证书校验（自签名内网）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	tlsCfg, err := clientTLS(*tlsCA, *tlsSkip)
	if err != nil {
		fmt.Fprintf(stderr, "atoll %s: %v\n", cmd, err)
		return 1
	}
	c, err := configuredClient(*masterURL, auth.Token(*token), tlsCfg, os.Getenv(*sessionEnv), *space, *allowInsecure)
	if err != nil {
		fmt.Fprintln(stderr, "atoll client:", err)
		return 1
	}

	switch cmd {
	case "put":
		if fs.NArg() != 2 {
			fmt.Fprintln(stderr, "用法: atoll put [-replicas N] [-min-copies N] [-f] <本地文件> <远程路径>")
			return 2
		}
		// 上传路由：≤ SmallFileMax 且未显式要求 min-copies>1 → 小文件单请求通道
		//（1 次往返，master 服务端写节点+提交）；大文件 → 64MB 块流水线；
		// 空文件 → legacy 单对象路径。
		st, statErr := os.Stat(fs.Arg(0))
		if statErr != nil {
			fmt.Fprintf(stderr, "put 失败: %v\n", statErr)
			return 1
		}
		var err error
		if st.Size() > 0 && st.Size() <= types.SmallFileMax && *minCopies <= 1 {
			data, rerr := os.ReadFile(fs.Arg(0))
			if rerr != nil {
				fmt.Fprintf(stderr, "put 失败: %v\n", rerr)
				return 1
			}
			_, err = c.PutSmall(fs.Arg(1), data, *replicas, *force)
		} else if st.Size() > 0 {
			err = c.PutChunkedWithMinCopies(fs.Arg(0), fs.Arg(1), *replicas, *minCopies, *force)
		} else {
			if *force {
				err = c.PutOverwrite(fs.Arg(0), fs.Arg(1), *replicas, true)
			} else {
				err = c.Put(fs.Arg(0), fs.Arg(1), *replicas)
			}
		}
		if err != nil {
			fmt.Fprintf(stderr, "put 失败: %v\n", err)
			return 1
		}
		action := "已上传"
		if *force {
			action = "已覆盖"
		}
		if planned, err := c.WritePlanning(context.Background()); err == nil && planned {
			fmt.Fprintf(stdout, "%s %s → %s（调度器确认条件已满足，%s）\n", action, fs.Arg(0), fs.Arg(1), humanSize(st.Size()))
		} else {
			fmt.Fprintf(stdout, "%s %s → %s（%d 副本，%s）\n", action, fs.Arg(0), fs.Arg(1), *replicas, humanSize(st.Size()))
		}
	case "protection":
		if fs.NArg() < 1 || fs.NArg() > 2 {
			fmt.Fprintln(stderr, "用法: atoll protection <远程路径> [performance|normal|security|inherit]")
			return 2
		}
		var policy types.ProtectionResponse
		var err error
		if fs.NArg() == 2 {
			tier := types.ProtectionTier(fs.Arg(1))
			if tier == "inherit" {
				tier = ""
			}
			policy, err = c.SetProtection(fs.Arg(0), tier)
		} else {
			policy, err = c.GetProtection(fs.Arg(0))
		}
		if err != nil {
			fmt.Fprintln(stderr, "protection 失败:", err)
			return 1
		}
		fmt.Fprintf(stdout, "%s: %s（来源 inode %d，策略版本 %d；仅影响新写入的优化权重）\n", fs.Arg(0), policy.Policy.Tier, policy.Policy.SourceInodeID, policy.Policy.Revision)
	case "get":
		if fs.NArg() != 2 {
			fmt.Fprintln(stderr, "用法: atoll get <远程路径> <本地文件>")
			return 2
		}
		if err := c.Get(fs.Arg(0), fs.Arg(1)); err != nil {
			fmt.Fprintf(stderr, "get 失败: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "已下载 %s → %s\n", fs.Arg(0), fs.Arg(1))
	case "ls":
		if fs.NArg() != 1 {
			fmt.Fprintln(stderr, "用法: atoll ls <远程路径>")
			return 2
		}
		kids, err := c.Ls(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(stderr, "ls 失败: %v\n", err)
			return 1
		}
		for _, k := range kids {
			tag := "d"
			if k.Type == 1 {
				tag = fmt.Sprintf("%dB", k.Size)
			}
			fmt.Fprintf(stdout, "%-12s %s\n", tag, k.Name)
		}
	case "mkdir":
		if fs.NArg() != 1 {
			fmt.Fprintln(stderr, "用法: atoll mkdir <远程路径>")
			return 2
		}
		if _, err := c.Mkdir(fs.Arg(0)); err != nil {
			fmt.Fprintf(stderr, "mkdir 失败: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "已创建目录 %s\n", fs.Arg(0))
	case "rm":
		if fs.NArg() != 1 {
			fmt.Fprintln(stderr, "用法: atoll rm <远程路径>")
			return 2
		}
		if err := c.Rm(fs.Arg(0)); err != nil {
			fmt.Fprintf(stderr, "rm 失败: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "已删除 %s\n", fs.Arg(0))
	}
	return 0
}

// ---- 管理后台 console ----

func runConsole(args []string, stdout, stderr io.Writer) int {
	// 子子命令：atoll console useradd <user> — 引导控制台账号。
	if len(args) > 0 && args[0] == "useradd" {
		return runConsoleUserAdd(args[1:], stdout, stderr)
	}
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":9430", "监听地址")
	masterURL := fs.String("master", envDefault("ATOLL_MASTER", "http://127.0.0.1:9420"), "master 地址")
	dataDir := fs.String("data-dir", "./console-data", "控制台用户/会话状态目录")
	token := fs.String("token", envDefault("ATOLL_TOKEN", ""), "集群认证 token")
	adminToken := fs.String("admin-token", envDefault("ATOLL_ADMIN_TOKEN", ""), "破坏性操作专用 token（空则回退集群 token）")
	tlsCert := fs.String("tls-cert", "", "TLS 证书文件（配 -tls-key 后 console 走 https）")
	tlsKey := fs.String("tls-key", "", "TLS 私钥文件")
	tlsCA := fs.String("tls-ca", "", "校验 master 证书用的 CA（master 走 https 时）")
	tlsSkip := fs.Bool("tls-skip-verify", false, "跳过 master 证书校验（自签名内网）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	outTLS, err := clientTLS(*tlsCA, *tlsSkip)
	if err != nil {
		fmt.Fprintf(stderr, "atoll console: %v\n", err)
		return 1
	}
	srv, err := console.New(console.Config{
		MasterURL:  *masterURL,
		Token:      auth.Token(*token),
		AdminToken: auth.Token(*adminToken),
		TLS:        outTLS,
		DataDir:    *dataDir,
	})
	if err != nil {
		fmt.Fprintf(stderr, "atoll console: %v\n", err)
		return 1
	}
	if srv.Users().Count() == 0 {
		fmt.Fprintln(stderr, "提示：还没有控制台账号，先运行 `atoll console useradd <用户名> -data-dir "+*dataDir+"` 创建管理员。")
	}
	httpSrv := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
	}()
	if err := serve(httpSrv, *tlsCert, *tlsKey, stderr, fmt.Sprintf("atoll console listening on %s (master=%s)", *listen, *masterURL)); err != nil {
		fmt.Fprintf(stderr, "atoll console: %v\n", err)
		return 1
	}
	return 0
}

// runConsoleUserAdd 创建/引导一个控制台账号。密码从 ATOLL_CONSOLE_PASSWORD 读，
// 避免明文进 shell 历史。默认角色 admin（首个账号通常是管理员）。
func runConsoleUserAdd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("console useradd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "./console-data", "控制台状态目录")
	role := fs.String("role", "admin", "角色：admin | readonly")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法: atoll console useradd <用户名> [-role admin|readonly]（密码经 ATOLL_CONSOLE_PASSWORD 传入）")
		return 2
	}
	pw := os.Getenv("ATOLL_CONSOLE_PASSWORD")
	if pw == "" {
		fmt.Fprintln(stderr, "请通过环境变量 ATOLL_CONSOLE_PASSWORD 提供密码")
		return 2
	}
	srv, err := console.New(console.Config{DataDir: *dataDir})
	if err != nil {
		fmt.Fprintf(stderr, "atoll console useradd: %v\n", err)
		return 1
	}
	if err := srv.Users().Add(fs.Arg(0), pw, console.Role(*role)); err != nil {
		fmt.Fprintf(stderr, "atoll console useradd: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "已创建控制台账号 %s（角色 %s）\n", fs.Arg(0), *role)
	return 0
}

// ---- GC ----

func runGC(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	masterURL := fs.String("master", envDefault("ATOLL_MASTER", "http://127.0.0.1:9420"), "master 地址")
	execute := fs.Bool("execute", false, "执行删除（默认仅 dry-run）")
	token := fs.String("token", envDefault("ATOLL_TOKEN", ""), "集群认证 token")
	adminToken := fs.String("admin-token", envDefault("ATOLL_ADMIN_TOKEN", ""), "破坏性操作专用 token（master 配了 admin token 时必需）")
	tlsCA := fs.String("tls-ca", "", "校验服务端证书用的 CA（master 走 https 时）")
	tlsSkip := fs.Bool("tls-skip-verify", false, "跳过证书校验（自签名内网）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	tlsCfg, err := clientTLS(*tlsCA, *tlsSkip)
	if err != nil {
		fmt.Fprintf(stderr, "gc: %v\n", err)
		return 1
	}
	// gc 只打 /admin/gc（破坏性）：优先用 admin token，未设则回退集群 token。
	tok := *adminToken
	if tok == "" {
		tok = *token
	}
	c := client.NewWithTLS(*masterURL, auth.Token(tok), tlsCfg)
	reports, err := c.GC(*execute)
	if err != nil {
		fmt.Fprintf(stderr, "gc 失败: %v\n", err)
		return 1
	}
	totalOrphans := 0
	totalBytes := int64(0)
	totalDeleted := 0
	for _, r := range reports {
		totalOrphans += r.OrphanCount
		totalBytes += r.OrphanBytes
		totalDeleted += r.Deleted
		if r.OrphanCount > 0 {
			fmt.Fprintf(stdout, "节点 %d (%s): %d 个孤儿, %d 字节\n", r.NodeID, r.NodeAddr, r.OrphanCount, r.OrphanBytes)
		}
	}
	if totalOrphans == 0 {
		fmt.Fprintln(stdout, "无孤儿对象")
	} else if *execute {
		// 打印真实删除数，而非孤儿总数。两轮确认下首轮删除 0（本轮登记、下轮才删），
		// 此前直接把孤儿总数当"已删除"会误导。
		fmt.Fprintf(stdout, "发现 %d 个孤儿（共 %d 字节），本轮已删除 %d 个\n", totalOrphans, totalBytes, totalDeleted)
	} else {
		fmt.Fprintf(stdout, "发现 %d 个孤儿, 共 %d 字节（dry-run 未删除）\n", totalOrphans, totalBytes)
	}
	return 0
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// clientTLS 从 -tls-ca/-tls-skip-verify 构建出站 TLS 配置；两者都空则返回 nil（普通 HTTP）。
func clientTLS(caFile string, skipVerify bool) (*tls.Config, error) {
	if caFile == "" && !skipVerify {
		return nil, nil
	}
	return auth.ClientTLS(caFile, skipVerify)
}

// splitSeeds 解析逗号分隔的种子节点地址，去空白与空项。
func splitSeeds(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// humanSize 人类可读的字节数（KiB/MiB/GiB）。
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
