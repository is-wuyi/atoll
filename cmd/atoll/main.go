// atoll 是一个分布式文件存储系统（项目名：环礁）。
// 单一二进制包含三种角色：master（中心服务器）、node（存储节点），
// CLI 客户端命令 put/get/ls/mkdir/rm，以及 FUSE 挂载命令 mount。
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"atoll/client"
	"atoll/master"
	"atoll/master/meta"
	"atoll/mount"
	"atoll/node"
)

const usageText = `usage: atoll <command> [args]

服务角色:
  atoll master   启动中心服务器（元数据 + 副本调度）
  atoll node     启动存储节点（对象存储 + 心跳）

客户端命令 (可用 -master 或环境变量 ATOLL_MASTER 指定 master 地址):
  atoll put <本地文件> <远程路径>    上传文件 [-replicas N]
  atoll get <远程路径> <本地文件>    下载文件
  atoll ls  <远程路径>              列目录
  atoll mkdir <远程路径>            建目录
  atoll rm  <远程路径>              删除文件/空目录
  atoll mount <挂载点>              FUSE 挂载为本地目录 [-cache 缓冲目录 -replicas N]`

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
	case "put", "get", "ls", "mkdir", "rm":
		return runClientCmd(cmd, rest, stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usageText)
		return 0
	default:
		fmt.Fprintf(stderr, "atoll: unknown command %q\n\n%s\n", cmd, usageText)
		return 2
	}
}

// ---- master ----

func runMaster(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("master", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":9420", "监听地址")
	dbPath := fs.String("db", "atoll.db", "元数据 bbolt 文件路径")
	nodeMaxAge := fs.Duration("node-max-age", 30*time.Second, "节点心跳超时阈值")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	store, err := meta.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "atoll master: %v\n", err)
		return 1
	}
	defer store.Close()
	srv := master.NewServer(store, *nodeMaxAge)
	log.Printf("atoll master listening on %s (db=%s)", *listen, *dbPath)
	if err := http.ListenAndServe(*listen, srv.Handler()); err != nil {
		fmt.Fprintf(stderr, "atoll master: %v\n", err)
		return 1
	}
	return 0
}

// ---- node ----

func runNode(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("node", flag.ContinueOnError)
	fs.SetOutput(stderr)
	masterURL := fs.String("master", envDefault("ATOLL_MASTER", "http://127.0.0.1:9420"), "master 地址")
	listen := fs.String("listen", ":9421", "监听地址")
	advertise := fs.String("advertise", "", "注册到 master 供客户端直连的地址；跨机部署必须显式指定（如 203.0.113.5:9421）")
	dataDir := fs.String("data-dir", "./node-data", "对象存储目录")
	totalBytes := fs.Int64("total-bytes", 100<<30, "声明容量（字节）")
	if err := fs.Parse(args); err != nil {
		return 2
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
	if err := n.InitUsedBytes(); err != nil {
		fmt.Fprintf(stderr, "atoll node: %v\n", err)
		return 1
	}
	if err := n.Register(); err != nil {
		fmt.Fprintf(stderr, "atoll node: 注册 master 失败: %v\n", err)
		return 1
	}
	log.Printf("atoll node listening on %s (data=%s)", *listen, *dataDir)
	if err := http.ListenAndServe(*listen, n.Handler()); err != nil {
		fmt.Fprintf(stderr, "atoll node: %v\n", err)
		return 1
	}
	return 0
}

// ---- FUSE 挂载 ----

func runMount(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("mount", flag.ContinueOnError)
	fs.SetOutput(stderr)
	masterURL := fs.String("master", envDefault("ATOLL_MASTER", "http://127.0.0.1:9420"), "master 地址")
	replicas := fs.Int("replicas", 2, "新写入文件的副本数")
	cacheDir := fs.String("cache", filepath.Join(os.TempDir(), "atoll-cache"), "写缓冲临时目录")
	debug := fs.Bool("debug", false, "输出 FUSE 调试日志")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法: atoll mount [-cache 目录] <挂载点>")
		return 2
	}
	mountPoint := fs.Arg(0)
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		fmt.Fprintf(stderr, "atoll mount: %v\n", err)
		return 1
	}

	c := client.New(*masterURL)
	m, err := mount.New(c, *cacheDir, *replicas)
	if err != nil {
		fmt.Fprintf(stderr, "atoll mount: %v\n", err)
		return 1
	}
	server, err := fs.Mount(mountPoint, m.Root(), &fs.Options{
		MountOptions: fuse.MountOptions{Name: "atoll", Debug: *debug},
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
	replicas := fs.Int("replicas", 2, "副本数（仅 put 使用，含主副本）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c := client.New(*masterURL)

	switch cmd {
	case "put":
		if fs.NArg() != 2 {
			fmt.Fprintln(stderr, "用法: atoll put [-replicas N] <本地文件> <远程路径>")
			return 2
		}
		if err := c.Put(fs.Arg(0), fs.Arg(1), *replicas); err != nil {
			fmt.Fprintf(stderr, "put 失败: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "已上传 %s → %s（%d 副本）\n", fs.Arg(0), fs.Arg(1), *replicas)
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

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
