package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"atoll/master"
	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

func runRole(cfg *Config, stderr io.Writer) int {
	switch cfg.Role {
	case "master":
		return runMasterRole(cfg)
	case "node":
		return runNodeRole(cfg)
	case "drive":
		return runDrive(cfg, stderr)
	}
	return 2
}

// serve 启动 HTTP 服务；SIGINT/SIGTERM 触发 5s 优雅关闭，返回进程退出码。
func serve(httpSrv *http.Server, banner string) int {
	log.Printf("%s", banner)
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("transferlab: %v", err)
		return 1
	}
	return 0
}

// runMasterRole 用生产 master.Server + meta.Store + Scanner + Autonomy 装配中心，
// 原样启用 write-planning + transfer-planning（状态持久化，重启必须保持同配置），
// 并在外层挂 /lab/* 控制面（同一把共享随机 Bearer）。Autonomy 以 add 模式装配，
// 后台间隔拉长（1h）——派工由 /lab/step 显式驱动，与生产 claim/源绑定/回执路径一致。
func runMasterRole(cfg *Config) int {
	store, err := meta.Open(cfg.DB)
	if err != nil {
		log.Printf("transferlab master: 打开元数据库失败: %v", err)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	defer store.Close()

	srv := master.NewServer(store, cfg.NodeMaxAge.D())
	// 修复扫描默认拉长到 1h：缺块必须由显式 /lab/reserve + /lab/step 补齐，
	// 不允许后台修复提前把“第三副本”掩掉；GC（两轮确认）与死亡监视保持常态。
	scanner := master.NewScanner(store, cfg.NodeMaxAge.D(), cfg.RepairInterval.D(), cfg.GCInterval.D())
	scanner.SetToken(auth.Token(cfg.Token))
	scanner.SetAdditiveOnly(true)
	srv.SetScanner(scanner)
	srv.SetToken(auth.Token(cfg.Token))
	srv.SetAdminToken(auth.Token(cfg.Token))
	if err := srv.EnableWritePlanning(master.WritePlanningConfig{
		MaxReplicas: cfg.WriteMaxReplicas, TransferPlanning: true,
	}); err != nil {
		log.Printf("transferlab master: 启用写规划失败: %v", err)
		return 1
	}
	aut, err := master.NewAutonomy(store, cfg.NodeMaxAge.D(), master.AutonomyConfig{
		Mode: master.AutonomyAdd, Interval: cfg.AutonomyInterval.D(), RetryInterval: cfg.AutonomyRetry.D(),
		MaxDispatchPerTick: cfg.AutonomyDispatch, MaxBytesPerRound: cfg.AutonomyBytes,
		MaxReplicas: cfg.WriteMaxReplicas,
	})
	if err != nil {
		log.Printf("transferlab master: autonomy 装配失败: %v", err)
		return 1
	}
	aut.SetTransport(auth.Token(cfg.Token), nil)
	srv.SetAutonomy(aut)
	// 刻意不调 aut.Start：自治后台循环（即使间隔 1h）与显式测试时序竞争。
	// 派工只由 /lab/step 显式触发（生产 Step：claim 源绑定 → /pull → 真回执）。
	scanner.Start(ctx)
	defer func() {
		cancel()
		scanner.Wait()
	}()

	lab := &masterLab{store: store, autonomy: aut, nodeMaxAge: cfg.NodeMaxAge.D()}
	labHandler := auth.Wrap(lab.Routes(), auth.Token(cfg.Token))
	prod := srv.Handler()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/lab/") {
			labHandler.ServeHTTP(w, r)
			return
		}
		prod.ServeHTTP(w, r)
	})
	return serve(&http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second},
		fmt.Sprintf("transferlab master 监听 %s (db=%s, write-planning+transfer 已启用, /lab/* 随机 Bearer 门控)", cfg.Listen, cfg.DB))
}

// runNodeRole 用生产 node.Node 装配存储节点：本地传输预算必须在注册前一次性配置
// （计划腿会派发确定速率，节点本地 Limiter 是执行闸），注册后包上 lab 录制/故障层。
func runNodeRole(cfg *Config) int {
	n := node.New(cfg.DataDir, cfg.Master, cfg.Advertise, cfg.TotalBytes)
	if err := n.ConfigureTransferBudget(types.TransferBudget{
		UploadBPS: cfg.UploadBPS, DownloadBPS: cfg.DownloadBPS, MaxConcurrent: cfg.TransferConcurrent,
	}); err != nil {
		log.Printf("transferlab node: 传输预算配置失败: %v", err)
		return 1
	}
	n.SetToken(auth.Token(cfg.Token))
	if err := n.InitUsedBytes(); err != nil {
		log.Printf("transferlab node: %v", err)
		return 1
	}
	if err := n.Register(); err != nil {
		log.Printf("transferlab node: 注册 master 失败: %v", err)
		return 1
	}
	lab := newNodeLab(cfg.Label, 4096)
	lab.nodeID.Store(int64(n.NodeIDForTest()))
	handler := lab.WrapNode(n, auth.Token(cfg.Token))
	return serve(&http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second},
		fmt.Sprintf("transferlab node %s 监听 %s (advertise=%s, up=%dB/s down=%dB/s)",
			cfg.Label, cfg.Listen, cfg.Advertise, cfg.UploadBPS, cfg.DownloadBPS))
}
