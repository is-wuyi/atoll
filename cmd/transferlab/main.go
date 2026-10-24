// transferlab 是 f9b7a73 闭环的隔离 EasyTier NAS 实机测试 runner（非正式部署）。
//
// 三个角色全部复用生产实现：master.Server + meta.Store、node.Node、client.Client。
// 一切配置来自 -config 私有 JSON（含随机 Bearer token，仅测试使用，不入 repo）。
// lab 控制面（/lab/*）与集群共用同一把共享随机 token；样本是随机 plain 数据，
// 本工具不声称 AEAD/安全模式验证。主线程负责部署、SSH 与报告归档。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("transferlab", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "私有配置 JSON 路径（role/token/各角色字段；随机 Bearer 不入 repo）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" {
		fmt.Fprintln(stderr, "用法: transferlab -config <私有JSON>（role=master|node|drive）")
		return 2
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		// 配置错误绝不回显 token 值，只描述字段问题。
		fmt.Fprintln(stderr, "transferlab 配置错误:", err)
		return 2
	}
	// 可选 dns_server：本测试进程的解析经本地 loopback 代理（TTL 缓存+bounded
	// 上游重试）固定到 mesh 中心 DNS——系统 DNS 把 .et.net 落公网占位时的隔离
	// 手段；不改系统 DNS/hosts/EasyTier，缺省不接。
	cleanupDNS := func() {}
	if cfg.DNSServer != "" {
		c, err := applyDNSOverride(cfg.DNSServer)
		if err != nil {
			fmt.Fprintln(stderr, "transferlab: DNS 代理启动失败:", err)
			return 1
		}
		cleanupDNS = c
		fmt.Fprintf(stderr, "transferlab: 本进程解析经 loopback TTL 缓存 → 上游 %s（TTL≤30s；UDP 单次读截止4s、最多3次；失败不缓存；不改系统 DNS）\n", cfg.DNSServer)
	}
	defer cleanupDNS()
	return runRole(cfg, stderr)
}

// applyDNSOverride 启动 loopback DNS 代理并把本进程 net.DefaultResolver 固定到
// 它（PreferGo）。Dial 回调直接 net.DialUDP 到代理（数值地址，绝不经过任何
// resolver——net.Dialer.DialContext 会读全局 net.DefaultResolver，与覆盖写入
// 构成数据竞争/递归）。上游 53/tcp 已实测拒绝：TCP（仅 TC 截断重试会出现）
// 显式快速失败，不走 TCP 上游、无公共 DNS 回退。返回 cleanup：恢复原 resolver
// 并终止代理（调用方 defer）。
func applyDNSOverride(server string) (func(), error) {
	proxy, err := startDNSProxy(server)
	if err != nil {
		return nil, err
	}
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network == "tcp" {
				return nil, errors.New("transferlab dns: 上游 53/tcp 已拒绝，仅支持 UDP")
			}
			return net.DialUDP("udp", nil, proxy.udpAddr())
		},
	}
	return func() {
		net.DefaultResolver = old
		proxy.close()
	}, nil
}
