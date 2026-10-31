package main

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// 私有配置校验：token 门禁、字段必填、监听绑定纪律。错误只描述字段问题，
// 绝不回显 token 值。
func TestConfigTokenRules(t *testing.T) {
	long := strings.Repeat("x", 24) + "secret-suffix-not-logged"
	cfg := &Config{Role: "master", Token: long, Listen: "mesh-host:29460", DB: "lab.db"}
	cfg.normalize()
	if err := cfg.validate(); err != nil {
		t.Fatalf("合法 master 配置被拒: %v", err)
	}
	if cfg.NodeMaxAge.D() != 30*time.Second {
		t.Fatalf("默认 node_max_age = %v", cfg.NodeMaxAge.D())
	}
	short := &Config{Role: "master", Token: "short", Listen: "mesh-host:29460", DB: "lab.db"}
	err := short.validate()
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("短 token 应报错且提及 token: %v", err)
	}
	if strings.Contains(err.Error(), "short") && len("short") >= 24 {
		t.Fatal("unreachable")
	}
	if strings.Contains(err.Error(), long) {
		t.Fatal("错误信息不得回显 token 值")
	}
}

func TestConfigRejectsWildcardListen(t *testing.T) {
	for _, addr := range []string{":29460", "0.0.0.0:29460", ":::29460"} {
		cfg := &Config{Role: "node", Token: strings.Repeat("t", 30), Master: "http://m:29460",
			Advertise: "mesh:29461", DataDir: "d", Label: "A", Listen: addr,
			UploadBPS: 4 * MiB, DownloadBPS: 16 * MiB, TransferConcurrent: 4}
		if err := cfg.validate(); err == nil {
			t.Fatalf("监听 %q 应被拒绝（防公网暴露）", addr)
		}
	}
}

// 负值是配置错误：normalize 只补未设置的 0，不得把负值“救”成默认。
func TestConfigRejectsNegativeValues(t *testing.T) {
	cfg := &Config{Role: "node", Token: strings.Repeat("t", 30), Master: "http://m:29460",
		Advertise: "mesh:29461", DataDir: "d", Label: "A", Listen: "mesh:29461",
		TotalBytes: -1, UploadBPS: 4 * MiB, DownloadBPS: 16 * MiB, TransferConcurrent: 4}
	if err := cfg.validate(); err == nil {
		t.Fatal("负 total_bytes 应被拒")
	}
	m := &Config{Role: "master", Token: strings.Repeat("t", 30), Listen: "mesh:29460", DB: "x",
		NodeMaxAge: Dur(-time.Second)}
	m.normalize()
	if err := m.validate(); err == nil {
		t.Fatal("负 node_max_age 应被拒")
	}
	ok := &Config{Role: "master", Token: strings.Repeat("t", 30), Listen: "mesh:29460", DB: "x"}
	ok.normalize()
	if err := ok.validate(); err != nil {
		t.Fatalf("未设置字段应取默认: %v", err)
	}
}

func TestConfigRoleFields(t *testing.T) {
	node := &Config{Role: "node", Token: strings.Repeat("t", 30), Master: "http://m:29460",
		Advertise: "mesh:29461", DataDir: "d", Label: "A", Listen: "mesh:29461"}
	if err := node.validate(); err == nil {
		t.Fatal("缺预算的 node 应被拒")
	}
	node.UploadBPS, node.DownloadBPS, node.TransferConcurrent = 4*MiB, 16*MiB, 4
	node.normalize()
	if err := node.validate(); err != nil {
		t.Fatalf("合法 node 被拒: %v", err)
	}
	drive := &Config{Role: "drive", Token: strings.Repeat("t", 30), Master: "http://m:29460", ReportPath: "r.json"}
	if err := drive.validate(); err == nil {
		t.Fatal("缺 nodes 的 drive 应被拒")
	}
	drive.Nodes = []NodeRef{
		{Label: "A", Addr: "a:29461", UploadBPS: 4 * MiB, DownloadBPS: 16 * MiB},
		{Label: "A", Addr: "b:29461", UploadBPS: 4 * MiB, DownloadBPS: 16 * MiB},
	}
	if err := drive.validate(); err == nil {
		t.Fatal("重复 label 应被拒")
	}
	drive.Nodes[1].Label = "B"
	drive.Ingress = "A"
	drive.ClientUploadBPS, drive.ClientDownloadBPS = 4*MiB, 16*MiB
	drive.ClientConcurrent = 2
	drive.Scenarios = []string{"fault"}
	if err := drive.validate(); err == nil {
		t.Fatal("未知场景应被拒（fault 由主线程手控）")
	}
	drive.Scenarios = []string{"one-ingress", "protection"}
	if err := drive.validate(); err != nil {
		t.Fatalf("合法 drive 被拒: %v", err)
	}
}

// 配置含共享随机 Bearer：组/其他可读一律拒绝，必须 0600。
func TestLoadConfigRequiresPrivatePerms(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "node.lab.json")
	raw := `{"role":"node","token":"` + strings.Repeat("t", 30) + `","master":"http://m:29460",` +
		`"advertise":"mesh:29461","listen":"mesh:29461","data_dir":"d","label":"A",` +
		`"upload_bps":4194304,"download_bps":16777216,"transfer_concurrency":4}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("0644 配置应被拒并提示 chmod 600: %v", err)
	}
	if err := os.Chmod(cfgPath, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("0600 配置应通过: %v", err)
	}
	if cfg.Label != "A" || cfg.UploadBPS != 4*MiB {
		t.Fatal("字段解析错误")
	}
}

// 配置路径为符号链接一律拒绝：不跟随，防链接目标被替换或权限更宽。
func TestLoadConfigRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	raw := `{"role":"node","token":"` + strings.Repeat("t", 30) + `","master":"http://m:29460",` +
		`"advertise":"mesh:29461","listen":"mesh:29461","data_dir":"d","label":"A"}`
	if err := os.WriteFile(real, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	if _, err := LoadConfig(link); err == nil || !strings.Contains(err.Error(), "符号链接") {
		t.Fatalf("符号链接配置应被拒，got %v", err)
	}
	if _, err := LoadConfig(real); err != nil {
		t.Fatalf("实体文件应通过: %v", err)
	}
}

// dns_server：可选、必须数值 IP:port；缺省=系统解析不变（不隐含外联公共 DNS）。
func TestConfigDNSServerValidation(t *testing.T) {
	base := func(ds string) *Config {
		cfg := &Config{Role: "node", Token: strings.Repeat("t", 30), Master: "http://m:29460",
			Advertise: "mesh:29461", DataDir: "d", Label: "A", Listen: "mesh:29461",
			DNSServer: ds}
		cfg.normalize()
		return cfg
	}
	if err := base("10.126.126.126:53").validate(); err != nil {
		t.Fatalf("数值 IP:port 应通过: %v", err)
	}
	if err := base("").validate(); err != nil {
		t.Fatalf("缺省 dns_server 应通过: %v", err)
	}
	for _, bad := range []string{
		"dns.mesh.et.net:53", // 主机名：校验本身不得再依赖 DNS
		"10.126.126.126",     // 缺端口
		"10.126.126.126:notaport",
		"10.126.126.126:",
		"10.126.126.126:0",
		"999.1.1.1:53", // 非法 IP
	} {
		if err := base(bad).validate(); err == nil {
			t.Fatalf("dns_server %q 应被拒", bad)
		}
	}
}

// PreferGo 仍继承系统 trust-ad；带 AD 的查询按代理契约不缓存。
// 同时验证真实 resolver 经本地代理解析、缓存/旁路及 cleanup 恢复。
func TestApplyDNSOverrideProxyCache(t *testing.T) {
	oldAttempts, oldTimeout := dnsUpstreamAttempts, dnsUpstreamTimeout
	dnsUpstreamAttempts, dnsUpstreamTimeout = 1, 300*time.Millisecond
	t.Cleanup(func() { dnsUpstreamAttempts, dnsUpstreamTimeout = oldAttempts, oldTimeout })

	up := startFakeDNS(t, 1, "") // 上游 TTL=1s
	before := net.DefaultResolver
	cleanup, err := applyDNSOverride(up.addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	if net.DefaultResolver == before {
		t.Fatal("resolver 未被替换")
	}
	ctx := context.Background()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "node-a.et.net")
	if err != nil || len(ips) != 1 || ips[0].String() != "10.1.2.3" {
		t.Fatalf("首次解析失败: %v %v", ips, err)
	}
	if up.count() != 1 {
		t.Fatalf("首次解析应打上游 1 次，got %d", up.count())
	}
	first := up.firstQuery()
	if len(first) < 12 {
		t.Fatal("上游未收到完整 DNS 查询")
	}
	flags := binary.BigEndian.Uint16(first[2:4])
	if flags & ^uint16(0x0100|dnsFlagAD) != 0 {
		t.Fatalf("resolver 发出未预期的查询 flags: %#04x", flags)
	}
	wantWithinTTL := 1
	if flags&dnsFlagAD != 0 {
		wantWithinTTL = 2
	}
	ips2, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "node-a.et.net")
	if err != nil || len(ips2) != 1 || ips2[0].String() != "10.1.2.3" {
		t.Fatalf("第二次解析失败: %v %v", ips2, err)
	}
	if up.count() != wantWithinTTL {
		t.Fatalf("flags=%#04x，TTL 内上游查询应为 %d 次，got %d；首 %x；末 %x",
			flags, wantWithinTTL, up.count(), first, up.lastQuery())
	}
	time.Sleep(1300 * time.Millisecond)
	if _, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "node-a.et.net"); err != nil {
		t.Fatalf("过期后解析失败: %v", err)
	}
	if up.count() != wantWithinTTL+1 {
		t.Fatalf("过期后应再打上游，want %d got %d", wantWithinTTL+1, up.count())
	}
	cleanup()
	if net.DefaultResolver != before {
		t.Fatal("cleanup 未恢复原 resolver")
	}
}

// 上游全败（超时）与 SERVFAIL 都绝不缓存：两次相同查询各重打一次上游，
// 客户端拿到 rcode=SERVFAIL 且应答 ID 按每次请求 rebind（0x1111/0x2222）。
func TestDNSProxyTimeoutAndServfailNotCached(t *testing.T) {
	oldAttempts, oldTimeout := dnsUpstreamAttempts, dnsUpstreamTimeout
	dnsUpstreamAttempts, dnsUpstreamTimeout = 1, 200*time.Millisecond
	t.Cleanup(func() { dnsUpstreamAttempts, dnsUpstreamTimeout = oldAttempts, oldTimeout })

	for _, mode := range []string{"silent", "servfail"} {
		up := startFakeDNS(t, 1, mode)
		p, err := startDNSProxy(up.addr())
		if err != nil {
			t.Fatal(err)
		}
		for i, id := range []uint16{0x1111, 0x2222} {
			q := buildFakeQuery(id, "node-b.et.net", 1)
			resp, rerr := udpRoundtripE(p.addr(), q, 2*time.Second)
			if rerr != nil {
				t.Fatalf("%s roundtrip %d: %v；上游已收 %d 包", mode, i+1, rerr, up.count())
			}
			if resp[3]&0x0F != 2 {
				t.Fatalf("%s 第 %d 次应回 SERVFAIL，got rcode=%d", mode, i+1, resp[3]&0x0F)
			}
			if resp[0] != q[0] || resp[1] != q[1] {
				t.Fatalf("%s 第 %d 次应答 ID 未按请求 rebind", mode, i+1)
			}
		}
		p.close()
		if got := up.count(); got != 2 {
			t.Fatalf("%s 不应缓存：两次查询应各打上游一次，got %d", mode, got)
		}
	}
}

// 上游端口无监听：DialUDP 即刻成功、Write 后 Read 立即 ECONNREFUSED——
// bounded 重试后必须回合成 SERVFAIL（不依赖 fake，纯 synth 路径）。
func TestDNSProxyUpstreamRefusedSynthServfail(t *testing.T) {
	oldAttempts, oldTimeout := dnsUpstreamAttempts, dnsUpstreamTimeout
	dnsUpstreamAttempts, dnsUpstreamTimeout = 1, 200*time.Millisecond
	t.Cleanup(func() { dnsUpstreamAttempts, dnsUpstreamTimeout = oldAttempts, oldTimeout })

	// 找一个确定无监听的端口：先占再关。
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()
	p, err := startDNSProxy(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	resp := udpRoundtrip(t, p.addr(), buildFakeQuery(0x0B0B, "refused.et.net", 1))
	if resp[3]&0x0F != 2 {
		t.Fatalf("上游拒绝应合成 SERVFAIL，got rcode=%d", resp[3]&0x0F)
	}
}

// raw 层缓存回归：不经 resolver，两次字节相同的查询（仅 ID 不同）第二次必须
// 命中缓存（上游 1 次、应答 ID rebind、回包 TTL 已减到剩余≤cap 30s——不是上游
// 原值 50s），并抽查缓存条目记录 rcode/IPv4 TTL。
func TestDNSProxyCacheRawQuery(t *testing.T) {
	oldAttempts, oldTimeout := dnsUpstreamAttempts, dnsUpstreamTimeout
	dnsUpstreamAttempts, dnsUpstreamTimeout = 1, 300*time.Millisecond
	t.Cleanup(func() { dnsUpstreamAttempts, dnsUpstreamTimeout = oldAttempts, oldTimeout })

	up := startFakeDNS(t, 50, "") // 上游 TTL=50s（>cap，验证封顶+递减）
	p, err := startDNSProxy(up.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	q := buildFakeQuery(0x0A01, "cache.et.net", 1)
	resp := udpRoundtrip(t, p.addr(), q)
	if resp[3]&0x0F != 0 {
		t.Fatalf("首次查询应 NOERROR，got rcode=%d", resp[3]&0x0F)
	}
	p.mu.Lock()
	n := len(p.cache)
	p.mu.Unlock()
	if n != 1 {
		t.Fatalf("首次查询后缓存应有 1 条，got %d", n)
	}
	resp2 := udpRoundtrip(t, p.addr(), q) // 同字节第二次（命中）
	if up.count() != 1 {
		t.Fatalf("同 raw query 第二次应命中缓存，上游 got %d", up.count())
	}
	if resp2[0] != q[0] || resp2[1] != q[1] {
		t.Fatal("缓存命中应答 ID 未按本次请求 rebind")
	}
	// 回包 A 记录 TTL = 剩余秒数（fake 应答名 2 字节指针：ttl 在 qEnd+6..+10），
	// 必须 ≤30s cap 且明显小于上游原值 50s（honor TTL，不延长）。
	_, _, _, qEnd, err := parseQuestion(resp2)
	if err != nil {
		t.Fatal(err)
	}
	servedTTL := binary.BigEndian.Uint32(resp2[qEnd+6 : qEnd+10])
	if servedTTL > 30 || servedTTL < 20 {
		t.Fatalf("命中回包 TTL 应为剩余秒数(≤30)，got %d", servedTTL)
	}
	p.mu.Lock()
	for _, e := range p.cache {
		if e.rcode != 0 || e.ttlA != 50*time.Second || !time.Now().Before(e.expire) {
			p.mu.Unlock()
			t.Fatalf("缓存条目应记录 rcode=0/ttlA=50s/未过期，got %+v", e)
		}
	}
	p.mu.Unlock()
}

// ---- fake UDP DNS server（127.0.0.1 随机端口，统计收包并留存查询字节）----

type fakeDNS struct {
	pc      net.PacketConn
	ttl     uint32
	mode    string // ""|silent(收包不应答，模拟上游超时)|servfail(回合成 SERVFAIL)
	mu      sync.Mutex
	queries int
	firstQ  []byte // 首个查询字节（诊断：对比两次上游查询是否相同）
	lastQ   []byte // 最近一次查询字节
}

func startFakeDNS(t *testing.T, ttl uint32, mode string) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	f := &fakeDNS{pc: pc, ttl: ttl, mode: mode}
	go f.loop()
	return f
}

func (f *fakeDNS) addr() string { return f.pc.LocalAddr().String() }

func (f *fakeDNS) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries
}

func (f *fakeDNS) firstQuery() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.firstQ
}

func (f *fakeDNS) lastQuery() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastQ
}

func (f *fakeDNS) loop() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := f.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		f.mu.Lock()
		f.queries++
		if f.firstQ == nil {
			f.firstQ = append([]byte(nil), pkt...)
		}
		f.lastQ = append([]byte(nil), pkt...)
		f.mu.Unlock()
		if f.mode == "silent" {
			continue
		}
		id := binary.BigEndian.Uint16(pkt[0:2])
		_, typ, _, qEnd, err := parseQuestion(pkt)
		if err != nil {
			continue
		}
		var resp []byte
		if f.mode == "servfail" {
			resp = synthServfail(pkt, qEnd)
		} else {
			resp = fakeDNSReply(id, pkt, qEnd, typ, f.ttl)
		}
		_, _ = f.pc.WriteTo(resp, addr)
	}
}

// fakeDNSReply 原样回显问题段 + 单条 A/AAAA 记录（RR 名用压缩指针 0xC00C）。
func fakeDNSReply(id uint16, query []byte, qEnd int, typ uint16, ttl uint32) []byte {
	rdata := []byte{10, 1, 2, 3}
	if typ == 28 { // AAAA
		rdata = make([]byte, 16)
		rdata[0], rdata[15] = 0xfd, 1
	}
	out := make([]byte, 0, 12+qEnd-12+10+16+len(rdata))
	out = append(out, byte(id>>8), byte(id), 0x84, 0x80) // QR|AA, RA
	out = append(out, 0, 1, 0, 1, 0, 0, 0, 0)            // qd=1 an=1
	out = append(out, query[12:qEnd]...)
	out = append(out, 0xC0, 0x0C) // RR 名 → 问题名指针
	out = binary.BigEndian.AppendUint16(out, typ)
	out = binary.BigEndian.AppendUint16(out, 1) // IN
	out = binary.BigEndian.AppendUint32(out, ttl)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	return append(out, rdata...)
}

// buildFakeQuery 构造单问题 A/AAAA 查询（RD=1）。
func buildFakeQuery(id uint16, name string, typ uint16) []byte {
	var q []byte
	q = binary.BigEndian.AppendUint16(q, id)
	q = binary.BigEndian.AppendUint16(q, 0x0100)
	q = binary.BigEndian.AppendUint16(q, 1) // qd
	q = binary.BigEndian.AppendUint16(q, 0) // an
	q = binary.BigEndian.AppendUint16(q, 0) // ns
	q = binary.BigEndian.AppendUint16(q, 0) // ar
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, typ)
	return binary.BigEndian.AppendUint16(q, 1)
}

// udpRoundtrip 向代理发查询并等应答（断言 ID 回显由调用方做）。
func udpRoundtrip(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	resp, err := udpRoundtripE(addr, query, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// udpRoundtripE 同上但返回错误（诊断用）。
func udpRoundtripE(addr string, query []byte, timeout time.Duration) ([]byte, error) {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// 预检：真实预算上界（150s ioTimeout 与 300s 传输计划 TTL）。
func TestPreflightBudgetBounds(t *testing.T) {
	cfg := func(size int64, up uint64) *Config {
		return &Config{SampleBytes: size, ClientUploadBPS: up, ClientConcurrent: 2,
			Nodes: []NodeRef{{Label: "A", Addr: "a:1", UploadBPS: up, DownloadBPS: 16 * MiB},
				{Label: "B", Addr: "b:1", UploadBPS: up, DownloadBPS: 16 * MiB}}}
	}
	if err := preflight(cfg(192*MiB, 4*MiB)); err != nil {
		t.Fatalf("192MiB @4MiB/s 应通过: %v", err)
	}
	if err := preflight(cfg(80*MiB, 1*MiB)); err != nil {
		t.Fatalf("80MiB @1MiB/s 应通过: %v", err)
	}
	if err := preflight(cfg(192*MiB, 1*MiB)); err == nil {
		t.Fatal("192MiB @1MiB/s 应拒绝（估时超 300s TTL）")
	}
	if err := preflight(cfg(64*MiB, 4*MiB)); err == nil {
		t.Fatal("≤64MiB 样本应拒绝（不成多块）")
	}
	if err := preflight(cfg(80*MiB, 256<<10)); err == nil {
		t.Fatal("256KiB/s 上行应拒绝（逼近 150s ioTimeout）")
	}
}
