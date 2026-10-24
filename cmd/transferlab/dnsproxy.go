package main

// 本测试进程专用 DNS 代理（仅 loopback 随机端口，可 cleanup 终止）：
// net.DefaultResolver 只指向它，它再转发到 cfg.dns_server（数值 IP:port）。
// 背景：28425 节点对每个复制 descriptor 重复发 DNS UDP 查询且经常超时——
// 相同 (name/type/flags) 的查询在 TTL 内只打一次上游。TTL 按上游应答原值
// 取用（IPv4 A 记录 TTL 记录在案），只封顶 30s、绝不延长 authoritative TTL，
// 绝不 hardcode IP 映射、不改全局系统 DNS。上游仅 UDP（实测 53/tcp 被拒）：
// 每次尝试写后等应答 read deadline（默认 4s，dial 即刻成功不占边界）、最多
// 3 次——单条查询最坏 ~12s；全败向客户端回合成 SERVFAIL 且不缓存——单主
// 健康/heartbeat 有界阻塞，不会 stall 死。SERVFAIL/NXDOMAIN/timeout/空答案
// 一律不缓存（负缓存未做）。非生产网络修复：仅供隔离 lab 复用。
//
// 应答一律原样转发/缓存（问题段与记录区不动，压缩指针保持有效），
// 仅把 ID 按每次请求 rebind。解析为 stdlib 手写最小 wire 解析（支持压缩
// 指针，限 32 跳防循环），不引入新依赖、不动 go.mod。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	dnsMaxCacheTTL   = 30 * time.Second
	dnsMaxCacheItems = 512
	dnsMaxPending    = 32 // 在途处理上限，满载丢弃（客户端 resolver 自会重传）
)

// 包级变量仅为测试可调（避免 3×4s 真等）；生产路径不改。
var (
	dnsUpstreamAttempts = 3
	dnsUpstreamTimeout  = 4 * time.Second
)

// DNS flags 位（16 位字）：QR=0x8000 Opcode=0x7800 AA=0x0400 TC=0x0200
// RD=0x0100 RA=0x0080 Z=0x0040 AD=0x0020 CD=0x0010 RCODE=0x000F。
const (
	dnsFlagQR = 0x8000
	dnsFlagOP = 0x7800
	dnsFlagZ  = 0x0040
	dnsFlagAD = 0x0020
	dnsFlagCD = 0x0010
)

type dnsKey struct {
	name  string // 小写、带尾点
	typ   uint16
	class uint16
	rd    bool
}

type dnsEntry struct {
	reply  []byte // ID=0 的上游原始应答；每次取用 rebind 客户端 ID
	expire time.Time
	rcode  int
	ttlA   time.Duration // IPv4 A 记录 TTL（记录用）
}

type dnsProxy struct {
	upstream string
	upAddr   *net.UDPAddr // 上游数值 IP:port 预解析；转发全程不触碰任何 resolver
	conn     *net.UDPConn
	pending  chan struct{}
	mu       sync.Mutex
	cache    map[dnsKey]dnsEntry
	wg       sync.WaitGroup
}

// startDNSProxy 在 127.0.0.1 随机 UDP 端口起代理，upstream 为数值 IP:port
// （LoadConfig 已校验，此处 netip 再解析一次，绝不做名字解析）。
func startDNSProxy(upstream string) (*dnsProxy, error) {
	ap, err := netip.ParseAddrPort(upstream)
	if err != nil {
		return nil, fmt.Errorf("上游 %q 需为数值 IP:port: %w", upstream, err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	p := &dnsProxy{upstream: upstream,
		upAddr: &net.UDPAddr{IP: net.IP(ap.Addr().AsSlice()), Port: int(ap.Port())},
		conn:   conn, pending: make(chan struct{}, dnsMaxPending),
		cache: map[dnsKey]dnsEntry{}}
	p.wg.Add(1)
	go p.loop()
	return p, nil
}

func (p *dnsProxy) addr() string { return p.conn.LocalAddr().String() }

func (p *dnsProxy) udpAddr() *net.UDPAddr { return p.conn.LocalAddr().(*net.UDPAddr) }

// close 终止读取循环并等所有在途处理结束（幂等：重复 Close 仅报错被忽略）。
func (p *dnsProxy) close() {
	p.conn.Close()
	p.wg.Wait()
}

func (p *dnsProxy) loop() {
	defer p.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, addr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return // close() 触发
		}
		select {
		case p.pending <- struct{}{}:
		default:
			continue // 满载丢弃（bounded）：客户端 resolver 自会重传
		}
		pkt := append([]byte(nil), buf[:n]...)
		p.wg.Add(1)
		go func(pkt []byte, addr *net.UDPAddr) {
			defer func() { <-p.pending; p.wg.Done() }()
			p.handle(pkt, addr)
		}(pkt, addr)
	}
}

func (p *dnsProxy) handle(pkt []byte, client *net.UDPAddr) {
	if len(pkt) < 12 {
		return
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&dnsFlagQR != 0 { // 响应：忽略
		return
	}
	if binary.BigEndian.Uint16(pkt[4:6]) != 1 { // 只处理单问题查询
		return
	}
	name, typ, class, qEnd, err := parseQuestion(pkt)
	if err != nil {
		return
	}
	key := dnsKey{name: strings.ToLower(name), typ: typ, class: class, rd: flags&0x0100 != 0}
	cacheable := cacheableQuery(pkt, flags, typ, class)
	if cacheable {
		if e, ok := p.lookup(key); ok {
			// 命中：TTL 全部置为剩余时间（只改 ANSWER 区，OPT 伪 TTL 不动），
			// honest honor upstream TTL。
			p.send(patchAnswerTTLs(e.reply, time.Until(e.expire)), pkt, client)
			return
		}
	}
	resp, ok := p.forward(pkt)
	if !ok { // bounded 全败：合成 SERVFAIL 快速失败，不缓存
		if s := synthServfail(pkt, qEnd); s != nil {
			p.send(s, pkt, client)
		}
		return
	}
	if cacheable {
		p.store(key, resp)
	}
	p.send(resp, pkt, client)
}

// cacheableQuery 只缓存常规 Go 查询：QR=0、标准 Opcode、class IN、type A/AAAA、
// Z/AD/CD=0；额外段仅允许 Go 默认形态 EDNS0 OPT（type 41、DO=0、无 option）或
// 无 EDNS。不支持的 flags/形态一律照转不缓存。
func cacheableQuery(pkt []byte, flags uint16, typ, class uint16) bool {
	if flags&(dnsFlagQR|dnsFlagOP|dnsFlagZ|dnsFlagAD|dnsFlagCD) != 0 {
		return false
	}
	if class != 1 || (typ != 1 && typ != 28) { // 仅 IN 的 A/AAAA
		return false
	}
	ar := int(binary.BigEndian.Uint16(pkt[10:12]))
	if ar == 0 {
		return true
	}
	if ar != 1 {
		return false
	}
	_, _, _, qEnd, err := parseQuestion(pkt)
	if err != nil || qEnd+11 > len(pkt) {
		return false
	}
	// OPT: NAME(1), TYPE(2), CLASS(2), extended RCODE(1), version(1), flags(2), RDLEN(2).
	opt := pkt[qEnd:]
	return len(opt) == 11 && opt[0] == 0 &&
		binary.BigEndian.Uint16(opt[1:3]) == 41 &&
		binary.BigEndian.Uint32(opt[5:9]) == 0 &&
		binary.BigEndian.Uint16(opt[9:11]) == 0
}

// forward 用独立 UDP socket 转发原始查询（含客户端 ID）：dial 即刻成功，
// 查询边界=每次尝试的应答 read deadline（dnsUpstreamTimeout），最多
// dnsUpstreamAttempts 次。net.DialUDP 直连数值地址，不经过任何 resolver
// （net.Dialer.DialContext 会读全局 net.DefaultResolver，与覆盖写入构成竞争）。
func (p *dnsProxy) forward(query []byte) ([]byte, bool) {
	for i := 0; i < dnsUpstreamAttempts; i++ {
		c, err := net.DialUDP("udp", nil, p.upAddr)
		if err == nil {
			if _, werr := c.Write(query); werr == nil {
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(dnsUpstreamTimeout))
				n, rerr := c.Read(buf)
				if rerr == nil && validReply(buf[:n], query) {
					c.Close()
					return append([]byte(nil), buf[:n]...), true
				}
			}
			c.Close()
		}
	}
	return nil, false
}

// validReply 校验上游应答：QR=响应、QD 恰为 1、ID 回显 + 问题段语义一致
// （容忍上游重编码/压缩）。
func validReply(resp, query []byte) bool {
	if len(resp) < 12 || len(query) < 12 {
		return false
	}
	if resp[2]&0x80 == 0 { // 必须是响应（QR=1，flags 高字节 bit7）
		return false
	}
	if binary.BigEndian.Uint16(resp[4:6]) != 1 { // 恰一个 question
		return false
	}
	if resp[0] != query[0] || resp[1] != query[1] {
		return false
	}
	rname, rtyp, rclass, _, err := parseQuestion(resp)
	if err != nil {
		return false
	}
	qname, qtyp, qclass, _, err := parseQuestion(query)
	if err != nil {
		return false
	}
	return rclass == 1 && qclass == 1 && rtyp == qtyp && strings.EqualFold(rname, qname)
}

func (p *dnsProxy) lookup(key dnsKey) (dnsEntry, bool) {
	p.mu.Lock()
	e, ok := p.cache[key]
	p.mu.Unlock()
	if !ok || !time.Now().Before(e.expire) { // 惰性过期
		return dnsEntry{}, false
	}
	return e, true
}

// store 只缓存 NOERROR+非空答案+minTTL>0 的应答；TTL 原值取用、封顶 30s。
func (p *dnsProxy) store(key dnsKey, resp []byte) {
	if len(resp) < 12 {
		return
	}
	rcode := int(resp[3] & 0x0F)
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	if rcode != 0 || an == 0 || resp[2]&0x02 != 0 { // SERVFAIL/NX/NODATA/TC 不缓存
		return
	}
	minTTL, aTTL, err := minAnswerTTL(resp)
	if err != nil || minTTL == 0 {
		return
	}
	d := time.Duration(minTTL) * time.Second
	if d > dnsMaxCacheTTL {
		d = dnsMaxCacheTTL
	}
	cp := append([]byte(nil), resp...)
	cp[0], cp[1] = 0, 0 // ID 置零，取用时按每次请求 rebind
	p.mu.Lock()
	if len(p.cache) >= dnsMaxCacheItems {
		for k := range p.cache { // 随机逐出一条（map 遍历序随机，lab 足够）
			delete(p.cache, k)
			break
		}
	}
	p.cache[key] = dnsEntry{reply: cp, expire: time.Now().Add(d),
		rcode: rcode, ttlA: time.Duration(aTTL) * time.Second}
	p.mu.Unlock()
}

// patchAnswerTTLs 把应答 ANSWER 区全部 RR 的 TTL 置为剩余秒数（min remaining，
// 不向上调）；AUTHORITY/ADDITIONAL（含 OPT 伪 TTL）不动。解析失败时原样返回。
func patchAnswerTTLs(msg []byte, remaining time.Duration) []byte {
	out := append([]byte(nil), msg...)
	if len(out) < 12 {
		return out
	}
	secs := uint32(0)
	if remaining > time.Second {
		secs = uint32(remaining / time.Second)
	}
	qd := int(binary.BigEndian.Uint16(out[4:6]))
	an := int(binary.BigEndian.Uint16(out[6:8]))
	off, err := 12, error(nil)
	for i := 0; i < qd && err == nil; i++ {
		off, _, err = walkName(out, off)
		off += 4
	}
	for i := 0; i < an && err == nil; i++ {
		off, _, err = walkName(out, off)
		if err != nil {
			break
		}
		if off+10 > len(out) {
			break
		}
		binary.BigEndian.PutUint32(out[off+4:off+8], secs)
		rdlen := int(binary.BigEndian.Uint16(out[off+8 : off+10]))
		off += 10 + rdlen
	}
	return out
}

// send 按本次请求 rebind 客户端 ID 后回包（缓存命中/转发/合成统一走这里）。
func (p *dnsProxy) send(msg, query []byte, client *net.UDPAddr) {
	if len(msg) < 12 {
		return
	}
	out := append([]byte(nil), msg...)
	out[0], out[1] = query[0], query[1]
	_, _ = p.conn.WriteToUDP(out, client)
}

// synthServfail 用原始查询的 ID/问题段合成 SERVFAIL（QR|RD|RA, RCODE=2）。
func synthServfail(query []byte, qEnd int) []byte {
	if qEnd < 12 || qEnd > len(query) {
		return nil
	}
	out := make([]byte, 12, 12+qEnd-12)
	out[0], out[1] = query[0], query[1]
	out[2], out[3] = 0x81, 0x82 // QR|RD, RA|RCODE=SERVFAIL
	binary.BigEndian.PutUint16(out[4:6], 1)
	return append(out, query[12:qEnd]...)
}

// ---- 最小 DNS wire 解析（仅代理需要的部分）----

func parseQuestion(pkt []byte) (name string, typ, class uint16, end int, err error) {
	if len(pkt) < 12 {
		return "", 0, 0, 0, errors.New("dns: 短头")
	}
	end, name, err = walkName(pkt, 12)
	if err != nil {
		return "", 0, 0, 0, err
	}
	if end+4 > len(pkt) {
		return "", 0, 0, 0, errors.New("dns: 问题段截断")
	}
	typ = binary.BigEndian.Uint16(pkt[end:])
	class = binary.BigEndian.Uint16(pkt[end+2:])
	return name, typ, class, end + 4, nil
}

// walkName 走 DNS 名字（支持压缩指针，限 32 跳防循环），返回名字结束偏移
// 与带尾点小写化的展示名（缓存 key 用 strings.ToLower 再规整）。
func walkName(pkt []byte, off int) (int, string, error) {
	var sb strings.Builder
	end := -1
	for hops := 0; ; hops++ {
		if hops > 32 || off < 0 || off >= len(pkt) {
			return 0, "", errors.New("dns: 名字越界/指针循环")
		}
		l := int(pkt[off])
		switch {
		case l == 0:
			off++
			if end < 0 {
				end = off
			}
			return end, sb.String(), nil
		case l&0xC0 == 0xC0:
			if off+2 > len(pkt) {
				return 0, "", errors.New("dns: 截断指针")
			}
			if end < 0 {
				end = off + 2
			}
			off = (l&0x3F)<<8 | int(pkt[off+1])
		case l&0xC0 != 0:
			return 0, "", errors.New("dns: 保留标签类型")
		default:
			if off+1+l > len(pkt) {
				return 0, "", errors.New("dns: 标签越界")
			}
			sb.WriteByte('.')
			for _, c := range pkt[off+1 : off+1+l] {
				sb.WriteByte(lowerByte(c))
			}
			off += 1 + l
		}
	}
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// minAnswerTTL 遍历应答区：全部 RR 的最小 TTL 与 A 记录（IPv4）最小 TTL。
func minAnswerTTL(pkt []byte) (minTTL, aTTL uint32, err error) {
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		if off, _, err = walkName(pkt, off); err != nil {
			return 0, 0, err
		}
		off += 4
	}
	const maxU32 = ^uint32(0)
	minTTL, aTTL = maxU32, maxU32
	for i := 0; i < an; i++ {
		if off, _, err = walkName(pkt, off); err != nil {
			return 0, 0, err
		}
		if off+10 > len(pkt) {
			return 0, 0, errors.New("dns: RR 头截断")
		}
		// RR 固定头：TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
		typ := binary.BigEndian.Uint16(pkt[off:])
		ttl := binary.BigEndian.Uint32(pkt[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
		if typ == 1 && ttl < aTTL {
			aTTL = ttl
		}
		if ttl < minTTL {
			minTTL = ttl
		}
		off += 10 + rdlen
		if off > len(pkt) {
			return 0, 0, errors.New("dns: RR 越界")
		}
	}
	if minTTL == maxU32 {
		minTTL, aTTL = 0, 0
	}
	return minTTL, aTTL, nil
}
