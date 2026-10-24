package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const MiB = 1 << 20

// Dur 允许配置文件用 "30s"/"5m" 表达时长；空值在 normalize 里给默认。
type Dur time.Duration

func (d *Dur) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("时长 %q 非法: %w", s, err)
	}
	*d = Dur(v)
	return nil
}

// D 返回原始时长。
func (d Dur) D() time.Duration { return time.Duration(d) }

// NodeRef 是 drive 侧对一个节点的声明：地址与预算必须与该节点自己的 node 配置一致
// （profile 预算同源，节点本地 Limiter 才能承接计划派发的速率）。
type NodeRef struct {
	Label         string `json:"label"`
	Addr          string `json:"addr"`
	UploadBPS     uint64 `json:"upload_bps"`
	DownloadBPS   uint64 `json:"download_bps"`
	MaxConcurrent int    `json:"max_concurrent"`
}

// Config 是全部角色共用的私有配置结构，按 Role 取用对应字段。
type Config struct {
	Role  string `json:"role"`
	Token string `json:"token"`

	// 可选：dns_server（数值 IP:port，如 mesh 中心 DNS）。仅覆盖**本测试进程**
	// 的域名解析——系统 DNS 把 .et.net 落公网占位时的隔离测试手段；
	// 缺省完全不动系统解析/hosts。格式校验见 validate，进程内接线见 main。
	DNSServer string `json:"dns_server"`

	// master
	Listen            string `json:"listen"`
	DB                string `json:"db"`
	NodeMaxAge        Dur    `json:"node_max_age"`
	WriteMaxReplicas  int    `json:"write_max_replicas"`
	AutonomyInterval  Dur    `json:"autonomy_interval"`
	AutonomyRetry     Dur    `json:"autonomy_retry"`
	AutonomyBytes     int64  `json:"autonomy_bytes_per_round"`
	AutonomyDispatch  int    `json:"autonomy_dispatch_per_step"`
	RepairInterval    Dur    `json:"repair_interval"`
	GCInterval        Dur    `json:"gc_interval"`
	NodeHeartbeatWait Dur    `json:"node_heartbeat_wait"`

	// node
	Master             string `json:"master"`
	Advertise          string `json:"advertise"`
	DataDir            string `json:"data_dir"`
	TotalBytes         int64  `json:"total_bytes"`
	Label              string `json:"label"`
	UploadBPS          uint64 `json:"upload_bps"`
	DownloadBPS        uint64 `json:"download_bps"`
	TransferConcurrent int    `json:"transfer_concurrency"`

	// drive
	Nodes             []NodeRef `json:"nodes"`
	Ingress           string    `json:"ingress"`
	SampleBytes       int64     `json:"sample_bytes"`
	ClientUploadBPS   uint64    `json:"client_upload_bps"`
	ClientDownloadBPS uint64    `json:"client_download_bps"`
	ClientConcurrent  int       `json:"client_concurrent"`
	RemoteDir         string    `json:"remote_dir"`
	Scenarios         []string  `json:"scenarios"`
	ReportPath        string    `json:"report_path"`
	JoinWait          Dur       `json:"join_wait"`
	StepInterval      Dur       `json:"step_interval"`
	ObserveWait       Dur       `json:"observe_wait"`
	ScenarioDeadline  Dur       `json:"scenario_deadline"`
}

// LoadConfig 读取并校验私有配置。错误只描述字段，绝不回显 token 值。
func LoadConfig(path string) (*Config, error) {
	// 含共享随机 Bearer 的文件必须 0600：组/其他可读一律拒绝，
	// 防止凭据经共享临时目录或宽松 umask 外泄。符号链接一律拒绝
	// （不跟随：链接目标可能是权限更宽或被替换的路径）。
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s 是符号链接：拒绝跟随，请直接传入实体文件", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s 权限 %o 过宽：含共享随机 Bearer，必须 chmod 600", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.normalize()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) normalize() {
	setDur := func(d *Dur, v time.Duration) {
		if d.D() == 0 {
			*d = Dur(v)
		}
	}
	setInt := func(v *int, def int) {
		if *v == 0 {
			*v = def
		}
	}
	// 默认值只填补“未设置”（0）；负值是配置错误，交给 validate 拒绝，
	// 绝不静默改成默认值掩盖。
	setDur(&c.NodeMaxAge, 30*time.Second)
	setDur(&c.AutonomyInterval, time.Hour)
	setDur(&c.AutonomyRetry, 30*time.Second)
	setDur(&c.RepairInterval, time.Hour)
	setDur(&c.GCInterval, 10*time.Minute)
	setDur(&c.NodeHeartbeatWait, 8*time.Second)
	setInt(&c.WriteMaxReplicas, 8)
	setInt(&c.AutonomyDispatch, 2)
	if c.AutonomyBytes == 0 {
		c.AutonomyBytes = 256 << 20
	}
	if c.TotalBytes == 0 {
		c.TotalBytes = 100 << 30
	}
	if c.UploadBPS == 0 {
		c.UploadBPS = 4 * MiB
	}
	if c.DownloadBPS == 0 {
		c.DownloadBPS = 16 * MiB
	}
	setInt(&c.TransferConcurrent, 4)
	if c.SampleBytes == 0 {
		c.SampleBytes = 192 * MiB // 3×64MiB；主线程可先用 80MiB(64+16)
	}
	if c.ClientUploadBPS == 0 {
		c.ClientUploadBPS = 4 * MiB
	}
	if c.ClientDownloadBPS == 0 {
		c.ClientDownloadBPS = 16 * MiB
	}
	setInt(&c.ClientConcurrent, 2)
	if c.RemoteDir == "" {
		c.RemoteDir = "/transferlab"
	}
	if len(c.Scenarios) == 0 {
		c.Scenarios = []string{"one-ingress", "protection"}
	}
	setDur(&c.JoinWait, 10*time.Minute)
	setDur(&c.StepInterval, 3*time.Second)
	setDur(&c.ObserveWait, 12*time.Second)
	setDur(&c.ScenarioDeadline, 6*time.Minute)
}

func (c *Config) validate() error {
	if len(c.Token) < 24 || strings.ContainsAny(c.Token, " \t\r\n") {
		return fmt.Errorf("token 必须 ≥24 字符的随机值（atoll auth gen 生成），当前长度 %d", len(c.Token))
	}
	// dns_server 只接受数值 IP:port（不解析主机名：查这个名字本身就要先过 DNS）。
	if c.DNSServer != "" {
		host, port, err := net.SplitHostPort(c.DNSServer)
		if err != nil || net.ParseIP(host) == nil {
			return fmt.Errorf("dns_server %q 需为数值 IP:port（如 mesh 中心 DNS）；缺省则用系统解析", c.DNSServer)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("dns_server %q 端口需为 1..65535 数字", c.DNSServer)
		}
	}
	switch c.Role {
	case "master":
		if err := positive(map[string]time.Duration{
			"node_max_age": c.NodeMaxAge.D(), "autonomy_interval": c.AutonomyInterval.D(),
			"autonomy_retry": c.AutonomyRetry.D(), "repair_interval": c.RepairInterval.D(),
			"gc_interval": c.GCInterval.D()}); err != nil {
			return err
		}
		if c.AutonomyBytes < 0 || c.AutonomyDispatch < 0 || c.WriteMaxReplicas < 0 {
			return fmt.Errorf("master 的预算/并发/副本数不得为负")
		}
		return checkBind(c.Listen, "listen")
	case "node":
		if err := positive(map[string]time.Duration{"node_max_age": c.NodeMaxAge.D()}); err != nil {
			return err
		}
		if c.TotalBytes < 0 {
			return fmt.Errorf("total_bytes 不得为负")
		}
		if c.Master == "" || c.Advertise == "" || c.DataDir == "" || c.Label == "" {
			return fmt.Errorf("node 需要 master/advertise/data_dir/label")
		}
		if err := checkBind(c.Listen, "listen"); err != nil {
			return err
		}
		if c.UploadBPS == 0 || c.DownloadBPS == 0 {
			return fmt.Errorf("node 必须声明有限上下行预算（传输计划会派发确定速率）")
		}
		if c.UploadBPS > 1<<40 || c.DownloadBPS > 1<<40 {
			return fmt.Errorf("node 预算超出可信上限")
		}
		if c.TransferConcurrent < 1 || c.TransferConcurrent > 8 {
			return fmt.Errorf("transfer_concurrency 需在 1..8")
		}
	case "drive":
		if c.Master == "" || c.ReportPath == "" {
			return fmt.Errorf("drive 需要 master/report_path")
		}
		if len(c.Nodes) < 2 {
			return fmt.Errorf("drive 至少声明 2 个 nodes（label+addr+预算）")
		}
		seenLabel, seenAddr := map[string]bool{}, map[string]bool{}
		for _, n := range c.Nodes {
			if n.Label == "" || n.Addr == "" || seenLabel[n.Label] || seenAddr[n.Addr] {
				return fmt.Errorf("nodes 的 label/addr 必填且不得重复")
			}
			seenLabel[n.Label], seenAddr[n.Addr] = true, true
			if n.UploadBPS == 0 || n.DownloadBPS == 0 {
				return fmt.Errorf("node %s 必须声明 upload_bps/download_bps", n.Label)
			}
		}
		if !seenLabel[c.Ingress] {
			return fmt.Errorf("ingress %q 必须是 nodes 之一", c.Ingress)
		}
		if c.ClientUploadBPS == 0 || c.ClientDownloadBPS == 0 {
			return fmt.Errorf("drive 必须声明 client_upload_bps/client_download_bps")
		}
		if c.ClientConcurrent < 1 || c.ClientConcurrent > 4 {
			return fmt.Errorf("client_concurrent 需在 1..4")
		}
		for _, s := range c.Scenarios {
			if s != "one-ingress" && s != "protection" {
				return fmt.Errorf("未知场景 %q（支持 one-ingress|protection；fault 由主线程经 /lab/fault 手控）", s)
			}
		}
	default:
		return fmt.Errorf("role 必须是 master|node|drive")
	}
	return nil
}

// checkBind 拒绝通配监听：healthz 与 lab 路由虽有 token 门，但隔离纪律要求
// 显式绑定 mesh 域名/IP，绝不 0.0.0.0 暴露公网（公网 IP 是否合规由主线程核）。
func checkBind(addr, field string) error {
	if addr == "" {
		return fmt.Errorf("master/node 需要 %s（mesh 域名:端口）", field)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q 需要 host:port 形式", field, addr)
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return fmt.Errorf("%s 必须显式绑定 mesh 域名/IP，禁止通配地址", field)
	}
	return nil
}

func positive(values map[string]time.Duration) error {
	for name, d := range values {
		if d <= 0 {
			return fmt.Errorf("%s 必须为正时长", name)
		}
	}
	return nil
}
