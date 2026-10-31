package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"

	"atoll/pkg/peerauth"
	ma "github.com/multiformats/go-multiaddr"
)

const defaultP2PListen = "/ip4/0.0.0.0/tcp/0"

// p2pStringList accepts both repeated flags and comma-separated values. Keeping
// raw values as canonical multiaddrs lets peertransport perform the same
// validation when it learns addresses at runtime.
type p2pStringList struct {
	values         []string
	allowEphemeral bool
	allowDNS       bool
}

func (v *p2pStringList) String() string {
	return strings.Join(v.values, ",")
}

func (v *p2pStringList) Set(raw string) error {
	parts := strings.Split(raw, ",")
	if len(parts) == 0 {
		return errors.New("empty peer address")
	}
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			return errors.New("empty peer address")
		}
		if err := validateP2PMultiaddr(value, v.allowEphemeral, v.allowDNS); err != nil {
			return err
		}
		for _, existing := range v.values {
			if existing == value {
				return fmt.Errorf("duplicate peer address %q", value)
			}
		}
		if len(v.values) >= peerauth.MaxAddresses {
			return fmt.Errorf("too many peer addresses (maximum %d)", peerauth.MaxAddresses)
		}
		v.values = append(v.values, value)
	}
	return nil
}

func (v *p2pStringList) clone() []string {
	return append([]string(nil), v.values...)
}

type p2pCLIFlags struct {
	enabled    *bool
	listen     p2pStringList
	announce   p2pStringList
	identity   *string
	publicOnly *bool
}

func addP2PFlags(fs *flag.FlagSet) *p2pCLIFlags {
	p := &p2pCLIFlags{}
	p.enabled = fs.Bool("p2p", false, "启用安全 peer 数据面")
	p.listen.allowEphemeral = true
	fs.Var(&p.listen, "p2p-listen", "peer 监听 multiaddr（可重复或逗号分隔；默认 /ip4/0.0.0.0/tcp/0）")
	p.announce.allowDNS = true
	fs.Var(&p.announce, "p2p-announce", "覆盖自动发现的 peer 公布 multiaddr（可重复或逗号分隔）")
	p.identity = fs.String("p2p-identity", "", "peer 持久身份文件（空 = 使用角色默认路径；用户客户端为空时使用临时身份）")
	p.publicOnly = fs.Bool("p2p-public-only", false, "只允许公布和使用公共 peer 地址")
	return p
}

func (p *p2pCLIFlags) listenAddresses() []string {
	if len(p.listen.values) == 0 {
		return []string{defaultP2PListen}
	}
	return p.listen.clone()
}

func (p *p2pCLIFlags) announceAddresses() []string {
	return p.announce.clone()
}

func (p *p2pCLIFlags) identityPath(defaultPath string) string {
	if p.identity != nil && *p.identity != "" {
		return *p.identity
	}
	return defaultPath
}

func (p *p2pCLIFlags) enabledValue() bool {
	return p != nil && p.enabled != nil && *p.enabled
}

// validateMaster checks CLI-only invariants before the master opens its
// database or starts any worker. The peer directory is an HTTPS proof surface,
// so the origin must be explicit rather than inferred from a listen address.
func validateMasterP2P(p *p2pCLIFlags, origin string, secure, allowInsecure, tlsSkip, writePlanning bool) error {
	if p == nil || !p.enabledValue() {
		return nil
	}
	if err := validateP2PFlags(p); err != nil {
		return err
	}
	if !secure {
		return errors.New("-p2p requires -secure")
	}
	if allowInsecure || tlsSkip {
		return errors.New("-p2p requires verified TLS and rejects -allow-insecure/-tls-skip-verify")
	}
	if !writePlanning {
		return errors.New("-p2p requires -write-planning")
	}
	if _, err := peerauth.CanonicalOrigin(origin); err != nil {
		return fmt.Errorf("-p2p-origin: %w", err)
	}
	return nil
}

func validateNodeP2P(p *p2pCLIFlags, secure, allowInsecure, tlsSkip bool, certFile, keyFile string) error {
	if p == nil || !p.enabledValue() {
		return nil
	}
	if err := validateP2PFlags(p); err != nil {
		return err
	}
	if !secure {
		return errors.New("-p2p requires -secure")
	}
	if allowInsecure || tlsSkip || certFile == "" || keyFile == "" {
		return errors.New("-p2p requires verified TLS certificates and rejects -allow-insecure/-tls-skip-verify")
	}
	return nil
}

func validateClientP2P(p *p2pCLIFlags, masterURL, session string, space uint64, allowInsecure, tlsSkip bool) error {
	if p == nil || !p.enabledValue() {
		return nil
	}
	if err := validateP2PFlags(p); err != nil {
		return err
	}
	if session == "" || space == 0 {
		return errors.New("-p2p requires a secure session and nonzero -space")
	}
	if allowInsecure || tlsSkip {
		return errors.New("-p2p requires verified TLS and rejects -allow-insecure/-tls-skip-verify")
	}
	if _, err := peerauth.CanonicalOrigin(masterURL); err != nil {
		return fmt.Errorf("-p2p master: %w", err)
	}
	return nil
}

func validateP2PAnnounce(p *p2pCLIFlags) error {
	if p == nil || !p.enabledValue() || len(p.announce.values) == 0 {
		return nil
	}
	addresses, err := peerauth.NormalizeAddresses(p.announce.values, p.publicOnly != nil && *p.publicOnly)
	if err != nil {
		return fmt.Errorf("-p2p-announce: %w", err)
	}
	if len(addresses) != len(p.announce.values) {
		return errors.New("-p2p-announce contains duplicate addresses")
	}
	return nil
}

func validateP2PFlags(p *p2pCLIFlags) error {
	if p == nil || !p.enabledValue() {
		return nil
	}
	return validateP2PAnnounce(p)
}

func validateP2PMultiaddr(value string, allowEphemeral, allowDNS bool) error {
	address, err := ma.NewMultiaddr(value)
	if err != nil || address.String() != value {
		return fmt.Errorf("invalid peer multiaddr %q", value)
	}
	protocols := address.Protocols()
	if len(protocols) < 2 || len(protocols) > 3 {
		return fmt.Errorf("unsupported peer multiaddr shape %q", value)
	}
	first := protocols[0].Code
	isIP := first == ma.P_IP4 || first == ma.P_IP6
	isDNS := first == ma.P_DNS4 || first == ma.P_DNS6
	if !isIP && (!allowDNS || !isDNS) {
		return fmt.Errorf("peer multiaddr %q must use ip4/ip6", value)
	}
	transport := protocols[1].Code
	if transport != ma.P_TCP && transport != ma.P_UDP {
		return fmt.Errorf("peer multiaddr %q must use tcp or quic-v1", value)
	}
	if transport == ma.P_TCP && len(protocols) != 2 || transport == ma.P_UDP && (len(protocols) != 3 || protocols[2].Code != ma.P_QUIC_V1) {
		return fmt.Errorf("peer multiaddr %q has an invalid transport shape", value)
	}
	port, err := address.ValueForProtocol(transport)
	if err != nil {
		return fmt.Errorf("peer multiaddr %q has no port", value)
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || (!allowEphemeral && portNumber == 0) {
		return fmt.Errorf("peer multiaddr %q has an invalid port", value)
	}
	if isIP {
		host, err := address.ValueForProtocol(first)
		if err != nil {
			return fmt.Errorf("peer multiaddr %q has no host", value)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("peer multiaddr %q has an invalid IP address", value)
		}
		// announce (allowEphemeral=false) must not advertise unspecified or
		// multicast/broadcast addresses; listen (allowEphemeral=true) may bind them.
		if !allowEphemeral && (ip.IsUnspecified() || ip.IsMulticast()) {
			return fmt.Errorf("peer multiaddr %q is not an advertisable address", value)
		}
	}
	return nil
}
