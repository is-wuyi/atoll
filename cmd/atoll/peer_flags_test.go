package main

import (
	"flag"
	"strings"
	"testing"
)

func p2pTestFlags(enabled bool) *p2pCLIFlags {
	fs := flag.NewFlagSet("p2p-test", flag.ContinueOnError)
	p := addP2PFlags(fs)
	*p.enabled = enabled
	return p
}

// listen: bind addresses may be unspecified and ephemeral; TCP and QUIC both
// accepted; DNS names are not bind addresses.
func TestP2PListenAddresses(t *testing.T) {
	p := p2pTestFlags(true)
	for _, addr := range []string{
		"/ip4/0.0.0.0/tcp/0",
		"/ip6/::/tcp/0",
		"/ip4/127.0.0.1/tcp/7000",
		"/ip4/0.0.0.0/udp/0/quic-v1",
	} {
		if err := p.listen.Set(addr); err != nil {
			t.Fatalf("listen %q rejected: %v", addr, err)
		}
	}
	for _, addr := range []string{
		"/dns4/example.com/tcp/1", // bind cannot be DNS
		"/ip4/1.2.3.4/tcp/0/x",    // trailing junk
		"/ip4/1.2.3.4/http",       // wrong transport
		"/ip4/::1/tcp/1",          // IPv4 family with IPv6 literal
		"/ip6/127.0.0.1/tcp/1",    // IPv6 family with IPv4 literal
	} {
		if err := p.listen.Set(addr); err == nil {
			t.Fatalf("listen %q should be rejected", addr)
		}
	}
}

// announce: noncanonical or unusable addresses are refused; DNS is allowed.
func TestP2PAnnounceAddresses(t *testing.T) {
	p := p2pTestFlags(true)
	for _, addr := range []string{
		"/ip4/192.0.2.5/tcp/7000",
		"/ip6/2001:db8::5/udp/7000/quic-v1",
		"/dns4/node.example.com/tcp/7000",
	} {
		if err := p.announce.Set(addr); err != nil {
			t.Fatalf("announce %q rejected: %v", addr, err)
		}
	}
	for _, addr := range []string{
		"/ip4/192.0.2.5/tcp/0",     // port 0 is not advertisable
		"/ip4/0.0.0.0/tcp/7000",    // unspecified is not advertisable
		"/ip4/192.0.2.5/udp/7000",  // UDP without quic-v1
		"/ip4/192.0.2.5/tcp/70000", // port out of range
	} {
		if err := p.announce.Set(addr); err == nil {
			t.Fatalf("announce %q should be rejected", addr)
		}
	}
}

// public-only blocks loopback/private/CGNAT announce addresses up front, before
// any component is constructed.
func TestP2PAnnouncePublicOnly(t *testing.T) {
	p := p2pTestFlags(true)
	*p.publicOnly = true
	if err := p.announce.Set("/ip4/192.0.2.5/tcp/7000"); err != nil {
		t.Fatalf("public announce rejected: %v", err)
	}
	// A private address must fail at Set time only if it is syntactically valid
	// but non-public; Set itself does not apply public-only, so the preflight in
	// validateP2PAnnounce is what rejects it. Build the value directly.
	p2 := p2pTestFlags(true)
	*p2.publicOnly = true
	if err := p2.announce.Set("/ip4/127.0.0.1/tcp/7000"); err != nil {
		t.Fatalf("loopback announce Set failed (semantic check is preflight): %v", err)
	}
	if err := validateP2PFlags(p2); err == nil {
		t.Fatal("public-only loopback announce should be rejected by preflight")
	}
	// Without public-only, loopback is allowed (local test harness).
	p3 := p2pTestFlags(true)
	if err := p3.announce.Set("/ip4/127.0.0.1/tcp/7000"); err != nil {
		t.Fatalf("loopback announce without public-only rejected: %v", err)
	}
	if err := validateP2PFlags(p3); err != nil {
		t.Fatalf("loopback announce should pass without public-only: %v", err)
	}
}

func TestP2PDuplicatesAndCount(t *testing.T) {
	p := p2pTestFlags(true)
	if err := p.listen.Set("/ip4/0.0.0.0/tcp/0,/ip4/0.0.0.0/tcp/0"); err == nil {
		t.Fatal("duplicate listen address should be rejected")
	}
	q := p2pTestFlags(true)
	for i := 1; i <= peerauthMaxAddressesForTest(); i++ {
		addr := testAnnounceAddr(i)
		if err := q.announce.Set(addr); err != nil {
			t.Fatalf("address %d rejected: %v", i, err)
		}
	}
	// MaxAddresses is 16; a 17th distinct value must be rejected.
	if err := q.announce.Set(testAnnounceAddr(17)); err == nil {
		t.Fatal("17th announce address should be rejected")
	}
}

func testAnnounceAddr(i int) string {
	return "/ip4/10.0." + string(rune('0'+i/10)) + "." + string(rune('0'+i%10)) + "/tcp/" + intString(1000+i)
}

func intString(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func peerauthMaxAddressesForTest() int { return 16 }

// client peer requires a secure session, nonzero space and an exact HTTPS
// master origin; announce/public-only preflight applies before anything else.
func TestP2PClientPreflight(t *testing.T) {
	base := func() *p2pCLIFlags { return p2pTestFlags(true) }

	p := base()
	*p.publicOnly = true
	if err := p.announce.Set("/ip4/127.0.0.1/tcp/7000"); err != nil {
		t.Fatal(err)
	}
	// public-only + private announce must fail even with valid session/space.
	if err := validateClientP2P(p, "https://127.0.0.1:9420", "sess", 7, false, false); err == nil {
		t.Fatal("client with public-only private announce should be rejected")
	}

	// Missing session or space.
	if err := validateClientP2P(base(), "https://127.0.0.1:9420", "", 7, false, false); err == nil {
		t.Fatal("client without session should be rejected")
	}
	if err := validateClientP2P(base(), "https://127.0.0.1:9420", "sess", 0, false, false); err == nil {
		t.Fatal("client without space should be rejected")
	}
	// Insecure transport must be refused.
	if err := validateClientP2P(base(), "https://127.0.0.1:9420", "sess", 7, true, false); err == nil {
		t.Fatal("client with allow-insecure should be rejected")
	}

	// Origin must be canonical HTTPS. Every disambiguating URL form is refused.
	for _, origin := range []string{
		"http://127.0.0.1:9420",       // wrong scheme
		"https://127.0.0.1:9420/?x=1", // raw query
		"https://127.0.0.1:9420/?",    // ForceQuery
		"https://127.0.0.1:9420/a",    // path
		"https://user@127.0.0.1:9420", // userinfo
		"https://127.0.0.1:9420#frag", // fragment
	} {
		if err := validateClientP2P(base(), origin, "sess", 7, false, false); err == nil {
			t.Fatalf("client origin %q should be rejected", origin)
		}
	}
	if err := validateClientP2P(base(), "https://127.0.0.1:9420", "sess", 7, false, false); err != nil {
		t.Fatalf("client canonical origin should pass: %v", err)
	}
}

// master peer requires secure + verified TLS + write planning + exact origin.
func TestP2PMasterPreflight(t *testing.T) {
	ok := func() *p2pCLIFlags { return p2pTestFlags(true) }
	origin := "https://127.0.0.1:9420"
	if err := validateMasterP2P(ok(), origin, true, false, false, true); err != nil {
		t.Fatalf("valid master p2p rejected: %v", err)
	}
	if err := validateMasterP2P(ok(), origin, false, false, false, true); err == nil {
		t.Fatal("master without secure should be rejected")
	}
	if err := validateMasterP2P(ok(), origin, true, false, false, false); err == nil {
		t.Fatal("master without write planning should be rejected")
	}
	if err := validateMasterP2P(ok(), origin, true, true, false, true); err == nil {
		t.Fatal("master with allow-insecure should be rejected")
	}
	if err := validateMasterP2P(ok(), origin, true, false, true, true); err == nil {
		t.Fatal("master with tls-skip should be rejected")
	}
	if err := validateMasterP2P(ok(), "http://127.0.0.1:9420", true, false, false, true); err == nil {
		t.Fatal("master with non-HTTPS origin should be rejected")
	}
}

// node peer requires secure + verified TLS certificates.
func TestP2PNodePreflight(t *testing.T) {
	ok := func() *p2pCLIFlags { return p2pTestFlags(true) }
	if err := validateNodeP2P(ok(), true, false, false, "cert", "key"); err != nil {
		t.Fatalf("valid node p2p rejected: %v", err)
	}
	if err := validateNodeP2P(ok(), false, false, false, "cert", "key"); err == nil {
		t.Fatal("node without secure should be rejected")
	}
	if err := validateNodeP2P(ok(), true, false, false, "", "key"); err == nil {
		t.Fatal("node without cert should be rejected")
	}
	if err := validateNodeP2P(ok(), true, true, false, "cert", "key"); err == nil {
		t.Fatal("node with allow-insecure should be rejected")
	}
}

// disabled p2p must not trip any preflight.
func TestP2PDisabledSkipsPreflight(t *testing.T) {
	p := p2pTestFlags(false)
	if err := validateMasterP2P(p, "", false, false, false, false); err != nil {
		t.Fatalf("disabled master p2p should pass: %v", err)
	}
	if err := validateClientP2P(p, "http://127.0.0.1:1", "", 0, false, false); err != nil {
		t.Fatalf("disabled client p2p should pass: %v", err)
	}
	if err := validateNodeP2P(p, false, false, false, "", ""); err != nil {
		t.Fatalf("disabled node p2p should pass: %v", err)
	}
}

// announce helper must be reachable via repeated and comma-separated flags.
func TestP2PStringListCommaAndRepeat(t *testing.T) {
	p := p2pTestFlags(true)
	if err := p.announce.Set("/ip4/192.0.2.1/tcp/1,/ip4/192.0.2.2/tcp/2"); err != nil {
		t.Fatalf("comma-separated announce rejected: %v", err)
	}
	if err := p.announce.Set("/ip4/192.0.2.3/tcp/3"); err != nil {
		t.Fatalf("repeated announce rejected: %v", err)
	}
	got := strings.Join(p.announceAddresses(), ",")
	want := "/ip4/192.0.2.1/tcp/1,/ip4/192.0.2.2/tcp/2,/ip4/192.0.2.3/tcp/3"
	if got != want {
		t.Fatalf("announce addresses = %q, want %q", got, want)
	}
}
