package peerauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"atoll/pkg/edgeidentity"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func proofIdentity(t *testing.T) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return id.String(), pub, priv
}

func TestPeerIdentityBindsExactPublicKey(t *testing.T) {
	id, pub, _ := proofIdentity(t)
	_, other, _ := proofIdentity(t)
	if err := ValidateIdentity(id, pub); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id  string
		pub []byte
	}{{id, other}, {id, pub[:31]}, {"invalid", pub}, {id + " ", pub}} {
		if ValidateIdentity(tc.id, tc.pub) == nil {
			t.Fatal("invalid peer identity was accepted")
		}
	}
}

func TestPeerAddressesAreBoundedCanonicalAndClassified(t *testing.T) {
	addresses := []string{"/ip6/::1/udp/9400/quic-v1", "/ip4/127.0.0.1/tcp/9400"}
	normalized, err := NormalizeAddresses(addresses, false)
	if err != nil || !reflect.DeepEqual(normalized, []string{addresses[1], addresses[0]}) {
		t.Fatalf("address normalization: %v %v", normalized, err)
	}
	if addresses[0] != "/ip6/::1/udp/9400/quic-v1" {
		t.Fatal("normalization mutated the caller's slice")
	}
	for _, address := range []string{
		"/ip4/0.0.0.0/tcp/9400", "/ip4/239.0.0.1/tcp/9400", "/ip4/169.254.0.1/tcp/9400",
		"/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/udp/9400", "/ip4/127.0.0.1/tcp/9400/ws",
		"/dnsaddr/example.test", "/unix/tmp/peer.sock", "/ip6/fe80::1/tcp/9400",
	} {
		if _, err := NormalizeAddresses([]string{address}, false); err == nil {
			t.Fatalf("unsupported address accepted: %s", address)
		}
	}
	if _, err := NormalizeAddresses([]string{addresses[0], addresses[0]}, false); err == nil {
		t.Fatal("duplicate addresses accepted")
	}
	if _, err := NormalizeAddresses(make([]string, MaxAddresses+1), false); err == nil {
		t.Fatal("unbounded address set accepted")
	}
	for _, address := range []string{
		"/ip4/127.0.0.1/tcp/9400", "/ip4/10.1.1.1/tcp/9400", "/ip4/100.64.0.1/tcp/9400",
		"/ip6/fd00::1/tcp/9400", "/dns4/example.test/tcp/9400",
	} {
		if _, err := NormalizeAddresses([]string{address}, true); err == nil {
			t.Fatalf("nonpublic address accepted by public policy: %s", address)
		}
	}
	if _, err := NormalizeAddresses([]string{"/ip4/8.8.8.8/tcp/9400"}, true); err != nil {
		t.Fatal(err)
	}
}

func TestPeerPublicationProofBindsOriginNodeAndRevision(t *testing.T) {
	id, pub, priv := proofIdentity(t)
	req := AddressPublication{PeerID: id, BindingRevision: 2, ExpectedRevision: 3, OperationID: "0123456789abcdef0123456789abcdef", Addresses: []string{"/ip4/127.0.0.1/tcp/9400"}, NotAfter: time.Now().UTC().Add(time.Minute)}
	message, err := PublicationProof("https://master.test", 7, req)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, message)
	if !Verify(pub, message, sig) {
		t.Fatal("valid publication proof rejected")
	}
	for _, mutate := range []func(*AddressPublication){
		func(r *AddressPublication) { r.BindingRevision++ },
		func(r *AddressPublication) { r.ExpectedRevision++ },
		func(r *AddressPublication) { r.NotAfter = r.NotAfter.Add(time.Second) },
		func(r *AddressPublication) { r.OperationID = "1123456789abcdef0123456789abcdef" },
		func(r *AddressPublication) { r.Addresses = []string{"/ip4/127.0.0.1/tcp/9401"} },
	} {
		changed := req
		mutate(&changed)
		other, err := PublicationProof("https://master.test", 7, changed)
		if err != nil || Verify(pub, other, sig) {
			t.Fatalf("changed publication binding accepted: %v", err)
		}
	}
	for _, tc := range []struct {
		origin string
		node   uint64
	}{{"https://other.test", 7}, {"https://master.test", 8}} {
		other, err := PublicationProof(tc.origin, tc.node, req)
		if err != nil || Verify(pub, other, sig) {
			t.Fatalf("proof replayed to another authority or node: %v", err)
		}
	}
	canonical, err := PublicationProof("https://MASTER.test:443/", 7, req)
	if err != nil || !bytes.Equal(canonical, message) {
		t.Fatal("equivalent canonical origins produced different proofs")
	}
}

func TestClientPeerProofBindsSessionSpaceAndExpiry(t *testing.T) {
	id, pub, priv := proofIdentity(t)
	req := ClientRegistration{PeerID: id, PublicKey: pub, OperationID: "0123456789abcdef0123456789abcdef", NotAfter: time.Now().UTC().Add(time.Minute)}
	message, err := ClientProof("https://master.test", "private-session", 2, req)
	if err != nil || bytes.Contains(message, []byte("private-session")) {
		t.Fatalf("client proof exposed its session: %v", err)
	}
	sig := ed25519.Sign(priv, message)
	if !Verify(pub, message, sig) {
		t.Fatal("valid client proof rejected")
	}
	for _, tc := range []struct {
		origin  string
		session string
		space   uint64
	}{{"https://other.test", "private-session", 2}, {"https://master.test", "other-session", 2}, {"https://master.test", "private-session", 3}} {
		other, err := ClientProof(tc.origin, tc.session, tc.space, req)
		if err != nil || Verify(pub, other, sig) {
			t.Fatalf("client registration replayed with different binding: %v", err)
		}
	}
	changed := req
	changed.ExpectedRevision++
	other, _ := ClientProof("https://master.test", "private-session", 2, changed)
	if Verify(pub, other, sig) {
		t.Fatal("client registration revision was not signed")
	}
	changed = req
	changed.NotAfter = changed.NotAfter.Add(time.Second)
	other, _ = ClientProof("https://master.test", "private-session", 2, changed)
	if Verify(pub, other, sig) {
		t.Fatal("client registration expiry was not signed")
	}
}

func TestEnrollmentProofHasDistinctDomainAndDeterministicTime(t *testing.T) {
	id, pub, priv := proofIdentity(t)
	now := time.Now()
	challenge := edgeidentity.Challenge{Nonce: bytes.Repeat([]byte{1}, 32), Audience: "atoll-master-device-v1", Purpose: "node-session", NotBefore: now, ExpiresAt: now.Add(time.Minute), Extras: EnrollmentExtras(&Enrollment{PeerID: id, PublicKey: pub, ExpectedRevision: 2})}
	message := EnrollmentProof(challenge)
	sig := ed25519.Sign(priv, message)
	challenge.NotBefore = challenge.NotBefore.UTC()
	challenge.ExpiresAt = challenge.ExpiresAt.UTC()
	if !Verify(pub, EnrollmentProof(challenge), sig) {
		t.Fatal("time zone normalization changed enrollment proof")
	}
	challenge.Extras["peer_expected_revision"] = "3"
	if Verify(pub, EnrollmentProof(challenge), sig) {
		t.Fatal("enrollment proof did not bind expected revision")
	}
	if bytes.Equal(message, proof("client-peer-registration", challenge)) {
		t.Fatal("enrollment and client proof domains overlap")
	}
	challenge.Extras["peer_expected_revision"] = "2"
	challenge.Audience = "https://other-master.test:443"
	if Verify(pub, EnrollmentProof(challenge), sig) {
		t.Fatal("enrollment proof did not bind the Master audience")
	}
}

func TestPeerDirectoryRejectsStaleDuplicateAndCrossRoleEntries(t *testing.T) {
	infraID, infraPub, _ := proofIdentity(t)
	id, pub, _ := proofIdentity(t)
	now := time.Now()
	entry := Endpoint{Role: RoleNode, NodeID: 7, Addr: "node.test:9443", PeerID: id, PublicKey: pub, BindingRevision: 1, Revision: 1, Addresses: []string{"/ip4/127.0.0.1/tcp/9400"}, ValidUntil: now.Add(time.Minute)}
	base := Directory{Protocol: Feature, Infrastructure: Infrastructure{PeerID: infraID, PublicKey: infraPub, Relay: true}, Endpoints: []Endpoint{entry}}
	if err := ValidateDirectory(base, now); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*Endpoint){
		func(e *Endpoint) { e.ValidUntil = now },
		func(e *Endpoint) { e.BindingRevision = 0 },
		func(e *Endpoint) { e.NodeID = 0 },
		func(e *Endpoint) { e.Role = RoleClient },
		func(e *Endpoint) { e.PeerID = infraID; e.PublicKey = infraPub },
	} {
		bad := base
		bad.Endpoints = []Endpoint{entry}
		mutation(&bad.Endpoints[0])
		if ValidateDirectory(bad, now) == nil {
			t.Fatal("invalid directory endpoint accepted")
		}
	}
	bad := base
	bad.Endpoints = []Endpoint{entry, entry}
	if ValidateDirectory(bad, now) == nil {
		t.Fatal("duplicate peer accepted")
	}
	client := base
	client.Endpoints = []Endpoint{{Role: RoleClient, PeerID: id, PublicKey: pub, Revision: 1, ValidUntil: now.Add(time.Minute)}}
	if err := ValidateDirectory(client, now); err != nil {
		t.Fatal(err)
	}
	client.Endpoints[0].Revision = 0
	if ValidateDirectory(client, now) == nil {
		t.Fatal("client directory entry without registration revision accepted")
	}
}

func TestPeerProofOriginRejectsAmbiguousURLs(t *testing.T) {
	for _, origin := range []string{"http://master.test", "https://user@master.test", "https://master.test/path", "https://master.test?", "https://master.test#fragment", "https://master.test:0", "https://master.test:0443"} {
		if _, err := CanonicalOrigin(origin); err == nil {
			t.Fatalf("ambiguous origin accepted: %s", origin)
		}
	}
}
