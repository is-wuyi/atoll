package peerauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"atoll/pkg/edgeidentity"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func ValidateIdentity(id string, publicKey []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("peer identity requires an Ed25519 public key")
	}
	pub, err := crypto.UnmarshalEd25519PublicKey(publicKey)
	if err != nil {
		return err
	}
	expected, err := peer.IDFromPublicKey(pub)
	if err != nil || expected.String() != id {
		return errors.New("peer id does not match the public key")
	}
	return nil
}

func ValidID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	decoded, err := peer.Decode(id)
	return err == nil && decoded.String() == id
}

func ValidOperation(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func CanonicalOrigin(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.Opaque != "" || u.Path != "" && u.Path != "/" {
		return "", errors.New("peer authorization requires an exact HTTPS Master origin")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if !ValidNodeAddr(net.JoinHostPort(host, port)) {
		return "", errors.New("invalid peer Master origin")
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

func ValidNodeAddr(addr string) bool {
	if len(addr) > 253 || strings.ContainsAny(addr, " /\\?#@\t\r\n\x00") {
		return false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != port {
		return false
	}
	return net.ParseIP(host) != nil || validDNSHost(strings.ToLower(host))
}

func validDNSHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || host != strings.ToLower(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return false
			}
		}
	}
	return true
}

func NormalizeAddresses(addresses []string, publicOnly bool) ([]string, error) {
	if len(addresses) > MaxAddresses {
		return nil, errors.New("too many peer addresses")
	}
	out := make([]string, 0, len(addresses))
	seen := make(map[string]bool)
	for _, value := range addresses {
		if len(value) == 0 || len(value) > MaxAddressLength {
			return nil, errors.New("invalid peer address length")
		}
		address, err := ma.NewMultiaddr(value)
		if err != nil || address.String() != value {
			return nil, errors.New("noncanonical peer address")
		}
		protocols := address.Protocols()
		if len(protocols) < 2 || len(protocols) > 3 {
			return nil, errors.New("unsupported peer address shape")
		}
		first := protocols[0].Code
		if first != ma.P_IP4 && first != ma.P_IP6 && first != ma.P_DNS4 && first != ma.P_DNS6 {
			return nil, errors.New("unsupported peer address host")
		}
		if first == ma.P_DNS4 || first == ma.P_DNS6 {
			host, _ := address.ValueForProtocol(first)
			if publicOnly || !validDNSHost(host) {
				return nil, errors.New("peer DNS address is not allowed")
			}
		} else {
			host, _ := address.ValueForProtocol(first)
			ip := net.ParseIP(host)
			if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return nil, errors.New("unusable peer IP address")
			}
			_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
			if publicOnly && (ip.IsLoopback() || ip.IsPrivate() || cgnat.Contains(ip)) {
				return nil, errors.New("nonpublic peer address")
			}
		}
		transport := protocols[1].Code
		if transport == ma.P_TCP && len(protocols) != 2 || transport == ma.P_UDP && (len(protocols) != 3 || protocols[2].Code != ma.P_QUIC_V1) || transport != ma.P_TCP && transport != ma.P_UDP {
			return nil, errors.New("unsupported peer address transport")
		}
		port, _ := address.ValueForProtocol(transport)
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil || p == 0 || seen[value] {
			return nil, errors.New("invalid or duplicate peer address")
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func EnrollmentProof(challenge edgeidentity.Challenge) []byte {
	challenge.NotBefore = challenge.NotBefore.UTC()
	challenge.ExpiresAt = challenge.ExpiresAt.UTC()
	return proof("peer-enrollment", challenge)
}

func PublicationProof(origin string, nodeID uint64, req AddressPublication) ([]byte, error) {
	canonical, err := CanonicalOrigin(origin)
	if err != nil {
		return nil, err
	}
	addresses, err := NormalizeAddresses(req.Addresses, false)
	if err != nil || !ValidID(req.PeerID) || !ValidOperation(req.OperationID) || nodeID == 0 || req.BindingRevision == 0 || !RepresentableTime(req.NotAfter) {
		return nil, errors.New("invalid peer publication")
	}
	body := struct {
		Origin           string    `json:"origin"`
		NodeID           uint64    `json:"node_id"`
		PeerID           string    `json:"peer_id"`
		BindingRevision  uint64    `json:"binding_revision"`
		ExpectedRevision uint64    `json:"expected_revision"`
		OperationID      string    `json:"operation_id"`
		Addresses        []string  `json:"addresses"`
		NotAfter         time.Time `json:"not_after"`
	}{canonical, nodeID, req.PeerID, req.BindingRevision, req.ExpectedRevision, req.OperationID, addresses, req.NotAfter.UTC()}
	return proof("peer-address-publication", body), nil
}

func ClientProof(origin, session string, spaceID uint64, req ClientRegistration) ([]byte, error) {
	return clientProof("client-peer-registration", origin, session, spaceID, req)
}

func ClientReleaseProof(origin, session string, spaceID uint64, req ClientRegistration) ([]byte, error) {
	return clientProof("client-peer-release", origin, session, spaceID, req)
}

func clientProof(purpose, origin, session string, spaceID uint64, req ClientRegistration) ([]byte, error) {
	canonical, err := CanonicalOrigin(origin)
	if err != nil || session == "" || spaceID == 0 || !ValidOperation(req.OperationID) || req.NotAfter.IsZero() || !RepresentableTime(req.NotAfter) || ValidateIdentity(req.PeerID, req.PublicKey) != nil {
		return nil, errors.New("invalid client peer registration")
	}
	digest := sha256.Sum256([]byte(session))
	body := struct {
		Origin           string    `json:"origin"`
		SessionHash      string    `json:"session_hash"`
		SpaceID          uint64    `json:"space_id"`
		PeerID           string    `json:"peer_id"`
		PublicKey        []byte    `json:"public_key"`
		ExpectedRevision uint64    `json:"expected_revision"`
		OperationID      string    `json:"operation_id"`
		NotAfter         time.Time `json:"not_after"`
	}{canonical, hex.EncodeToString(digest[:]), spaceID, req.PeerID, req.PublicKey, req.ExpectedRevision, req.OperationID, req.NotAfter.UTC()}
	return proof(purpose, body), nil
}

func RepresentableTime(at time.Time) bool {
	return !at.IsZero() && time.Unix(0, at.UnixNano()).Equal(at)
}

func Verify(publicKey, message, signature []byte) bool {
	return len(publicKey) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

func EnrollmentExtras(enrollment *Enrollment) map[string]string {
	if enrollment == nil {
		return nil
	}
	digest := sha256.Sum256(enrollment.PublicKey)
	return map[string]string{"peer_id": enrollment.PeerID, "peer_public_key_sha256": hex.EncodeToString(digest[:]), "peer_expected_revision": strconv.FormatUint(enrollment.ExpectedRevision, 10)}
}

func ValidateDirectory(directory Directory, now time.Time) error {
	if directory.Protocol != Feature || len(directory.Endpoints) > MaxDirectoryPeers || ValidateIdentity(directory.Infrastructure.PeerID, directory.Infrastructure.PublicKey) != nil {
		return errors.New("invalid peer directory")
	}
	infraAddresses, err := NormalizeAddresses(directory.Infrastructure.Addresses, false)
	if err != nil || !equalAddresses(infraAddresses, directory.Infrastructure.Addresses) {
		return errors.New("invalid infrastructure peer addresses")
	}
	seenPeers := map[string]bool{directory.Infrastructure.PeerID: true}
	seenNodes := make(map[uint64]bool)
	seenAddresses := make(map[string]bool)
	for _, endpoint := range directory.Endpoints {
		if ValidateIdentity(endpoint.PeerID, endpoint.PublicKey) != nil || !RepresentableTime(endpoint.ValidUntil) || seenPeers[endpoint.PeerID] || !now.Before(endpoint.ValidUntil) || endpoint.ValidUntil.After(now.Add(3*time.Minute)) {
			return errors.New("invalid or stale peer endpoint")
		}
		seenPeers[endpoint.PeerID] = true
		addresses, err := NormalizeAddresses(endpoint.Addresses, false)
		if err != nil || !equalAddresses(addresses, endpoint.Addresses) {
			return errors.New("invalid peer endpoint addresses")
		}
		switch endpoint.Role {
		case RoleNode:
			if endpoint.NodeID == 0 || !ValidNodeAddr(endpoint.Addr) || endpoint.BindingRevision == 0 || endpoint.Revision == 0 || seenAddresses[endpoint.Addr] || seenNodes[endpoint.NodeID] {
				return errors.New("invalid node peer endpoint")
			}
			seenAddresses[endpoint.Addr] = true
			seenNodes[endpoint.NodeID] = true
		case RoleClient:
			if endpoint.NodeID != 0 || endpoint.Addr != "" || len(endpoint.Addresses) != 0 || endpoint.BindingRevision != 0 || endpoint.Revision == 0 {
				return errors.New("client peer cannot publish storage endpoints")
			}
		default:
			return errors.New("invalid peer endpoint role")
		}
	}
	return nil
}

func equalAddresses(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func proof(purpose string, value any) []byte {
	raw, _ := json.Marshal(value)
	var out bytes.Buffer
	out.WriteString("atoll-peer-proof-v1\x00")
	out.WriteString(purpose)
	out.WriteByte(0)
	out.Write(raw)
	return out.Bytes()
}
