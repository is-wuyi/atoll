package peerauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMaximumDirectoryFitsPublishedByteLimit(t *testing.T) {
	infraID, infraPub, _ := proofIdentity(t)
	directory := Directory{Protocol: Feature, Infrastructure: Infrastructure{PeerID: infraID, PublicKey: infraPub, Addresses: []string{}, Relay: true}}
	now := time.Now()
	for i := 0; i < MaxDirectoryPeers; i++ {
		id, pub, _ := proofIdentity(t)
		addresses := make([]string, MaxAddresses)
		for j := range addresses {
			host := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 56) + fmt.Sprintf("%02d", j)
			addresses[j] = "/dns4/" + host + "/tcp/9443"
		}
		normalized, err := NormalizeAddresses(addresses, false)
		if err != nil {
			t.Fatal(err)
		}
		directory.Endpoints = append(directory.Endpoints, Endpoint{NodeID: uint64(i + 1), Addr: fmt.Sprintf("node%d.test:9443", i), Role: RoleNode, PeerID: id, PublicKey: pub, BindingRevision: 1, Revision: 1, Addresses: normalized, ValidUntil: now.Add(time.Minute)})
	}
	if err := ValidateDirectory(directory, now); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 1<<20 || len(raw) > MaxDirectoryBytes {
		t.Fatalf("directory bytes=%d, expected greater than old 1MiB and within limit", len(raw))
	}
	var got Directory
	if err := DecodeJSONLimit(bytes.NewReader(raw), &got, MaxDirectoryBytes); err != nil {
		t.Fatal(err)
	}
	if len(got.Endpoints) != MaxDirectoryPeers {
		t.Fatal("directory truncated")
	}
}

func TestPeerDNSNamesRejectAmbiguity(t *testing.T) {
	for _, host := range []string{"UPPER.test", "double..test", "-leading.test", "trailing-.test", "quote\".test", "zero\x00.test", "tab\t.test", "tool<script>.test", strings.Repeat("a", 64) + ".test"} {
		if _, err := NormalizeAddresses([]string{"/dns4/" + host + "/tcp/9443"}, false); err == nil {
			t.Fatalf("noncanonical DNS host accepted: %q", host)
		}
	}
	if _, err := NormalizeAddresses([]string{"/dns4/node.example/tcp/9443"}, false); err != nil {
		t.Fatal(err)
	}
}
