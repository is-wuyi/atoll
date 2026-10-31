package peerauth

import "testing"

func TestPeerDirectoryCopyDoesNotAliasCallerSlices(t *testing.T) {
	directory := Directory{
		Infrastructure: Infrastructure{PublicKey: []byte{1}, Addresses: []string{"infrastructure"}},
		Endpoints:      []Endpoint{{PublicKey: []byte{2}, Addresses: []string{"endpoint"}}},
	}
	copy := CopyDirectory(directory)
	directory.Infrastructure.PublicKey[0] = 9
	directory.Infrastructure.Addresses[0] = "changed"
	directory.Endpoints[0].PublicKey[0] = 9
	directory.Endpoints[0].Addresses[0] = "changed"
	if copy.Infrastructure.PublicKey[0] != 1 || copy.Infrastructure.Addresses[0] != "infrastructure" || copy.Endpoints[0].PublicKey[0] != 2 || copy.Endpoints[0].Addresses[0] != "endpoint" {
		t.Fatal("directory snapshot retained caller-owned slices")
	}
}

func TestPeerDirectoryCopyPreservesEmptyJSONArrays(t *testing.T) {
	copy := CopyDirectory(Directory{})
	if copy.Endpoints == nil || copy.Infrastructure.Addresses == nil {
		t.Fatal("empty directory slices would encode as null")
	}
}

func TestPeerBindingsCompareIdentityKeyAndRevision(t *testing.T) {
	left := &Binding{PeerID: "peer", PublicKey: []byte{1, 2}, Revision: 1}
	right := &Binding{PeerID: "peer", PublicKey: []byte{1, 2}, Revision: 1}
	if !SameBinding(left, right) || !SameBinding(nil, nil) || SameBinding(nil, left) {
		t.Fatal("equal bindings did not compare consistently")
	}
	right.Revision++
	if SameBinding(left, right) {
		t.Fatal("binding revision was ignored")
	}
	right.Revision = left.Revision
	right.PublicKey[0]++
	if SameBinding(left, right) {
		t.Fatal("binding public key was ignored")
	}
}
