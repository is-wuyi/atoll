package peerauth

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPeerJSONRejectsAmbiguityAndUnknownFields(t *testing.T) {
	for _, raw := range []string{
		`{"peer_id":"first","peer_id":"second"}`,
		`{"Peer_ID":"first"}`,
		`{"peer_id":null}`,
		`{"peer_id":"first","unexpected":1}`,
		`{"peer_id":"first"} {"peer_id":"second"}`,
		`null`,
		`{"addresses":[null]}`,
		strings.Repeat(" ", MaxJSONBytes+1),
	} {
		var out AddressPublication
		if err := DecodeJSON(strings.NewReader(raw), &out); err == nil {
			t.Fatalf("invalid authorization JSON accepted: %s", raw[:min(len(raw), 100)])
		}
	}
}

func TestPeerJSONPreservesPublicationZeroCAS(t *testing.T) {
	var out AddressPublication
	if err := DecodeJSON(strings.NewReader(`{"peer_id":"first","binding_revision":1,"expected_revision":0,"operation_id":"operation","addresses":[],"not_after":"2026-10-29T12:00:00Z","signature":""}`), &out); err != nil {
		t.Fatal(err)
	}
	if out.ExpectedRevision != 0 || out.PeerID != "first" || len(out.Addresses) != 0 {
		t.Fatal("decoder changed the request fields")
	}
}

func TestPeerJSONRequiresExplicitRevisionAndProofFields(t *testing.T) {
	client := ClientRegistration{PeerID: "first", PublicKey: []byte{1}, ExpectedRevision: 0, OperationID: "operation", NotAfter: time.Now().UTC(), Signature: []byte{1}}
	publication := AddressPublication{PeerID: "first", BindingRevision: 1, ExpectedRevision: 0, OperationID: "operation", Addresses: []string{}, NotAfter: time.Now().UTC(), Signature: []byte{1}}
	for _, test := range []struct {
		name       string
		value      any
		makeOutput func() any
		fields     []string
	}{
		{"client", client, func() any { return new(ClientRegistration) }, []string{"peer_id", "public_key", "expected_revision", "operation_id", "not_after", "signature"}},
		{"publication", publication, func() any { return new(AddressPublication) }, []string{"peer_id", "binding_revision", "expected_revision", "operation_id", "addresses", "not_after", "signature"}},
	} {
		raw, err := json.Marshal(test.value)
		if err != nil {
			t.Fatal(err)
		}
		if err := DecodeJSON(bytes.NewReader(raw), test.makeOutput()); err != nil {
			t.Fatal(err)
		}
		for _, field := range test.fields {
			t.Run(test.name+"/"+field, func(t *testing.T) {
				var values map[string]json.RawMessage
				if err := json.Unmarshal(raw, &values); err != nil {
					t.Fatal(err)
				}
				delete(values, field)
				missing, err := json.Marshal(values)
				if err != nil {
					t.Fatal(err)
				}
				if DecodeJSON(bytes.NewReader(missing), test.makeOutput()) == nil {
					t.Fatal("missing proof binding field accepted")
				}
			})
		}
	}
}

func TestPeerJSONRejectsNestedDuplicateFields(t *testing.T) {
	var out struct {
		Peer Enrollment `json:"peer"`
	}
	if err := DecodeJSON(strings.NewReader(`{"peer":{"peer_id":"a","peer_id":"b"}}`), &out); err == nil {
		t.Fatal("nested duplicate authentication fields accepted")
	}
}

func TestPeerJSONExplicitLimitSupportsBoundedDirectoryResponses(t *testing.T) {
	raw := `{"payload":"` + strings.Repeat("x", MaxJSONBytes) + `"}`
	var out struct {
		Payload string `json:"payload"`
	}
	if DecodeJSON(strings.NewReader(raw), &out) == nil {
		t.Fatal("default limit accepted oversized response")
	}
	if err := DecodeJSONLimit(strings.NewReader(raw), &out, 1<<20); err != nil {
		t.Fatal(err)
	}
	if len(out.Payload) != MaxJSONBytes {
		t.Fatal("large bounded response truncated")
	}
	for _, limit := range []int64{-1, 0, MaxDirectoryBytes + 1, 32} {
		if DecodeJSONLimit(strings.NewReader(raw), &out, limit) == nil {
			t.Fatal("invalid or insufficient limit accepted")
		}
	}
	if DecodeJSONLimit(strings.NewReader(`{"payload":"a","payload":"b"}`), &out, 1<<20) == nil {
		t.Fatal("custom limit skipped strict ambiguity check")
	}
}

func TestPeerTimeRepresentationRejectsWrappedExpiry(t *testing.T) {
	id, pub, _ := proofIdentity(t)
	var req ClientRegistration
	if err := json.Unmarshal([]byte(`{"not_after":"2500-01-01T00:00:00Z"}`), &req); err != nil {
		t.Fatal(err)
	}
	req.PeerID, req.PublicKey, req.OperationID = id, pub, "0123456789abcdef0123456789abcdef"
	if _, err := ClientProof("https://master.test", "private-session", 1, req); err == nil {
		t.Fatal("wrapped expiry accepted in client registration proof")
	}
	if _, err := PublicationProof("https://master.test", 1, AddressPublication{PeerID: id, BindingRevision: 1, OperationID: req.OperationID, NotAfter: req.NotAfter}); err == nil {
		t.Fatal("wrapped expiry accepted in node address proof")
	}
}

func TestPeerProofDoesNotRetainCallerSignature(t *testing.T) {
	id, pub, _ := proofIdentity(t)
	req := ClientRegistration{PeerID: id, PublicKey: pub, OperationID: "0123456789abcdef0123456789abcdef"}
	if err := json.Unmarshal([]byte(`{"not_after":"2026-10-29T12:00:00Z"}`), &req); err != nil {
		t.Fatal(err)
	}
	first, err := ClientProof("https://master.test", "private-session", 1, req)
	if err != nil {
		t.Fatal(err)
	}
	req.Signature = bytes.Repeat([]byte{42}, 64)
	second, err := ClientProof("https://master.test", "private-session", 1, req)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("signature became part of its own signed message")
	}
}
