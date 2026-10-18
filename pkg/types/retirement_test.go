package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRetirementJSONRequiresExactFields(t *testing.T) {
	request := ObjectRetirement{Version: 1, ObjectID: 7, NodeID: 3, FenceID: "fence-123456789012345", AttemptID: "attempt-1234567890123", ExpectedSize: 0}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var parsed ObjectRetirement
	if err := DecodeRetirementJSON(raw, &parsed); err != nil || parsed != request {
		t.Fatalf("roundtrip: %+v %v", parsed, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for field := range fields {
		t.Run("missing-"+field, func(t *testing.T) {
			copy := make(map[string]json.RawMessage)
			for key, value := range fields {
				if key != field {
					copy[key] = value
				}
			}
			bad, _ := json.Marshal(copy)
			if err := DecodeRetirementJSON(bad, &ObjectRetirement{}); err == nil {
				t.Fatal("missing field accepted")
			}
		})
	}
	for _, bad := range []string{
		strings.TrimSuffix(string(raw), "}") + `,"node_id":3}`,
		strings.Replace(string(raw), `"node_id"`, `"Node_ID"`, 1),
		strings.Replace(string(raw), `"expected_size":0`, `"expected_size":null`, 1),
		strings.TrimSuffix(string(raw), "}") + `,"extra":true}`,
		string(raw) + `{}`,
		`[]`,
	} {
		if err := DecodeRetirementJSON([]byte(bad), &ObjectRetirement{}); err == nil {
			t.Errorf("ambiguous request accepted: %s", bad)
		}
	}
}

func TestRetirementReceiptRequiresPresenceOfZeroValues(t *testing.T) {
	request := ObjectRetirement{Version: 1, ObjectID: 7, NodeID: 3, FenceID: "fence-123456789012345", AttemptID: "attempt-1234567890123", ExpectedSize: 0}
	receipt := ObjectRetirementReceipt{ObjectRetirement: request, State: RetirementRemoved, Usage: NodeUsage{Epoch: "boot", Sequence: 1}}
	raw, _ := json.Marshal(receipt)
	var parsed ObjectRetirementReceipt
	if err := DecodeRetirementJSON(raw, &parsed); err != nil || parsed != receipt || parsed.Validate() != nil {
		t.Fatalf("roundtrip: %+v %v", parsed, err)
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	for field := range fields {
		t.Run("missing-"+field, func(t *testing.T) {
			copy := make(map[string]json.RawMessage)
			for key, value := range fields {
				if key != field {
					copy[key] = value
				}
			}
			bad, _ := json.Marshal(copy)
			if err := DecodeRetirementJSON(bad, &ObjectRetirementReceipt{}); err == nil {
				t.Fatal("missing receipt field accepted")
			}
		})
	}
	for _, field := range []string{"epoch", "sequence", "used_bytes"} {
		t.Run("missing-usage-"+field, func(t *testing.T) {
			var usage map[string]json.RawMessage
			json.Unmarshal(fields["usage"], &usage)
			delete(usage, field)
			copy := make(map[string]json.RawMessage)
			for key, value := range fields {
				copy[key] = value
			}
			copy["usage"], _ = json.Marshal(usage)
			bad, _ := json.Marshal(copy)
			if err := DecodeRetirementJSON(bad, &ObjectRetirementReceipt{}); err == nil {
				t.Fatal("missing usage field accepted")
			}
		})
	}
}

func TestRetirementResourcePathIsCanonical(t *testing.T) {
	for _, path := range []string{"/retire/0", "/retire/01", "/retire/+1", "/retire/1/", "/retire/-1", "/objects/1", "/retire/18446744073709551616"} {
		if _, ok := RetirementPathID(path); ok {
			t.Errorf("noncanonical path accepted: %s", path)
		}
	}
	if id, ok := RetirementPathID(RetirementPath(7)); !ok || id != 7 {
		t.Fatal("canonical path rejected")
	}
}
