package types

import (
	"encoding/json"
	"testing"
)

func TestWriteAttemptFeatureAndProtocolVersion(t *testing.T) {
	if WriteRecoveryFeature != "write-recovery-v2" || WriteIntegrityProtocol != "integrity-write-v3" {
		t.Fatal("registered attempt protocol must not be mistaken for the previous recovery protocol")
	}
	id := "0123456789abcdef0123456789abcdef"
	raw, err := json.Marshal(BeginWriteProgressRequest{ObjectID: 1, NodeID: 2, Epoch: 1, RequestID: id})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["expected_attempt"]; !ok {
		t.Fatal("initial attempt CAS cannot omit zero")
	}
}
