package types

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

const RetirementVersion = 1
const RetirementRemoved = "removed"

// AttemptID binds a fresh observation to one durable Master request; FenceID never changes.
type ObjectRetirement struct {
	Version      int    `json:"version"`
	ObjectID     uint64 `json:"object_id"`
	NodeID       uint64 `json:"node_id"`
	FenceID      string `json:"fence_id"`
	AttemptID    string `json:"attempt_id"`
	ExpectedSize int64  `json:"expected_size"`
}

type ObjectRetirementReceipt struct {
	ObjectRetirement
	State        string    `json:"state"`
	RemovedBytes int64     `json:"removed_bytes"`
	Usage        NodeUsage `json:"usage"`
}

func ValidRetirementToken(s string) bool {
	return len(s) >= 16 && len(s) <= 128 && !strings.ContainsAny(s, " /\\\t\r\n\x00")
}

func (r ObjectRetirement) Validate() error {
	if r.Version != RetirementVersion || r.ObjectID == 0 || r.NodeID == 0 || r.ExpectedSize < 0 ||
		!ValidRetirementToken(r.FenceID) || !ValidRetirementToken(r.AttemptID) {
		return errors.New("invalid object retirement")
	}
	return nil
}

func (r ObjectRetirementReceipt) Validate() error {
	if err := r.ObjectRetirement.Validate(); err != nil {
		return err
	}
	if r.State != RetirementRemoved || r.RemovedBytes < 0 || r.RemovedBytes > r.ExpectedSize ||
		r.Usage.Epoch == "" || len(r.Usage.Epoch) > 128 || r.Usage.Sequence == 0 || r.Usage.UsedBytes < 0 {
		return errors.New("invalid retirement receipt")
	}
	return nil
}

func RetirementPath(id uint64) string { return "/retire/" + strconv.FormatUint(id, 10) }

func RetirementPathID(path string) (uint64, bool) {
	if !strings.HasPrefix(path, "/retire/") {
		return 0, false
	}
	value := strings.TrimPrefix(path, "/retire/")
	id, err := strconv.ParseUint(value, 10, 64)
	return id, err == nil && id > 0 && strconv.FormatUint(id, 10) == value
}

// Duplicate fields, aliases and nulls would make the authenticated body ambiguous.
func DecodeRetirementJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return errors.New("invalid retirement body size")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := retirementJSONValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("extra retirement JSON value")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	required := []string{"version", "object_id", "node_id", "fence_id", "attempt_id", "expected_size"}
	switch out.(type) {
	case *ObjectRetirement:
	case *ObjectRetirementReceipt:
		required = append(required, "state", "removed_bytes", "usage")
		var usage map[string]json.RawMessage
		if err := json.Unmarshal(fields["usage"], &usage); err != nil {
			return errors.New("retirement usage object required")
		}
		for _, name := range []string{"epoch", "sequence", "used_bytes"} {
			if _, ok := usage[name]; !ok {
				return errors.New("missing retirement usage field")
			}
		}
	default:
		return nil
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return errors.New("missing retirement field")
		}
	}
	return nil
}

func retirementJSONValue(d *json.Decoder, depth int) error {
	if depth > 4 {
		return errors.New("retirement JSON nesting too deep")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("null retirement field")
	}
	if delim, ok := token.(json.Delim); ok {
		if delim != '{' {
			return errors.New("retirement JSON object required")
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] || strings.ToLower(name) != name {
				return errors.New("ambiguous retirement JSON field")
			}
			seen[name] = true
			if err := retirementJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if depth == 0 {
		return errors.New("retirement JSON object required")
	}
	return nil
}
