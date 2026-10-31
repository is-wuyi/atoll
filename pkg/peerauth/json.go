package peerauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const MaxJSONBytes = 64 << 10

// Duplicate fields, case aliases and nulls must not acquire a different meaning after authorization.
func DecodeJSON(reader io.Reader, out any) error {
	return DecodeJSONLimit(reader, out, MaxJSONBytes)
}

func DecodeJSONLimit(reader io.Reader, out any, limit int64) error {
	if limit <= 0 || limit > MaxDirectoryBytes {
		return errors.New("invalid peer authorization JSON limit")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return errors.New("invalid peer authorization JSON size")
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	if err := jsonValue(check, 0); err != nil {
		return err
	}
	if _, err := check.Token(); err != io.EOF {
		return errors.New("peer authorization JSON must contain one value")
	}
	var required []string
	switch out.(type) {
	case *AddressPublication:
		required = []string{"peer_id", "binding_revision", "expected_revision", "operation_id", "addresses", "not_after", "signature"}
	case *ClientRegistration:
		required = []string{"peer_id", "public_key", "expected_revision", "operation_id", "not_after", "signature"}
	}
	if len(required) > 0 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		for _, name := range required {
			if _, ok := fields[name]; !ok {
				return errors.New("missing peer authorization field " + name)
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func jsonValue(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("peer authorization JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return errors.New("invalid or null peer authorization JSON")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			name, ok := token.(string)
			if err != nil || !ok || name == "" || name != strings.ToLower(name) || seen[name] {
				return errors.New("ambiguous peer authorization JSON field")
			}
			seen[name] = true
			if err := jsonValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid peer authorization JSON object")
		}
	case '[':
		for decoder.More() {
			if err := jsonValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid peer authorization JSON array")
		}
	default:
		return errors.New("invalid peer authorization JSON delimiter")
	}
	return nil
}
