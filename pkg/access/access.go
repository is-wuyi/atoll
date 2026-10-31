package access

import (
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"atoll/pkg/edgeidentity"
	"atoll/pkg/peerauth"
	"atoll/pkg/types"
)

const (
	SpaceHeader = "X-Atoll-Space"
	PlanHeader  = "X-Atoll-Plan-ID"
)

// PlanAttemptHeader carries the protection claim attempt alongside PlanHeader.
// Empty means a legacy plan; ticket normalization only accepts a non-zero
// attempt for device GET /objects requests that also carry a PlanID.
const PlanAttemptHeader = "X-Atoll-Plan-Attempt"
const PlanAttemptTokenHeader = "X-Atoll-Plan-Attempt-Token"

type TicketRequest struct {
	NodeAddr         string `json:"node_addr"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	Query            string `json:"query,omitempty"`
	PlanID           string `json:"plan_id,omitempty"`
	PlanAttempt      uint32 `json:"plan_attempt,omitempty"`
	PlanAttemptToken string `json:"plan_attempt_token,omitempty"`
	BodyHash         string `json:"body_hash,omitempty"`
	// WriteEpoch binds the ticket to one planned-write generation. Zero means
	// a legacy (non-recovery) write, which keeps the original behavior.
	WriteEpoch uint64 `json:"write_epoch,omitempty"`
	// Resume marks a zero-length PUT that only re-confirms an already stored
	// object under the current epoch. It never authorizes new payload bytes.
	Resume         bool   `json:"resume,omitempty"`
	WriteAttemptID string `json:"write_attempt_id,omitempty"`
	SourcePeerID   string `json:"source_peer_id,omitempty"`
}

type Ticket struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CheckRequest struct {
	Token            string `json:"token"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	Query            string `json:"query,omitempty"`
	PlanID           string `json:"plan_id,omitempty"`
	PlanAttempt      uint32 `json:"plan_attempt,omitempty"`
	PlanAttemptToken string `json:"plan_attempt_token,omitempty"`
	BodyHash         string `json:"body_hash,omitempty"`
	// WriteEpoch and Resume mirror the ticket fields: the node repeats what it
	// received on the wire so the master can bind the check to the same
	// generation and the same zero-length re-confirm intent.
	WriteEpoch     uint64 `json:"write_epoch,omitempty"`
	Resume         bool   `json:"resume,omitempty"`
	WriteAttemptID string `json:"write_attempt_id,omitempty"`
	SourcePeerID   string `json:"source_peer_id,omitempty"`
}

type CheckResult struct {
	Allowed   bool      `json:"allowed"`
	ExpiresAt time.Time `json:"expires_at"`
}

type DeviceChallengeRequest struct {
	PublicKey  []byte               `json:"public_key"`
	Addr       string               `json:"addr"`
	TotalBytes int64                `json:"total_bytes"`
	Invite     string               `json:"invite,omitempty"`
	Peer       *peerauth.Enrollment `json:"peer,omitempty"`
}

type DeviceChallenge struct {
	ID        string                 `json:"id"`
	Challenge edgeidentity.Challenge `json:"challenge"`
}

type DeviceLoginRequest struct {
	ChallengeID   string `json:"challenge_id"`
	Signature     []byte `json:"signature"`
	PeerSignature []byte `json:"peer_signature,omitempty"`
}

type DeviceSession struct {
	NodeID    uint64            `json:"node_id"`
	Token     string            `json:"token"`
	ExpiresAt time.Time         `json:"expires_at"`
	Peer      *peerauth.Binding `json:"peer,omitempty"`
}

func WriteAttemptID(req *http.Request) (string, error) {
	values := req.Header.Values(types.WriteAttemptHeader)
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 || !ValidWriteAttemptID(values[0]) {
		return "", errors.New("invalid write attempt id")
	}
	return values[0], nil
}

func ValidWriteAttemptID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// Transport clones requests so credentials for one destination cannot mutate a caller's request.
type Transport struct {
	Base      http.RoundTripper
	Authorize func(*http.Request) error
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	copy := req.Clone(req.Context())
	if err := t.Authorize(copy); err != nil {
		if copy.Body != nil {
			copy.Body.Close()
		}
		return nil, err
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(copy)
}
