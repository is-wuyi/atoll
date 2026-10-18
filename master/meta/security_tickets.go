package meta

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

var ErrAccessTicket = errors.New("access denied")

const AccessTicketTTL = 2 * time.Minute

type accessTicketRecord struct {
	Request          access.TicketRequest  `json:"request"`
	AudienceNodeID   uint64                `json:"audience_node_id"`
	AudienceIdentity string                `json:"audience_identity"`
	Issuer           string                `json:"issuer"`
	UserID           uint64                `json:"user_id,omitempty"`
	SpaceID          uint64                `json:"space_id,omitempty"`
	SessionHash      []byte                `json:"session_hash,omitempty"`
	DeviceIdentity   string                `json:"device_identity,omitempty"`
	DeviceVersion    uint64                `json:"device_version,omitempty"`
	ExpiresAt        time.Time             `json:"expires_at"`
	Integrity        types.ObjectIntegrity `json:"integrity"`
}

func ticketResourceID(path string) (uint64, bool) {
	var value string
	switch {
	case strings.HasPrefix(path, "/objects/"):
		value = strings.TrimPrefix(path, "/objects/")
	case strings.HasPrefix(path, "/replicate/"):
		value = strings.TrimPrefix(path, "/replicate/")
	case strings.HasPrefix(path, "/verify/"):
		value = strings.TrimPrefix(path, "/verify/")
	default:
		return 0, false
	}
	id, err := strconv.ParseUint(value, 10, 64)
	return id, err == nil && id != 0 && strconv.FormatUint(id, 10) == value
}

func normalizeTicketRequest(req access.TicketRequest) (access.TicketRequest, error) {
	if !validDeviceEndpoint(req.NodeAddr) || len(req.Path) > 512 || len(req.Query) > 1024 || len(req.PlanID) > 128 {
		return req, ErrAccessTicket
	}
	if req.Path == "" || req.Path[0] != '/' || strings.ContainsAny(req.Path, "\\\x00") || strings.Contains(req.Path, "//") {
		return req, ErrAccessTicket
	}
	q, err := url.ParseQuery(req.Query)
	if err != nil {
		return req, ErrAccessTicket
	}
	for key, values := range q {
		if key != "plan_id" || len(values) != 1 {
			return req, ErrAccessTicket
		}
	}
	if q.Get("plan_id") != "" {
		if req.PlanID != "" && q.Get("plan_id") != req.PlanID {
			return req, ErrAccessTicket
		}
		req.PlanID = q.Get("plan_id")
	}
	req.Query = q.Encode()
	if req.BodyHash != "" && len(req.BodyHash) != 64 {
		return req, ErrAccessTicket
	}
	return req, nil
}

func targetDeviceTx(tx *bolt.Tx, addr string) (DeviceRecord, error) {
	var target DeviceRecord
	found := false
	err := tx.Bucket(bucketNodes).ForEach(func(_, raw []byte) error {
		var n types.NodeInfo
		if err := json.Unmarshal(raw, &n); err != nil {
			return err
		}
		if n.Addr == addr {
			var err error
			target, err = deviceByNodeTx(tx, n.ID)
			if err != nil {
				return err
			}
			found = true
		}
		return nil
	})
	if err != nil {
		return target, err
	}
	if !found {
		return target, ErrAccessTicket
	}
	return target, nil
}

func planTargetAllowedTx(tx *bolt.Tx, planID string, d types.ObjectIntegrity, nodeID uint64, now time.Time) bool {
	if planID == "" {
		return types.ContainsUint64(d.Replicas, nodeID)
	}
	plan, err := planTx(tx, planID)
	if err != nil || plan.State != ProtectionPending || plan.ProfileRevision != profileRevisionTx(tx) || !exactProtectionIdentity(d, plan.Expected) {
		return false
	}
	for _, t := range plan.Targets {
		if t.NodeID == nodeID && !t.Done && t.Attempts > 0 && now.Before(t.NextAttempt) {
			return true
		}
	}
	return types.ContainsUint64(d.Replicas, nodeID)
}

func validateUserTicketTx(tx *bolt.Tx, t accessTicketRecord, now time.Time) (types.ObjectIntegrity, error) {
	user, err := sessionUserHashTx(tx, t.SessionHash, now)
	if err != nil || user.ID != t.UserID {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	id, ok := ticketResourceID(t.Request.Path)
	if !ok || !strings.HasPrefix(t.Request.Path, "/objects/") || t.Request.Query != "" || t.Request.PlanID != "" || t.Request.BodyHash != "" {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	write := t.Request.Method == http.MethodPut
	if t.Request.Method != http.MethodGet && !write {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	if _, err := authorizeSpaceTx(tx, user.ID, t.SpaceID, write); err != nil {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	anchor, err := objectAnchorTx(tx, id)
	if err != nil {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	if err := inodeInSpaceTx(tx, t.SpaceID, anchor); err != nil {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	d, err := integrityTx(tx, id)
	if err != nil || !types.ContainsUint64(d.Replicas, t.AudienceNodeID) {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	in, err := getInodeTx(tx, d.InodeID)
	if err != nil {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	if write {
		if !in.Staging || !in.Chunked || !d.ChecksumKnown {
			return types.ObjectIntegrity{}, ErrAccessTicket
		}
		if hasPlannedWriteTx(tx, in.ID) {
			u, err := plannedWriteTx(tx, in.ID)
			if err != nil || u.Actor != (WriteActor{UserID: user.ID, SpaceID: t.SpaceID}) || u.Upload.State != types.WritePending || !now.Before(u.Upload.ExpiresAt) {
				return types.ObjectIntegrity{}, ErrAccessTicket
			}
		} else {
			u, err := secureUploadTx(tx, in.ID)
			if err != nil || u.UserID != user.ID || u.SpaceID != t.SpaceID {
				return types.ObjectIntegrity{}, ErrAccessTicket
			}
		}
	} else if in.Staging {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	return d, nil
}

func validateDeviceTicketTx(tx *bolt.Tx, t accessTicketRecord, now time.Time) (types.ObjectIntegrity, error) {
	var sender DeviceRecord
	if err := readSecurityData(tx, "device", t.DeviceIdentity, &sender); err != nil || sender.Revoked || sender.SessionVersion != t.DeviceVersion {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	id, ok := ticketResourceID(t.Request.Path)
	if !ok || t.Request.BodyHash != "" || t.Request.Query != "" {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	d, err := integrityTx(tx, id)
	if err != nil || !d.ChecksumKnown {
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	switch {
	case t.Request.Method == http.MethodGet && strings.HasPrefix(t.Request.Path, "/objects/"):
		if !planTargetAllowedTx(tx, t.Request.PlanID, d, sender.NodeID, now) || !types.ContainsUint64(d.Done, t.AudienceNodeID) || types.ContainsUint64(d.Suspect, t.AudienceNodeID) {
			return types.ObjectIntegrity{}, ErrAccessTicket
		}
	case t.Request.Method == http.MethodPut && strings.HasPrefix(t.Request.Path, "/replicate/"):
		if t.Request.PlanID != "" || !types.ContainsUint64(d.Done, sender.NodeID) || types.ContainsUint64(d.Suspect, sender.NodeID) || !types.ContainsUint64(d.Replicas, t.AudienceNodeID) {
			return types.ObjectIntegrity{}, ErrAccessTicket
		}
	default:
		return types.ObjectIntegrity{}, ErrAccessTicket
	}
	return d, nil
}

func validateControlTicket(req access.TicketRequest) bool {
	if _, ok := types.RetirementPathID(req.Path); ok {
		return req.Method == http.MethodPost && req.Query == "" && types.ValidRetirementToken(req.PlanID) && len(req.BodyHash) == 64
	}
	if id, ok := ticketResourceID(req.Path); ok && id != 0 {
		switch {
		case strings.HasPrefix(req.Path, "/objects/"):
			return req.Method == http.MethodGet || req.Method == http.MethodPut
		case strings.HasPrefix(req.Path, "/verify/"):
			return req.Method == http.MethodPost
		}
	}
	if req.Path == "/pull" {
		return req.Method == http.MethodPost && req.BodyHash != ""
	}
	if req.Path == "/admin/objects" {
		return req.Method == http.MethodGet
	}
	if req.Path == "/meta-backup" || strings.HasPrefix(req.Path, "/meta-backup/") {
		return req.Method == http.MethodGet || req.Method == http.MethodPut || req.Method == http.MethodDelete
	}
	return false
}

func (s *Store) IssueUserTicket(session string, spaceID uint64, req access.TicketRequest, now time.Time) (access.Ticket, error) {
	user, err := s.UserForSession(session, now)
	if err != nil {
		return access.Ticket{}, ErrAccessTicket
	}
	return s.issueTicket(accessTicketRecord{Issuer: "user", UserID: user.ID, SpaceID: spaceID, SessionHash: hashOpaqueToken(session), Request: req}, now)
}
func (s *Store) IssueDeviceTicket(session string, req access.TicketRequest, now time.Time) (access.Ticket, error) {
	d, err := s.DeviceForSession(session, now)
	if err != nil {
		return access.Ticket{}, ErrAccessTicket
	}
	return s.issueTicket(accessTicketRecord{Issuer: "device", DeviceIdentity: d.Identity, DeviceVersion: d.SessionVersion, Request: req}, now)
}
func (s *Store) IssueControlTicket(req access.TicketRequest, now time.Time) (access.Ticket, error) {
	return s.issueTicket(accessTicketRecord{Issuer: "control", Request: req}, now)
}

func (s *Store) issueTicket(record accessTicketRecord, now time.Time) (access.Ticket, error) {
	req, err := normalizeTicketRequest(record.Request)
	if err != nil {
		return access.Ticket{}, err
	}
	record.Request = req
	token, err := secOpaque("at1_")
	if err != nil {
		return access.Ticket{}, err
	}
	record.ExpiresAt = now.Add(AccessTicketTTL)
	// Tickets are short-lived online references. Keeping issuance out of the
	// durable WAL avoids recursive backup authorization during a commit hook.
	err = s.db.Update(func(tx *bolt.Tx) error {
		w := &txw{tx: tx}
		target, err := targetDeviceTx(w.tx, record.Request.NodeAddr)
		if err != nil {
			return ErrAccessTicket
		}
		record.AudienceNodeID = target.NodeID
		record.AudienceIdentity = target.Identity
		switch record.Issuer {
		case "user":
			record.Integrity, err = validateUserTicketTx(w.tx, record, now)
		case "device":
			record.Integrity, err = validateDeviceTicketTx(w.tx, record, now)
		case "control":
			if !validateControlTicket(record.Request) {
				err = ErrAccessTicket
			}
			if id, ok := types.RetirementPathID(record.Request.Path); ok && !retirementRequestAllowedTx(w.tx, id, record.AudienceNodeID, record.Request.PlanID, record.Request.BodyHash) {
				err = ErrAccessTicket
			}
		default:
			err = ErrAccessTicket
		}
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketSecurity).Put(securityDataKey("ticket", secHash(token)), encoded)
	})
	if err != nil {
		return access.Ticket{}, err
	}
	return access.Ticket{Token: token, ExpiresAt: record.ExpiresAt}, nil
}

func (s *Store) CheckAccessTicket(nodeSession string, req access.CheckRequest, now time.Time) (access.CheckResult, error) {
	var out access.CheckResult
	if len(req.Token) > 256 {
		return out, ErrAccessTicket
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		node, err := deviceForSessionTx(tx, nodeSession, now)
		if err != nil {
			return ErrAccessTicket
		}
		var ticket accessTicketRecord
		if err := readSecurityData(tx, "ticket", secHash(req.Token), &ticket); err != nil || !now.Before(ticket.ExpiresAt) {
			return ErrAccessTicket
		}
		if node.NodeID != ticket.AudienceNodeID || node.Identity != ticket.AudienceIdentity || node.Addr != ticket.Request.NodeAddr {
			return ErrAccessTicket
		}
		normalized, err := normalizeTicketRequest(access.TicketRequest{NodeAddr: node.Addr, Method: req.Method, Path: req.Path, Query: req.Query, PlanID: req.PlanID, BodyHash: req.BodyHash})
		if err != nil || normalized != ticket.Request {
			return ErrAccessTicket
		}
		var current types.ObjectIntegrity
		switch ticket.Issuer {
		case "user":
			current, err = validateUserTicketTx(tx, ticket, now)
		case "device":
			current, err = validateDeviceTicketTx(tx, ticket, now)
		case "control":
			if !validateControlTicket(ticket.Request) {
				err = ErrAccessTicket
			}
			if id, ok := types.RetirementPathID(ticket.Request.Path); ok && !retirementRequestAllowedTx(tx, id, node.NodeID, ticket.Request.PlanID, ticket.Request.BodyHash) {
				err = ErrAccessTicket
			}
		default:
			err = ErrAccessTicket
		}
		if err != nil {
			return err
		}
		if ticket.Issuer != "control" && (!sameObjectContents(current, ticket.Integrity) || current.InodeID != ticket.Integrity.InodeID || current.Generation != ticket.Integrity.Generation) {
			return ErrAccessTicket
		}
		out = access.CheckResult{Allowed: true, ExpiresAt: ticket.ExpiresAt}
		return nil
	})
	return out, err
}

func BodySHA256(body []byte) string { sum := sha256.Sum256(body); return secHashBytes(sum[:]) }
func secHashBytes(raw []byte) string {
	const chars = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, b := range raw {
		out[i*2] = chars[b>>4]
		out[i*2+1] = chars[b&15]
	}
	return string(out)
}

// SweepSecurityTickets cleans one bounded ticket batch without adding WAL frames.
func (s *Store) SweepSecurityTickets(now time.Time) (int, error) {
	s.securitySweepMu.Lock()
	defer s.securitySweepMu.Unlock()
	if now.IsZero() {
		now = time.Now()
	}
	removed, corrupt, err := s.sweepSecurityTicketsLocked(now)
	if err != nil {
		return removed, err
	}
	if corrupt > 0 {
		return removed, errors.New("security sweep retained corrupt ticket records")
	}
	return removed, nil
}

func (s *Store) sweepSecurityTicketsLocked(now time.Time) (int, int, error) {
	removed := 0
	var next []byte
	corrupt := 0
	prefix := []byte("ticket/")
	err := s.db.Update(func(tx *bolt.Tx) error {
		victims, nxt, bad, err := securitySweepScanTx(tx, prefix, s.securitySweepCursor(prefix), func(v []byte) (bool, error) {
			var ticket accessTicketRecord
			if err := json.Unmarshal(v, &ticket); err != nil {
				return false, err
			}
			return !now.Before(ticket.ExpiresAt), nil
		})
		if err != nil {
			return err
		}
		for _, key := range victims {
			if err := tx.Bucket(bucketSecurity).Delete(key); err != nil {
				return err
			}
		}
		removed, next, corrupt = len(victims), nxt, bad
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	s.setSecuritySweepCursor(prefix, next)
	return removed, corrupt, nil
}
