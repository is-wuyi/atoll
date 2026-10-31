package meta

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"atoll/pkg/peerauth"
	bolt "go.etcd.io/bbolt"
)

var ErrPeerConflict = errors.New("peer authorization state changed")

var (
	keyPeerConfig      = []byte("peer/config")
	keyPeerInitialized = []byte("peer_directory_initialized_v1")
)

const peerStateScanLimit = peerauth.MaxDirectoryPeers * 8

type peerConfig struct {
	Version        int                     `json:"version"`
	Origin         string                  `json:"origin"`
	Infrastructure peerauth.Infrastructure `json:"infrastructure"`
}

type peerEndpointRecord struct {
	Endpoint    peerauth.Endpoint `json:"endpoint"`
	OperationID string            `json:"operation_id"`
	RequestHash string            `json:"request_hash"`
}

type clientPeerRecord struct {
	Endpoint              peerauth.Endpoint `json:"endpoint"`
	UserID                uint64            `json:"user_id"`
	SpaceID               uint64            `json:"space_id"`
	SessionHash           []byte            `json:"session_hash"`
	OperationID           string            `json:"operation_id"`
	RequestHash           string            `json:"request_hash"`
	RetainUntil           time.Time         `json:"retain_until"`
	AuthorizationRevision uint64            `json:"authorization_revision"`
	Released              bool              `json:"released,omitempty"`
}

func peerConfigTx(tx *bolt.Tx) (peerConfig, bool, error) {
	var cfg peerConfig
	security := tx.Bucket(bucketSecurity)
	writes := tx.Bucket(bucketWrites)
	if security == nil || writes == nil {
		return cfg, false, ErrPeerConflict
	}
	var writeCfg writeConfig
	if raw := writes.Get(keyWriteConfig); raw != nil {
		if json.Unmarshal(raw, &writeCfg) != nil || writeCfg.Version < 1 || writeCfg.Version > 4 {
			return cfg, false, ErrPeerConflict
		}
	}
	marker := tx.Bucket(bucketMeta).Get(keyPeerInitialized)
	raw := security.Get(keyPeerConfig)
	if raw == nil {
		if marker != nil || writeCfg.Version == 4 {
			return cfg, false, ErrPeerConflict
		}
		for _, prefix := range [][]byte{[]byte("peer-endpoint/"), []byte("client-peer/")} {
			key, _ := security.Cursor().Seek(prefix)
			if bytes.HasPrefix(key, prefix) {
				return cfg, false, ErrPeerConflict
			}
		}
		if err := walkPeerSecurity(tx, []byte("device/"), func(_, raw []byte) error {
			var device DeviceRecord
			if json.Unmarshal(raw, &device) != nil || device.Peer != nil {
				return ErrPeerConflict
			}
			return nil
		}); err != nil {
			return cfg, false, err
		}
		return cfg, false, nil
	}
	secure, err := securityEnabledTx(tx)
	if err != nil || !secure || writeCfg.Version != 4 || writeCfg.EnabledAt.IsZero() || !bytes.Equal(marker, []byte{1}) || json.Unmarshal(raw, &cfg) != nil || cfg.Version != 1 || !cfg.Infrastructure.Relay || peerauth.ValidateIdentity(cfg.Infrastructure.PeerID, cfg.Infrastructure.PublicKey) != nil {
		return cfg, false, ErrPeerConflict
	}
	origin, err := peerauth.CanonicalOrigin(cfg.Origin)
	addresses, addressErr := peerauth.NormalizeAddresses(cfg.Infrastructure.Addresses, false)
	if err != nil || origin != cfg.Origin || addressErr != nil || !samePeerAddresses(addresses, cfg.Infrastructure.Addresses) {
		return cfg, false, ErrPeerConflict
	}
	return cfg, true, nil
}

func samePeerAddresses(a, b []string) bool {
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

func walkPeerSecurity(tx *bolt.Tx, prefix []byte, visit func([]byte, []byte) error) error {
	examined := 0
	return walkSecurity(tx, prefix, func(key, raw []byte) error {
		if examined >= peerStateScanLimit {
			return ErrPeerConflict
		}
		examined++
		return visit(key, raw)
	})
}

func (s *Store) PeerDirectoryEnabled() (bool, error) {
	var enabled bool
	err := s.db.View(func(tx *bolt.Tx) error {
		_, ok, err := peerConfigTx(tx)
		enabled = ok
		return err
	})
	return enabled, err
}

func (s *Store) ConfigurePeerDirectory(origin string, infrastructure peerauth.Infrastructure) error {
	canonical, err := peerauth.CanonicalOrigin(origin)
	if err != nil || !infrastructure.Relay || peerauth.ValidateIdentity(infrastructure.PeerID, infrastructure.PublicKey) != nil {
		return ErrPeerConflict
	}
	addresses, err := peerauth.NormalizeAddresses(infrastructure.Addresses, false)
	if err != nil {
		return ErrPeerConflict
	}
	infrastructure.PublicKey = append([]byte(nil), infrastructure.PublicKey...)
	infrastructure.Addresses = addresses
	err = s.write(func(w *txw) error {
		secure, err := securityEnabledTx(w.tx)
		if err != nil || !secure {
			return ErrPeerConflict
		}
		if err := requireWritePlanningTx(w.tx); err != nil {
			return err
		}
		old, ok, err := peerConfigTx(w.tx)
		if err != nil {
			return err
		}
		if ok && (old.Origin != canonical || old.Infrastructure.PeerID != infrastructure.PeerID || !bytes.Equal(old.Infrastructure.PublicKey, infrastructure.PublicKey)) {
			return ErrPeerConflict
		}
		if ok && samePeerAddresses(old.Infrastructure.Addresses, infrastructure.Addresses) && old.Infrastructure.Relay == infrastructure.Relay {
			return nil
		}
		var cfg writeConfig
		if json.Unmarshal(w.tx.Bucket(bucketWrites).Get(keyWriteConfig), &cfg) != nil || cfg.Version < 1 || cfg.Version > 4 {
			return ErrPeerConflict
		}
		cfg.Version = 4
		encoded, _ := json.Marshal(cfg)
		if err := w.put(bcWrites, bucketWrites, keyWriteConfig, encoded); err != nil {
			return err
		}
		if err := w.put(bcMeta, bucketMeta, keyPeerInitialized, []byte{1}); err != nil {
			return err
		}
		return putSecurityJSON(w, keyPeerConfig, peerConfig{Version: 1, Origin: canonical, Infrastructure: infrastructure})
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}

func samePeerEnrollment(a, b *peerauth.Enrollment) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.PeerID == b.PeerID && a.ExpectedRevision == b.ExpectedRevision && bytes.Equal(a.PublicKey, b.PublicKey)
}

func peerSlotCountTx(tx *bolt.Tx, exceptNode uint64, exceptClient string, now time.Time) (int, error) {
	count := 0
	if err := walkPeerSecurity(tx, []byte("device/"), func(_, raw []byte) error {
		var device DeviceRecord
		if json.Unmarshal(raw, &device) != nil {
			return ErrPeerConflict
		}
		if !device.Revoked && device.Peer != nil && device.NodeID != exceptNode {
			count++
		}
		return nil
	}); err != nil {
		return 0, err
	}
	err := walkPeerSecurity(tx, []byte("client-peer/"), func(_, raw []byte) error {
		var record clientPeerRecord
		if json.Unmarshal(raw, &record) != nil || validateClientPeerRecord(record) != nil {
			return ErrPeerConflict
		}
		if record.Endpoint.PeerID != exceptClient && liveClientPeerTx(tx, record, now) {
			count++
		}
		return nil
	})
	return count, err
}

func bindDevicePeerTx(w *txw, device *DeviceRecord, enrollment *peerauth.Enrollment, challengeMessage, signature []byte, now time.Time) error {
	if enrollment == nil {
		if device.Peer != nil {
			return ErrDeviceAuth
		}
		return nil
	}
	cfg, enabled, err := peerConfigTx(w.tx)
	if err != nil || !enabled || peerauth.ValidateIdentity(enrollment.PeerID, enrollment.PublicKey) != nil || !peerauth.Verify(enrollment.PublicKey, challengeMessage, signature) || enrollment.PeerID == cfg.Infrastructure.PeerID {
		return ErrDeviceAuth
	}
	if device.Peer != nil && (device.Peer.Revision == 0 || peerauth.ValidateIdentity(device.Peer.PeerID, device.Peer.PublicKey) != nil) {
		return ErrPeerConflict
	}
	if device.Peer != nil && device.Peer.PeerID == enrollment.PeerID && bytes.Equal(device.Peer.PublicKey, enrollment.PublicKey) {
		if enrollment.ExpectedRevision != 0 && enrollment.ExpectedRevision != device.Peer.Revision {
			return ErrPeerConflict
		}
		return nil
	}
	var revision uint64
	if device.Peer != nil {
		revision = device.Peer.Revision
	}
	if enrollment.ExpectedRevision != revision || revision == ^uint64(0) {
		return ErrPeerConflict
	}
	if err := walkPeerSecurity(w.tx, []byte("device/"), func(_, raw []byte) error {
		var other DeviceRecord
		if json.Unmarshal(raw, &other) != nil {
			return ErrPeerConflict
		}
		if other.NodeID != device.NodeID && other.Peer != nil && other.Peer.PeerID == enrollment.PeerID {
			return ErrPeerConflict
		}
		return nil
	}); err != nil {
		return err
	}
	var client clientPeerRecord
	if err := readSecurityData(w.tx, "client-peer", enrollment.PeerID, &client); !errors.Is(err, ErrNotExist) {
		return ErrPeerConflict
	}
	if count, err := peerSlotCountTx(w.tx, device.NodeID, "", now); err != nil || count >= peerauth.MaxDirectoryPeers {
		return ErrPeerConflict
	}
	device.Peer = &peerauth.Binding{PeerID: enrollment.PeerID, PublicKey: append([]byte(nil), enrollment.PublicKey...), Revision: revision + 1}
	return nil
}

func (s *Store) NodePeerState(session string, now time.Time) (peerauth.NodeState, error) {
	var out peerauth.NodeState
	err := s.db.View(func(tx *bolt.Tx) error {
		device, err := deviceForSessionTx(tx, session, now)
		if err != nil {
			return err
		}
		if device.Peer != nil {
			cp := *device.Peer
			cp.PublicKey = append([]byte(nil), cp.PublicKey...)
			out.Binding = &cp
		}
		var record peerEndpointRecord
		if err := readSecurityData(tx, "peer-endpoint", fmtUint(device.NodeID), &record); err == nil && out.Binding != nil && record.Endpoint.BindingRevision == out.Binding.Revision {
			if record.Endpoint.Role != peerauth.RoleNode || record.Endpoint.PeerID != out.Binding.PeerID || !bytes.Equal(record.Endpoint.PublicKey, out.Binding.PublicKey) || record.Endpoint.NodeID != device.NodeID || record.Endpoint.Revision == 0 {
				return ErrPeerConflict
			}
			out.EndpointRevision = record.Endpoint.Revision
		} else if err != nil && !errors.Is(err, ErrNotExist) {
			return err
		}
		return nil
	})
	return out, err
}

func (s *Store) PublishPeerAddress(session string, req peerauth.AddressPublication, now time.Time) (peerauth.Endpoint, error) {
	var out peerauth.Endpoint
	if !now.Before(req.NotAfter) || req.NotAfter.After(now.Add(peerauth.EndpointLease)) {
		return out, ErrPeerConflict
	}
	err := s.write(func(w *txw) error {
		cfg, enabled, err := peerConfigTx(w.tx)
		if err != nil || !enabled {
			return ErrPeerConflict
		}
		device, err := deviceForSessionTx(w.tx, session, now)
		if err != nil || device.Peer == nil || device.Peer.PeerID != req.PeerID || device.Peer.Revision != req.BindingRevision {
			return ErrDeviceAuth
		}
		message, err := peerauth.PublicationProof(cfg.Origin, device.NodeID, req)
		if err != nil || !peerauth.Verify(device.Peer.PublicKey, message, req.Signature) {
			return ErrDeviceAuth
		}
		hash := BodySHA256(message)
		var old peerEndpointRecord
		err = readSecurityData(w.tx, "peer-endpoint", fmtUint(device.NodeID), &old)
		if err != nil && !errors.Is(err, ErrNotExist) {
			return err
		}
		if err == nil && old.Endpoint.BindingRevision == device.Peer.Revision {
			if old.Endpoint.PeerID != device.Peer.PeerID || !bytes.Equal(old.Endpoint.PublicKey, device.Peer.PublicKey) || old.Endpoint.NodeID != device.NodeID || old.Endpoint.Role != peerauth.RoleNode || old.Endpoint.Revision == 0 {
				return ErrPeerConflict
			}
			if old.OperationID == req.OperationID {
				if old.RequestHash != hash || old.Endpoint.Addr != device.Addr {
					return ErrPeerConflict
				}
				out = peerauth.CopyEndpoint(old.Endpoint)
				return nil
			}
		} else {
			old = peerEndpointRecord{}
		}
		if old.Endpoint.Revision != req.ExpectedRevision || req.ExpectedRevision == ^uint64(0) {
			return ErrPeerConflict
		}
		addresses, err := peerauth.NormalizeAddresses(req.Addresses, false)
		if err != nil {
			return err
		}
		out = peerauth.Endpoint{NodeID: device.NodeID, Addr: device.Addr, Role: peerauth.RoleNode, PeerID: req.PeerID, PublicKey: append([]byte(nil), device.Peer.PublicKey...), BindingRevision: req.BindingRevision, Revision: req.ExpectedRevision + 1, Addresses: addresses, ValidUntil: req.NotAfter.UTC()}
		return putSecurityData(w, "peer-endpoint", fmtUint(device.NodeID), peerEndpointRecord{Endpoint: out, OperationID: req.OperationID, RequestHash: hash})
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func validateClientPeerRecord(record clientPeerRecord) error {
	e := record.Endpoint
	if e.Role != peerauth.RoleClient || peerauth.ValidateIdentity(e.PeerID, e.PublicKey) != nil || e.NodeID != 0 || e.Addr != "" || len(e.Addresses) != 0 || e.BindingRevision != 0 || e.Revision == 0 || record.AuthorizationRevision == 0 || !peerauth.RepresentableTime(e.ValidUntil) || !peerauth.RepresentableTime(record.RetainUntil) || record.RetainUntil.Before(e.ValidUntil) || record.UserID == 0 || record.SpaceID == 0 || len(record.SessionHash) != 32 || !peerauth.ValidOperation(record.OperationID) || len(record.RequestHash) != 64 {
		return ErrPeerConflict
	}
	return nil
}

func (s *Store) ClientPeerState(session string, spaceID uint64, peerID string, now time.Time) (peerauth.ClientState, error) {
	var out peerauth.ClientState
	if !peerauth.ValidID(peerID) {
		return out, ErrPeerConflict
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		if _, enabled, err := peerConfigTx(tx); err != nil || !enabled {
			return ErrPeerConflict
		}
		user, err := sessionUserTx(tx, session, now)
		if err != nil {
			return err
		}
		if _, err := authorizeSpaceTx(tx, user.ID, spaceID, false); err != nil {
			return err
		}
		var record clientPeerRecord
		if err := readSecurityData(tx, "client-peer", peerID, &record); errors.Is(err, ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		if err := validateClientPeerRecord(record); err != nil || record.Endpoint.PeerID != peerID {
			return ErrPeerConflict
		}
		if user.ID != record.UserID && liveClientPeerTx(tx, record, now) {
			return ErrAuthentication
		}
		out.Revision = record.Endpoint.Revision
		return nil
	})
	return out, err
}

func liveClientPeerTx(tx *bolt.Tx, record clientPeerRecord, now time.Time) bool {
	if record.Released || validateClientPeerRecord(record) != nil || !now.Before(record.Endpoint.ValidUntil) {
		return false
	}
	user, err := sessionUserHashTx(tx, record.SessionHash, now)
	if err != nil || user.ID != record.UserID {
		return false
	}
	_, err = authorizeSpaceTx(tx, user.ID, record.SpaceID, false)
	return err == nil
}

func (s *Store) RegisterClientPeer(session string, spaceID uint64, req peerauth.ClientRegistration, now time.Time) (peerauth.Endpoint, error) {
	var out peerauth.Endpoint
	if !now.Before(req.NotAfter) || req.NotAfter.After(now.Add(peerauth.EndpointLease)) {
		return out, ErrPeerConflict
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		cfg, enabled, err := peerConfigTx(tx)
		if err != nil || !enabled {
			return ErrPeerConflict
		}
		user, err := sessionUserTx(tx, session, now)
		if err != nil {
			return err
		}
		if _, err = authorizeSpaceTx(tx, user.ID, spaceID, false); err != nil {
			return err
		}
		message, err := peerauth.ClientProof(cfg.Origin, session, spaceID, req)
		if err != nil || req.PeerID == cfg.Infrastructure.PeerID || !peerauth.Verify(req.PublicKey, message, req.Signature) {
			return ErrDeviceAuth
		}
		if err := walkPeerSecurity(tx, []byte("device/"), func(_, raw []byte) error {
			var d DeviceRecord
			if json.Unmarshal(raw, &d) != nil {
				return ErrPeerConflict
			}
			if d.Peer != nil && d.Peer.PeerID == req.PeerID {
				return ErrPeerConflict
			}
			return nil
		}); err != nil {
			return err
		}
		var previous clientPeerRecord
		oldErr := readSecurityData(tx, "client-peer", req.PeerID, &previous)
		if oldErr != nil && !errors.Is(oldErr, ErrNotExist) {
			return oldErr
		}
		hash := BodySHA256(message)
		sessionHash := hashOpaqueToken(session)
		var currentRevision uint64
		authorizationRevision := uint64(1)
		if oldErr == nil {
			if validateClientPeerRecord(previous) != nil || previous.Endpoint.PeerID != req.PeerID || !bytes.Equal(previous.Endpoint.PublicKey, req.PublicKey) {
				return ErrPeerConflict
			}
			if previous.UserID != user.ID && liveClientPeerTx(tx, previous, now) {
				return ErrPeerConflict
			}
			if previous.OperationID == req.OperationID {
				if previous.RequestHash != hash || !bytes.Equal(previous.SessionHash, sessionHash) || previous.UserID != user.ID || previous.SpaceID != spaceID {
					return ErrPeerConflict
				}
				out = peerauth.CopyEndpoint(previous.Endpoint)
				return nil
			}
			currentRevision = previous.Endpoint.Revision
			authorizationRevision = previous.AuthorizationRevision
			if previous.UserID != user.ID || previous.SpaceID != spaceID || !bytes.Equal(previous.SessionHash, sessionHash) || !liveClientPeerTx(tx, previous, now) {
				if authorizationRevision == ^uint64(0) {
					return ErrPeerConflict
				}
				authorizationRevision++
			}
		}
		if currentRevision != req.ExpectedRevision || currentRevision == ^uint64(0) {
			return ErrPeerConflict
		}
		if count, err := peerSlotCountTx(tx, 0, req.PeerID, now); err != nil || count >= peerauth.MaxDirectoryPeers {
			return ErrPeerConflict
		}
		stored, perUser := 0, 0
		var expired [][]byte
		if err := walkPeerSecurity(tx, []byte("client-peer/"), func(key, raw []byte) error {
			var rec clientPeerRecord
			if json.Unmarshal(raw, &rec) != nil || validateClientPeerRecord(rec) != nil {
				return ErrPeerConflict
			}
			if rec.Endpoint.PeerID == req.PeerID {
				return nil
			}
			if !now.Before(rec.RetainUntil) {
				expired = append(expired, append([]byte(nil), key...))
				return nil
			}
			stored++
			if !liveClientPeerTx(tx, rec, now) {
				return nil
			}
			if rec.UserID == user.ID {
				perUser++
			}
			return nil
		}); err != nil {
			return err
		}
		if stored >= peerStateScanLimit-1 || perUser >= 4 {
			return ErrPeerConflict
		}
		for _, key := range expired {
			if err := tx.Bucket(bucketSecurity).Delete(key); err != nil {
				return err
			}
		}
		out = peerauth.Endpoint{Role: peerauth.RoleClient, PeerID: req.PeerID, PublicKey: append([]byte(nil), req.PublicKey...), Revision: currentRevision + 1, ValidUntil: req.NotAfter.UTC()}
		raw, _ := json.Marshal(clientPeerRecord{Endpoint: out, UserID: user.ID, SpaceID: spaceID, SessionHash: sessionHash, OperationID: req.OperationID, RequestHash: hash, RetainUntil: req.NotAfter.UTC().Add(peerauth.EndpointLease), AuthorizationRevision: authorizationRevision})
		return tx.Bucket(bucketSecurity).Put(securityDataKey("client-peer", req.PeerID), raw)
	})
	return out, err
}

func (s *Store) ReleaseClientPeer(session string, spaceID uint64, req peerauth.ClientRegistration, now time.Time) (peerauth.ClientState, error) {
	var out peerauth.ClientState
	if !now.Before(req.NotAfter) || req.NotAfter.After(now.Add(peerauth.EndpointLease)) || req.ExpectedRevision == 0 {
		return out, ErrPeerConflict
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		cfg, enabled, err := peerConfigTx(tx)
		if err != nil || !enabled {
			return ErrPeerConflict
		}
		user, err := sessionUserTx(tx, session, now)
		if err != nil {
			return err
		}
		if _, err := authorizeSpaceTx(tx, user.ID, spaceID, false); err != nil {
			return err
		}
		message, err := peerauth.ClientReleaseProof(cfg.Origin, session, spaceID, req)
		if err != nil || !peerauth.Verify(req.PublicKey, message, req.Signature) {
			return ErrDeviceAuth
		}
		var record clientPeerRecord
		if readSecurityData(tx, "client-peer", req.PeerID, &record) != nil || validateClientPeerRecord(record) != nil || record.Endpoint.PeerID != req.PeerID || !bytes.Equal(record.Endpoint.PublicKey, req.PublicKey) || record.UserID != user.ID || record.SpaceID != spaceID || !bytes.Equal(record.SessionHash, hashOpaqueToken(session)) {
			return ErrPeerConflict
		}
		hash := BodySHA256(message)
		if record.OperationID == req.OperationID {
			if !record.Released || record.RequestHash != hash {
				return ErrPeerConflict
			}
			out.Revision = record.Endpoint.Revision
			return nil
		}
		if record.Released || record.Endpoint.Revision != req.ExpectedRevision || record.Endpoint.Revision == ^uint64(0) || record.AuthorizationRevision == ^uint64(0) {
			return ErrPeerConflict
		}
		record.Released = true
		record.Endpoint.Revision++
		record.AuthorizationRevision++
		record.OperationID, record.RequestHash = req.OperationID, hash
		if retain := req.NotAfter.Add(peerauth.EndpointLease); retain.After(record.RetainUntil) {
			record.RetainUntil = retain.UTC()
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		out.Revision = record.Endpoint.Revision
		return tx.Bucket(bucketSecurity).Put(securityDataKey("client-peer", req.PeerID), raw)
	})
	return out, err
}

func peerNodeEndpointTx(tx *bolt.Tx, nodeID uint64, now time.Time, nodeMaxAge time.Duration) (peerauth.Endpoint, error) {
	device, err := deviceByNodeTx(tx, nodeID)
	if err != nil || device.Peer == nil {
		return peerauth.Endpoint{}, ErrNotExist
	}
	raw := tx.Bucket(bucketNodes).Get(u64be(nodeID))
	var node struct {
		LastHeartbeat time.Time `json:"last_heartbeat"`
	}
	if raw == nil || json.Unmarshal(raw, &node) != nil || node.LastHeartbeat.IsZero() || now.Sub(node.LastHeartbeat) >= nodeMaxAge {
		return peerauth.Endpoint{}, ErrNotExist
	}
	var record peerEndpointRecord
	if err := readSecurityData(tx, "peer-endpoint", fmtUint(nodeID), &record); err != nil {
		return peerauth.Endpoint{}, err
	}
	if record.Endpoint.PeerID != device.Peer.PeerID || record.Endpoint.BindingRevision != device.Peer.Revision || record.Endpoint.Addr != device.Addr || !now.Before(record.Endpoint.ValidUntil) {
		return peerauth.Endpoint{}, ErrNotExist
	}
	addresses, err := peerauth.NormalizeAddresses(record.Endpoint.Addresses, false)
	if err != nil || record.Endpoint.Role != peerauth.RoleNode || record.Endpoint.NodeID != nodeID || record.Endpoint.Revision == 0 || !peerauth.RepresentableTime(record.Endpoint.ValidUntil) || !bytes.Equal(record.Endpoint.PublicKey, device.Peer.PublicKey) || !samePeerAddresses(addresses, record.Endpoint.Addresses) {
		return peerauth.Endpoint{}, ErrPeerConflict
	}
	return peerauth.CopyEndpoint(record.Endpoint), nil
}

func (s *Store) PeerDirectory(now time.Time, nodeMaxAge time.Duration) (peerauth.Directory, error) {
	if nodeMaxAge <= 0 {
		return peerauth.Directory{}, ErrPeerConflict
	}
	var out peerauth.Directory
	err := s.db.View(func(tx *bolt.Tx) error {
		cfg, enabled, err := peerConfigTx(tx)
		if err != nil || !enabled {
			return ErrPeerConflict
		}
		out = peerauth.Directory{Protocol: peerauth.Feature, Infrastructure: cfg.Infrastructure, Endpoints: []peerauth.Endpoint{}}
		examined := 0
		if err := tx.Bucket(bucketNodes).ForEach(func(key, _ []byte) error {
			if len(key) != 8 || examined >= peerStateScanLimit {
				return ErrPeerConflict
			}
			examined++
			endpoint, err := peerNodeEndpointTx(tx, beU64(key), now, nodeMaxAge)
			if errors.Is(err, ErrNotExist) || errors.Is(err, ErrDeviceAuth) {
				return nil
			}
			if err != nil {
				return err
			}
			out.Endpoints = append(out.Endpoints, endpoint)
			if len(out.Endpoints) > peerauth.MaxDirectoryPeers {
				return ErrPeerConflict
			}
			return nil
		}); err != nil {
			return err
		}
		return walkPeerSecurity(tx, []byte("client-peer/"), func(_, raw []byte) error {
			var record clientPeerRecord
			if json.Unmarshal(raw, &record) != nil || validateClientPeerRecord(record) != nil {
				return ErrPeerConflict
			}
			if liveClientPeerTx(tx, record, now) {
				out.Endpoints = append(out.Endpoints, peerauth.CopyEndpoint(record.Endpoint))
			}
			if len(out.Endpoints) > peerauth.MaxDirectoryPeers {
				return ErrPeerConflict
			}
			return nil
		})
	})
	sort.Slice(out.Endpoints, func(i, j int) bool { return out.Endpoints[i].PeerID < out.Endpoints[j].PeerID })
	return peerauth.CopyDirectory(out), err
}

func (s *Store) PeerAllowed(id string, now time.Time, nodeMaxAge time.Duration) (bool, error) {
	if !peerauth.ValidID(id) || nodeMaxAge <= 0 {
		return false, ErrPeerConflict
	}
	allowed := false
	err := s.db.View(func(tx *bolt.Tx) error {
		cfg, enabled, err := peerConfigTx(tx)
		if err != nil || !enabled {
			return ErrPeerConflict
		}
		if id == cfg.Infrastructure.PeerID {
			allowed = true
			return nil
		}
		var client clientPeerRecord
		if readSecurityData(tx, "client-peer", id, &client) == nil && client.Endpoint.PeerID == id && liveClientPeerTx(tx, client, now) {
			allowed = true
			return nil
		}
		return walkPeerSecurity(tx, []byte("device/"), func(_, raw []byte) error {
			var d DeviceRecord
			if json.Unmarshal(raw, &d) != nil {
				return ErrPeerConflict
			}
			if d.Revoked || d.Peer == nil || d.Peer.PeerID != id {
				return nil
			}
			var node struct {
				LastHeartbeat time.Time `json:"last_heartbeat"`
			}
			if v := tx.Bucket(bucketNodes).Get(u64be(d.NodeID)); v != nil && json.Unmarshal(v, &node) == nil && !node.LastHeartbeat.IsZero() && now.Sub(node.LastHeartbeat) < nodeMaxAge {
				allowed = true
			}
			return nil
		})
	})
	return allowed, err
}

func sourcePeerAuthorizedTx(tx *bolt.Tx, ticket accessTicketRecord, now time.Time) error {
	id := ticket.Request.SourcePeerID
	if id == "" {
		return nil
	}
	cfg, enabled, err := peerConfigTx(tx)
	if err != nil || !enabled || !peerauth.ValidID(id) {
		return ErrAccessTicket
	}
	switch ticket.Issuer {
	case "control":
		if id != cfg.Infrastructure.PeerID {
			return ErrAccessTicket
		}
	case "device":
		var d DeviceRecord
		if readSecurityData(tx, "device", ticket.DeviceIdentity, &d) != nil || d.Revoked || d.SessionVersion != ticket.DeviceVersion || d.Peer == nil || d.Peer.PeerID != id || d.Peer.Revision != ticket.SourcePeerRevision || ticket.SourcePeerRevision == 0 {
			return ErrAccessTicket
		}
	case "user":
		var rec clientPeerRecord
		if readSecurityData(tx, "client-peer", id, &rec) != nil || rec.Endpoint.PeerID != id || !liveClientPeerTx(tx, rec, now) || rec.UserID != ticket.UserID || rec.SpaceID != ticket.SpaceID || !bytes.Equal(rec.SessionHash, ticket.SessionHash) || rec.AuthorizationRevision != ticket.SourcePeerRevision || ticket.SourcePeerRevision == 0 {
			return ErrAccessTicket
		}
	default:
		return ErrAccessTicket
	}
	return nil
}

func (s *Store) PeerEndpointByAddr(addr string, now time.Time, nodeMaxAge time.Duration) (peerauth.Endpoint, error) {
	if !peerauth.ValidNodeAddr(addr) || nodeMaxAge <= 0 {
		return peerauth.Endpoint{}, ErrPeerConflict
	}
	var out peerauth.Endpoint
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		examined := 0
		return tx.Bucket(bucketNodes).ForEach(func(key, raw []byte) error {
			if len(key) != 8 || examined >= peerStateScanLimit {
				return ErrPeerConflict
			}
			examined++
			var n struct {
				Addr string `json:"addr"`
			}
			if json.Unmarshal(raw, &n) != nil {
				return ErrPeerConflict
			}
			if n.Addr == addr {
				if found {
					return ErrPeerConflict
				}
				endpoint, err := peerNodeEndpointTx(tx, beU64(key), now, nodeMaxAge)
				if err != nil {
					return err
				}
				out = endpoint
				found = true
			}
			return nil
		})
	})
	if err == nil && !found {
		err = ErrNotExist
	}
	return out, err
}

func (s *Store) sweepClientPeersLocked(now time.Time) (int, int, error) {
	removed, corrupt := 0, 0
	var next []byte
	prefix := []byte("client-peer/")
	err := s.db.Update(func(tx *bolt.Tx) error {
		victims, cursor, bad, err := securitySweepScanTx(tx, prefix, s.securitySweepCursor(prefix), func(raw []byte) (bool, error) {
			var record clientPeerRecord
			if json.Unmarshal(raw, &record) != nil || validateClientPeerRecord(record) != nil {
				return false, ErrPeerConflict
			}
			return !now.Before(record.RetainUntil), nil
		})
		if err != nil {
			return err
		}
		for _, key := range victims {
			if err := tx.Bucket(bucketSecurity).Delete(key); err != nil {
				return err
			}
		}
		removed, corrupt, next = len(victims), bad, cursor
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	s.setSecuritySweepCursor(prefix, next)
	return removed, corrupt, nil
}

func (s *Store) PeerInfrastructure() (peerauth.Infrastructure, error) {
	var out peerauth.Infrastructure
	err := s.db.View(func(tx *bolt.Tx) error {
		cfg, ok, err := peerConfigTx(tx)
		if err != nil || !ok {
			return ErrPeerConflict
		}
		out = cfg.Infrastructure
		return nil
	})
	return peerauth.CopyDirectory(peerauth.Directory{Infrastructure: out}).Infrastructure, err
}
