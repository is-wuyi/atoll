package master

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"atoll/master/meta"
	"atoll/pkg/access"
	"atoll/pkg/auth"
	"atoll/pkg/contentcrypto"
	"atoll/pkg/types"
)

type SecurityConfig struct {
	ControlToken  auth.Token
	AllowInsecure bool
}

type serverSecurity struct {
	config      SecurityConfig
	namespaceMu sync.Mutex
	publicSlots chan struct{}
	startOnce   sync.Once
	wg          sync.WaitGroup
}

// Configure before creating handlers or starting background workers.
func (s *Server) EnableSecurity(cfg SecurityConfig) error {
	if len(cfg.ControlToken) < 24 {
		return errors.New("secure master requires a private control token of at least 24 characters")
	}
	enabled, err := s.store.SecurityEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		return errors.New("security database must be bootstrapped first")
	}
	if s.tlsCfg != nil && s.tlsCfg.InsecureSkipVerify && !cfg.AllowInsecure {
		return errors.New("secure mode rejects TLS verification bypass")
	}
	if !cfg.AllowInsecure {
		outbound := &tls.Config{MinVersion: tls.VersionTLS12}
		if s.tlsCfg != nil {
			outbound = s.tlsCfg.Clone()
			if outbound.MinVersion < tls.VersionTLS12 {
				outbound.MinVersion = tls.VersionTLS12
			}
		}
		s.SetTLS(outbound)
	}
	s.security = &serverSecurity{config: cfg, publicSlots: make(chan struct{}, 4)}
	return nil
}

func bearer(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	token := strings.TrimPrefix(value, "Bearer ")
	if len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return ""
	}
	return token
}
func constantToken(a string, b auth.Token) bool {
	return b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) securityHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if r.TLS == nil && !s.security.config.AllowInsecure {
			httpError(w, http.StatusUpgradeRequired, "TLS required for security mode")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/metabackup") {
			// 加密备份已开启时放行（状态/触发/配置走控制凭据或 admin 会话的
			// 既有 adminPaths 闸）；未加密仍禁——账号元数据不能明文进节点。
			if s.backup == nil || !s.backup.EncryptionEnabled() {
				httpError(w, http.StatusConflict, "secure metadata backup requires an encrypted backup key; use an offline local backup")
				return
			}
		}
		if s.servePublicSecurity(w, r) {
			return
		}
		token := bearer(r)
		if r.URL.Path == "/security/check" && r.Method == http.MethodPost {
			if _, err := s.store.DeviceForSession(token, time.Now()); err != nil {
				httpError(w, http.StatusUnauthorized, "device authentication failed")
				return
			}
			var req access.CheckRequest
			if decodeJSON(w, r, &req) != nil {
				httpError(w, http.StatusBadRequest, "invalid access check")
				return
			}
			out, err := s.store.CheckAccessTicket(token, req, time.Now())
			if err != nil {
				httpError(w, http.StatusForbidden, "access denied")
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		if r.URL.Path == "/security/tickets" && r.Method == http.MethodPost {
			var req access.TicketRequest
			if decodeJSON(w, r, &req) != nil {
				httpError(w, http.StatusBadRequest, "invalid ticket request")
				return
			}
			var out access.Ticket
			var err error
			if strings.HasPrefix(token, "nd1_") {
				if _, err := s.store.DeviceForSession(token, time.Now()); err != nil {
					httpError(w, http.StatusUnauthorized, "device authentication failed")
					return
				}
				out, err = s.store.IssueDeviceTicket(token, req, time.Now())
			} else {
				spaceID, e := requestSpace(r)
				if e != nil {
					httpError(w, http.StatusForbidden, "space required")
					return
				}
				out, err = s.store.IssueUserTicket(token, spaceID, req, time.Now())
			}
			if err != nil {
				httpError(w, http.StatusForbidden, "access denied")
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		if strings.HasPrefix(token, "nd1_") {
			device, err := s.store.DeviceForSession(token, time.Now())
			if err != nil {
				httpError(w, http.StatusUnauthorized, "device authentication failed")
				return
			}
			if !s.allowDeviceMetadata(w, r, device) {
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if constantToken(token, s.security.config.ControlToken) || constantToken(token, s.adminToken) {
			if !strings.HasPrefix(r.URL.Path, "/admin/") {
				httpError(w, http.StatusForbidden, "control credential is not a user session")
				return
			}
			if adminPaths[r.URL.Path] && s.adminToken != "" && !constantToken(token, s.adminToken) {
				httpError(w, http.StatusUnauthorized, "admin credential required")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		// Namespace mutations and permission changes share one admission lock.
		// Node ticket checks do not take this lock: uploads may synchronously call back from a node.
		s.security.namespaceMu.Lock()
		defer s.security.namespaceMu.Unlock()
		user, err := s.store.UserForSession(token, time.Now())
		if err != nil {
			httpError(w, http.StatusUnauthorized, "authentication failed")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/auth/") {
			s.serveUserAuth(w, r, user, token)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			if !user.PlatformAdmin {
				httpError(w, http.StatusForbidden, "access denied")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		s.serveSpaceRequest(w, r, next, user)
	})
}

func (s *Server) servePublicSecurity(w http.ResponseWriter, r *http.Request) bool {
	key := r.Method + " " + r.URL.Path
	if key != "POST /auth/login" && key != "POST /auth/register" && key != "POST /security/devices/challenge" && key != "POST /security/devices/session" {
		return false
	}
	select {
	case s.security.publicSlots <- struct{}{}:
		defer func() { <-s.security.publicSlots }()
	default:
		httpError(w, http.StatusTooManyRequests, "authentication busy")
		return true
	}
	switch key {
	case "POST /auth/login":
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if decodeJSON(w, r, &req) != nil {
			httpError(w, http.StatusBadRequest, "invalid login")
			break
		}
		out, err := s.store.AuthenticateUser(req.Username, req.Password, time.Now())
		if err != nil {
			httpError(w, http.StatusUnauthorized, "authentication failed")
			break
		}
		writeJSON(w, http.StatusOK, out)
	case "POST /auth/register":
		var req struct {
			Invite   string `json:"invite"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if decodeJSON(w, r, &req) != nil {
			httpError(w, http.StatusBadRequest, "invalid registration")
			break
		}
		user, space, err := s.store.RegisterInvitedUser(req.Invite, req.Username, req.Password, time.Now())
		if err != nil {
			httpError(w, http.StatusForbidden, "registration denied")
			break
		}
		writeJSON(w, http.StatusCreated, map[string]any{"user": user, "space": publicSpace(space)})
	case "POST /security/devices/challenge":
		var req access.DeviceChallengeRequest
		if decodeJSON(w, r, &req) != nil {
			httpError(w, http.StatusBadRequest, "invalid device challenge")
			break
		}
		out, err := s.store.NewDeviceChallenge(req, time.Now())
		if err != nil {
			httpError(w, http.StatusUnauthorized, "device authentication failed")
			break
		}
		writeJSON(w, http.StatusOK, out)
	case "POST /security/devices/session":
		var req access.DeviceLoginRequest
		if decodeJSON(w, r, &req) != nil {
			httpError(w, http.StatusBadRequest, "invalid device proof")
			break
		}
		out, err := s.store.CompleteDeviceChallenge(req, time.Now())
		if err != nil {
			httpError(w, http.StatusUnauthorized, "device authentication failed")
			break
		}
		writeJSON(w, http.StatusOK, out)
	}
	return true
}

func publicSpace(space meta.Space) map[string]any {
	return map[string]any{"id": space.ID, "name": space.Name, "kind": space.Kind, "owner_id": space.OwnerID, "root_id": space.RootID}
}

func (s *Server) serveUserAuth(w http.ResponseWriter, r *http.Request, user meta.PublicUser, token string) {
	switch r.Method + " " + r.URL.Path {
	case "GET /auth/me":
		writeJSON(w, http.StatusOK, user)
	case "POST /auth/logout":
		if err := s.store.RevokeSession(token); err != nil {
			httpError(w, http.StatusUnauthorized, "authentication failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"logged_out": true})
	case "GET /auth/spaces":
		spaces, err := s.store.ListUserSpaces(user.ID)
		if err != nil {
			httpError(w, http.StatusForbidden, "access denied")
			return
		}
		out := make([]map[string]any, 0, len(spaces))
		for _, space := range spaces {
			out = append(out, publicSpace(space))
		}
		writeJSON(w, http.StatusOK, out)
	case "POST /auth/teams":
		var req struct {
			Name string `json:"name"`
		}
		if decodeJSON(w, r, &req) != nil {
			httpError(w, 400, "invalid team")
			return
		}
		space, err := s.store.CreateTeam(user.ID, req.Name)
		if err != nil {
			httpError(w, 400, "team creation failed")
			return
		}
		writeJSON(w, http.StatusCreated, publicSpace(space))
	case "POST /auth/members":
		var req struct {
			SpaceID uint64    `json:"space_id"`
			UserID  uint64    `json:"user_id"`
			Role    meta.Role `json:"role"`
		}
		if decodeJSON(w, r, &req) != nil {
			httpError(w, 400, "invalid member")
			return
		}
		if err := s.store.SetTeamMember(user.ID, req.SpaceID, req.UserID, req.Role); err != nil {
			httpError(w, 403, "access denied")
			return
		}
		writeJSON(w, 200, map[string]bool{"updated": true})
	case "DELETE /auth/members":
		spaceID, _ := strconv.ParseUint(r.URL.Query().Get("space_id"), 10, 64)
		userID, _ := strconv.ParseUint(r.URL.Query().Get("user_id"), 10, 64)
		if err := s.store.RemoveTeamMember(user.ID, spaceID, userID); err != nil {
			httpError(w, 403, "access denied")
			return
		}
		writeJSON(w, 200, map[string]bool{"removed": true})
	case "POST /auth/invites":
		var req struct {
			ExpiresAt time.Time `json:"expires_at"`
		}
		if decodeJSON(w, r, &req) != nil {
			httpError(w, 400, "invalid invite")
			return
		}
		code, err := s.store.CreateUserInvite(user.ID, req.ExpiresAt, time.Now())
		if err != nil {
			httpError(w, 403, "access denied")
			return
		}
		writeJSON(w, 201, map[string]any{"invite": code, "expires_at": req.ExpiresAt})
	case "POST /auth/devices/invites":
		if !user.PlatformAdmin {
			httpError(w, 403, "access denied")
			return
		}
		var req struct {
			ExpiresAt time.Time `json:"expires_at"`
		}
		if decodeJSON(w, r, &req) != nil {
			httpError(w, 400, "invalid invite")
			return
		}
		code, err := s.store.CreateDeviceInvite(req.ExpiresAt, time.Now())
		if err != nil {
			httpError(w, 400, "invalid invite lifetime")
			return
		}
		writeJSON(w, 201, map[string]any{"invite": code, "expires_at": req.ExpiresAt})
	case "GET /auth/devices":
		if !user.PlatformAdmin {
			httpError(w, 403, "access denied")
			return
		}
		out, err := s.store.ListDevices()
		if err != nil {
			httpError(w, 500, "device list unavailable")
			return
		}
		writeJSON(w, 200, out)
	case "POST /auth/devices/revoke":
		if !user.PlatformAdmin {
			httpError(w, 403, "access denied")
			return
		}
		var req struct {
			NodeID uint64 `json:"node_id"`
		}
		if decodeJSON(w, r, &req) != nil {
			httpError(w, 400, "invalid node")
			return
		}
		if err := s.store.RevokeDevice(req.NodeID); err != nil {
			httpError(w, 400, "device revoke failed")
			return
		}
		writeJSON(w, 200, map[string]bool{"revoked": true})
	case "POST /auth/users/disable":
		var req struct {
			UserID   uint64 `json:"user_id"`
			Disabled bool   `json:"disabled"`
		}
		if decodeJSON(w, r, &req) != nil {
			httpError(w, 400, "invalid user")
			return
		}
		if err := s.store.DisableUser(user.ID, req.UserID, req.Disabled); err != nil {
			httpError(w, 403, "access denied")
			return
		}
		writeJSON(w, 200, map[string]bool{"updated": true})
	case "POST /auth/password":
		var req struct {
			Old string `json:"old_password"`
			New string `json:"new_password"`
		}
		if decodeJSON(w, r, &req) != nil {
			httpError(w, 400, "invalid password change")
			return
		}
		if err := s.store.ChangePassword(user.ID, req.Old, req.New); err != nil {
			httpError(w, 403, "password change denied")
			return
		}
		writeJSON(w, 200, map[string]bool{"changed": true})
	case "GET /auth/content-key":
		if s.contentKEK == nil {
			httpError(w, http.StatusConflict, "content key service is not configured")
			return
		}
		objectID, err := strconv.ParseUint(r.URL.Query().Get("object_id"), 10, 64)
		generation, genErr := strconv.ParseUint(r.URL.Query().Get("generation"), 10, 64)
		spaceID, spaceErr := requestSpace(r)
		if err != nil || genErr != nil || spaceErr != nil || objectID == 0 || generation == 0 || spaceID == 0 {
			httpError(w, http.StatusBadRequest, "object_id, generation and space are required")
			return
		}
		key, keyErr := s.store.GetContentKey(user.ID, spaceID, objectID, generation)
		if keyErr != nil {
			httpError(w, http.StatusForbidden, "content key unavailable")
			return
		}
		wrapped, decodeErr := base64.RawStdEncoding.DecodeString(key.WrappedDEK)
		if decodeErr != nil {
			httpError(w, http.StatusInternalServerError, "content key is corrupt")
			return
		}
		dek, unwrapErr := contentcrypto.UnwrapDEK(s.contentKEK, objectID, wrapped)
		if unwrapErr != nil {
			httpError(w, http.StatusInternalServerError, "content key cannot be opened")
			return
		}
		// The user is authorized for this exact space/object/generation; return only
		// the DEK bytes over the already authenticated session/TLS channel.
		writeJSON(w, http.StatusOK, types.ContentKeyResponse{
			ObjectID: objectID, Generation: generation, KeyID: key.KeyID,
			DEK: base64.RawStdEncoding.EncodeToString(dek[:]),
		})
	case "POST /auth/content-key/prepare":
		if s.contentKEK == nil {
			httpError(w, http.StatusConflict, "content key service is not configured")
			return
		}
		var req types.PrepareContentKeyRequest
		if decodeJSON(w, r, &req) != nil {
			httpError(w, http.StatusBadRequest, "invalid content key request")
			return
		}
		if req.UploadID < types.StagingInodeBase || req.UploadID > types.MaxStagingInode || req.Index < 0 || req.Index >= types.MaxChunksPerFile {
			httpError(w, http.StatusBadRequest, "invalid content key request")
			return
		}
		spaceID, spaceErr := requestSpace(r)
		if spaceErr != nil || spaceID == 0 {
			httpError(w, http.StatusBadRequest, "space is required")
			return
		}
		key, keyErr := s.store.PrepareContentKey(user.ID, spaceID, types.ChunkID(req.UploadID, req.Index), req.UploadID, s.contentKEK, time.Now())
		if keyErr != nil {
			httpError(w, http.StatusForbidden, "content key denied")
			return
		}
		// 创建/幂等确认 wrapped DEK 后按授权通道解包发放（与 GET 同一出口）。
		wrapped, decodeErr := base64.RawStdEncoding.DecodeString(key.WrappedDEK)
		if decodeErr != nil {
			httpError(w, http.StatusInternalServerError, "content key is corrupt")
			return
		}
		dek, unwrapErr := contentcrypto.UnwrapDEK(s.contentKEK, types.ChunkID(req.UploadID, req.Index), wrapped)
		if unwrapErr != nil {
			httpError(w, http.StatusInternalServerError, "content key cannot be opened")
			return
		}
		writeJSON(w, http.StatusOK, types.ContentKeyResponse{
			ObjectID: types.ChunkID(req.UploadID, req.Index), Generation: req.UploadID, KeyID: key.KeyID,
			DEK: base64.RawStdEncoding.EncodeToString(dek[:]),
		})
	case "GET /auth/capacity":
		spaceID, err := requestSpace(r)
		if err != nil {
			httpError(w, 403, "space required")
			return
		}
		if _, err = s.store.AuthorizeSpace(user.ID, spaceID, false); err != nil {
			httpError(w, 403, "access denied")
			return
		}
		nodes, err := s.store.ListAliveNodes(s.nodeMaxAge)
		if err != nil {
			httpError(w, 500, "capacity unavailable")
			return
		}
		var total, used int64
		for _, node := range nodes {
			if _, err := s.store.DeviceByNode(node.ID); err == nil {
				total += node.TotalBytes
				used += node.UsedBytes
			}
		}
		writeJSON(w, 200, map[string]int64{"total_bytes": total, "used_bytes": used})
	case "POST /auth/files/empty":
		s.serveSecureEmpty(w, r, user)
	default:
		httpError(w, http.StatusForbidden, "access denied")
	}
}

func requestSpace(r *http.Request) (uint64, error) {
	values := r.Header.Values(access.SpaceHeader)
	if len(values) != 1 {
		return 0, meta.ErrAuthentication
	}
	id, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil || id == 0 {
		return 0, meta.ErrAuthentication
	}
	return id, nil
}

func spacePath(root, remote string) (string, error) {
	if remote == "" || len(remote) > 8192 || strings.ContainsAny(remote, "\\\x00") {
		return "", meta.ErrBadPath
	}
	for _, part := range strings.Split(remote, "/") {
		if part == ".." {
			return "", meta.ErrOutsideSpace
		}
	}
	clean := path.Clean("/" + remote)
	if clean == "/" {
		return root, nil
	}
	return root + clean, nil
}

func readSecurityJSON(r *http.Request) (map[string]json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		return nil, errors.New("request too large")
	}
	var out map[string]json.RawMessage
	if json.Unmarshal(data, &out) != nil || out == nil {
		return nil, errors.New("invalid JSON")
	}
	return out, nil
}
func resetSecurityJSON(r *http.Request, body map[string]json.RawMessage) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	return nil
}
func jsonUint(m map[string]json.RawMessage, k string) uint64 {
	var id uint64
	_ = json.Unmarshal(m[k], &id)
	return id
}
func jsonString(m map[string]json.RawMessage, k string) string {
	var v string
	_ = json.Unmarshal(m[k], &v)
	return v
}
func setJSON(m map[string]json.RawMessage, k string, v any) { m[k], _ = json.Marshal(v) }

func (s *Server) serveSpaceRequest(w http.ResponseWriter, r *http.Request, next http.Handler, user meta.PublicUser) {
	spaceID, err := requestSpace(r)
	if err != nil {
		httpError(w, 403, "space required")
		return
	}
	write := r.Method != http.MethodGet && r.URL.Path != "/files/chunks/suspect" && r.URL.Path != "/files/suspect"
	space, err := s.store.AuthorizeSpace(user.ID, spaceID, write)
	if err != nil {
		httpError(w, 403, "access denied")
		return
	}
	key := r.Method + " " + r.URL.Path
	r = r.Clone(r.Context())
	copyURL := *r.URL
	r.URL = &copyURL
	query := r.URL.Query()
	switch key {
	case "POST /writes", "POST /writes/chunks", "POST /writes/chunks/recover", "GET /writes/status", "GET /writes/transfer-nodes", "POST /writes/commit", "POST /writes/abort", "GET /protection", "POST /protection":
		// These handlers bind actor and space inside the metadata transaction.
	case "GET /meta", "GET /dirs/children", "DELETE /entry":
		remote, err := spacePath(space.InternalPath, query.Get("path"))
		if err != nil {
			httpError(w, 403, "path outside space")
			return
		}
		if write && remote == space.InternalPath {
			httpError(w, 403, "space root is protected")
			return
		}
		query.Set("path", remote)
		r.URL.RawQuery = query.Encode()
	case "POST /files/small":
		remote, err := spacePath(space.InternalPath, query.Get("path"))
		if err != nil || remote == space.InternalPath {
			httpError(w, 403, "invalid space path")
			return
		}
		query.Set("path", remote)
		if op := query.Get("op_id"); op != "" {
			query.Set("op_id", scopedOp(user.ID, spaceID, "small", op))
		}
		r.URL.RawQuery = query.Encode()
	case "POST /dirs", "POST /entry/rename", "POST /files/symlink", "POST /files":
		body, err := readSecurityJSON(r)
		if err != nil {
			httpError(w, 400, "invalid request")
			return
		}
		remote, err := spacePath(space.InternalPath, jsonString(body, "path"))
		if err != nil || remote == space.InternalPath {
			httpError(w, 403, "invalid space path")
			return
		}
		if key == "POST /files" {
			s.serveSecureCreate(w, r, user, space, body, remote)
			return
		}
		if key == "POST /files/symlink" {
			target := jsonString(body, "target")
			base := strings.TrimPrefix(path.Dir("/"+jsonString(body, "path")), "/")
			clean := path.Clean(path.Join(base, target))
			if strings.HasPrefix(target, "/") || strings.Contains(target, "\\") || strings.Contains(target, "\x00") || clean == ".." || strings.HasPrefix(clean, "../") {
				httpError(w, 403, "symlink target outside space")
				return
			}
		}
		setJSON(body, "path", remote)
		if resetSecurityJSON(r, body) != nil {
			httpError(w, 400, "invalid request")
			return
		}
	case "POST /files/chunks", "POST /files/commit":
		body, err := readSecurityJSON(r)
		if err != nil {
			httpError(w, 400, "invalid request")
			return
		}
		id := jsonUint(body, "inode_id")
		if key == "POST /files/commit" {
			count := jsonUint(body, "chunk_count")
			if count == 0 {
				httpError(w, 403, "legacy commit is disabled in secure mode")
				return
			}
			if op := jsonString(body, "op_id"); op != "" {
				fingerprintBytes, _ := json.Marshal(body)
				op = scopedOp(user.ID, spaceID, "commit", op)
				binding := meta.SecureCommitBinding{OpID: op, Fingerprint: meta.BodySHA256(fingerprintBytes)}
				if rec, ok, err := s.store.GetOpResult(op); err != nil {
					httpError(w, 500, "operation unavailable")
					return
				} else if ok {
					if rec.Kind != "commit" || rec.Fingerprint != binding.Fingerprint {
						httpError(w, 409, "operation ID conflict")
						return
					}
					if s.store.InodeInSpace(spaceID, rec.Inode.ID) != nil {
						httpError(w, 403, "access denied")
						return
					}
					if s.store.EnsureDurable() != nil {
						httpError(w, 503, "operation not confirmed")
						return
					}
					writeJSON(w, 200, rec.Inode)
					return
				}
				setJSON(body, "op_id", op)
				r = r.WithContext(withSecureCommit(r.Context(), binding))
			}
		} else if _, ok := body["checksum"]; !ok {
			httpError(w, 400, "recorded checksum required")
			return
		}
		u, err := s.store.AuthorizeSecureUpload(user.ID, spaceID, id)
		if err != nil {
			httpError(w, 403, "access denied")
			return
		}
		if key == "POST /files/commit" && jsonString(body, "name") != u.Name {
			httpError(w, 403, "upload name mismatch")
			return
		}
		if resetSecurityJSON(r, body) != nil {
			httpError(w, 400, "invalid request")
			return
		}
	case "POST /files/chunks/suspect", "POST /files/suspect":
		body, err := readSecurityJSON(r)
		if err != nil {
			httpError(w, 400, "invalid request")
			return
		}
		if s.store.InodeInSpace(spaceID, jsonUint(body, "inode_id")) != nil {
			httpError(w, 403, "access denied")
			return
		}
		_ = resetSecurityJSON(r, body)
	default:
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/files/staging/") {
			id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/files/staging/"), 10, 64)
			if err != nil {
				httpError(w, 403, "access denied")
				return
			}
			if _, err := s.store.AuthorizeSecureUpload(user.ID, spaceID, id); err != nil {
				httpError(w, 403, "access denied")
				return
			}
		} else {
			httpError(w, 403, "access denied")
			return
		}
	}
	next.ServeHTTP(w, r)
}

func scopedOp(user, space uint64, kind, op string) string {
	return fmt.Sprintf("secure:%d:%d:%s:%s", user, space, kind, meta.BodySHA256([]byte(op)))
}

func (s *Server) serveSecureCreate(w http.ResponseWriter, r *http.Request, user meta.PublicUser, space meta.Space, body map[string]json.RawMessage, remote string) {
	var chunked, overwrite bool
	_ = json.Unmarshal(body["chunked"], &chunked)
	_ = json.Unmarshal(body["overwrite"], &overwrite)
	if !chunked {
		httpError(w, 403, "secure uploads require immutable chunks")
		return
	}
	parentPath, name := splitPath(remote)
	parent, err := s.store.ResolvePath(parentPath)
	if err != nil {
		httpError(w, 404, "parent not found")
		return
	}
	in, err := s.store.CreateSecureUpload(user.ID, space.ID, parent.ID, name, overwrite, time.Now())
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"inode": in, "nodes": []types.NodeInfo{}})
}

func (s *Server) serveSecureEmpty(w http.ResponseWriter, r *http.Request, user meta.PublicUser) {
	spaceID, err := requestSpace(r)
	if err != nil {
		httpError(w, 403, "space required")
		return
	}
	space, err := s.store.AuthorizeSpace(user.ID, spaceID, true)
	if err != nil {
		httpError(w, 403, "access denied")
		return
	}
	var req struct {
		Path      string `json:"path"`
		Overwrite bool   `json:"overwrite"`
	}
	if decodeJSON(w, r, &req) != nil {
		httpError(w, 400, "invalid empty file request")
		return
	}
	remote, err := spacePath(space.InternalPath, req.Path)
	if err != nil || remote == space.InternalPath {
		httpError(w, 403, "invalid path")
		return
	}
	parentPath, name := splitPath(remote)
	parent, err := s.store.ResolvePath(parentPath)
	if err != nil {
		httpError(w, 404, "parent not found")
		return
	}
	in, old, replaced, err := s.store.CreateSecureEmpty(user.ID, spaceID, parent.ID, name, req.Overwrite, time.Now())
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	if replaced {
		s.reclaimReplacedObject(old)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"inode": in})
}

func (s *Server) allowDeviceMetadata(w http.ResponseWriter, r *http.Request, device meta.DeviceRecord) bool {
	key := r.Method + " " + r.URL.Path
	if key == "GET /files/replication" {
		nodeID, _ := strconv.ParseUint(r.URL.Query().Get("node_id"), 10, 64)
		if nodeID != device.NodeID {
			httpError(w, 403, "device mismatch")
			return false
		}
		return true
	}
	if key == "POST /nodes/transfer-observation" || key == "GET /nodes/transfer-peers" {
		return true
	}
	if key != "POST /nodes/heartbeat" && key != "POST /files/replicated/verified" && key != "POST /files/replicated/present" && key != "POST /files/objects/suspect" && key != "POST /files/protection/progress" && key != "POST /files/writes/progress" && key != "POST /files/writes/progress/begin" {
		httpError(w, 403, "device operation denied")
		return false
	}
	body, err := readSecurityJSON(r)
	if err != nil {
		httpError(w, 400, "invalid device request")
		return false
	}
	if key == "POST /files/objects/suspect" {
		var object types.ObjectIntegrity
		_ = json.Unmarshal(body["object"], &object)
		d, err := s.store.ObjectIntegrity(object.ObjectID)
		if err != nil {
			httpError(w, 403, "object not assigned")
			return false
		}
		if !types.ContainsUint64(d.Replicas, jsonUint(body, "node_id")) {
			httpError(w, 403, "target not assigned")
			return false
		}
		if !types.ContainsUint64(d.Replicas, device.NodeID) {
			if _, err := s.store.ProtectionDescriptor(object.PlanID, object.ObjectID, device.NodeID); err != nil {
				httpError(w, 403, "reporter not assigned")
				return false
			}
		}
	} else if jsonUint(body, "node_id") != device.NodeID {
		httpError(w, 403, "device mismatch")
		return false
	}
	if key == "POST /nodes/heartbeat" {
		var used int64
		if json.Unmarshal(body["used_bytes"], &used) != nil || used < 0 {
			httpError(w, 400, "invalid used bytes")
			return false
		}
	}
	if resetSecurityJSON(r, body) != nil {
		httpError(w, 400, "invalid request")
		return false
	}
	return true
}

func (s *Server) secureControlTransport(base http.RoundTripper) http.RoundTripper {
	return &access.Transport{Base: base, Authorize: func(r *http.Request) error {
		if r.URL == nil || r.URL.Host == "" || r.URL.User != nil || r.URL.Opaque != "" || r.URL.RawPath != "" || r.URL.Fragment != "" || r.URL.RawFragment != "" ||
			(r.Host != "" && !strings.EqualFold(r.Host, r.URL.Host)) {
			return errors.New("ambiguous control request destination")
		}
		if r.URL.Scheme != s.nodeScheme() {
			return errors.New("control transport scheme mismatch")
		}
		r.Header.Del("Authorization")
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			return nil
		}
		req := access.TicketRequest{NodeAddr: r.URL.Host, Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, PlanID: r.Header.Get(access.PlanHeader)}
		_, retirement := types.RetirementPathID(r.URL.Path)
		if r.URL.Path == "/pull" || retirement {
			if r.GetBody == nil {
				return errors.New("control request body is not replayable")
			}
			body, err := r.GetBody()
			if err != nil {
				return err
			}
			defer body.Close()
			raw, err := io.ReadAll(io.LimitReader(body, 64<<10+1))
			if err != nil || len(raw) > 64<<10 {
				return errors.New("control request body too large")
			}
			req.BodyHash = meta.BodySHA256(raw)
		}
		ticket, err := s.store.IssueControlTicket(req, time.Now())
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+ticket.Token)
		return nil
	}}
}

func (s *Server) AttachSecureTransports() {
	if s.security == nil {
		return
	}
	base := auth.HTTPTransport("", s.tlsCfg, nil).Fallback
	if s.scanner != nil {
		s.scanner.scheme = s.nodeScheme()
		s.scanner.httpClient.Transport = s.secureControlTransport(base)
		s.scanner.httpClient.CheckRedirect = rejectRedirect
	}
	if s.autonomy != nil {
		s.autonomy.scheme = s.nodeScheme()
		s.autonomy.http.Transport = s.secureControlTransport(base)
		s.autonomy.http.CheckRedirect = rejectRedirect
	}
	if s.backup != nil {
		if s.backup.EncryptionEnabled() {
			// 加密已开启：备份 blob 走在线控制票据到节点（validateControlTicket
			// 允许 GET/PUT/DELETE /meta-backup）。节点只见密文。
			s.backup.httpClient.Transport = s.secureControlTransport(base)
		} else {
			// 无加密的 secure 模式仍禁远端备份：账号元数据不能明文进陌生节点。
			s.backup.httpClient.Transport = securityRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("remote metadata backup requires an encrypted backup key in secure mode")
			})
		}
		s.backup.httpClient.CheckRedirect = rejectRedirect
	}
}

func rejectRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (s *Server) StartSecurity(ctx context.Context) {
	if s.security == nil {
		return
	}
	s.security.startOnce.Do(func() {
		s.security.wg.Add(1)
		go func() {
			defer s.security.wg.Done()
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-ticker.C:
					if _, err := s.store.SweepSecurityState(now); err != nil {
						log.Printf("security state cleanup: %v", err)
					}
				}
			}
		}()
	})
}

func (s *Server) WaitSecurity() {
	if s.security != nil {
		s.security.wg.Wait()
	}
}
