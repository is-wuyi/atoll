package master

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"atoll/internal/peertrace"
	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"
)

type PeerConfig struct {
	Origin         string
	Infrastructure peerauth.Infrastructure
}

type serverPeer struct {
	config    PeerConfig
	runtime   peertransport.RuntimeAPI
	transport *peerhttp.Transport
	startOnce sync.Once
	wg        sync.WaitGroup
}

func (s *Server) EnablePeerDirectory(cfg PeerConfig) error {
	if s.peers != nil || s.security == nil || s.security.config.AllowInsecure || s.nodeScheme() != "https" || s.tlsCfg == nil || s.tlsCfg.InsecureSkipVerify || s.writePlanner == nil {
		return errors.New("peer directory requires a secure HTTPS Master with write planning")
	}
	origin, err := peerauth.CanonicalOrigin(cfg.Origin)
	if err != nil {
		return err
	}
	cfg.Origin = origin
	cfg.Infrastructure = peerauth.CopyDirectory(peerauth.Directory{Infrastructure: cfg.Infrastructure}).Infrastructure
	if err := s.store.ConfigurePeerDirectory(origin, cfg.Infrastructure); err != nil {
		return err
	}
	s.peers = &serverPeer{config: cfg}
	return nil
}

func (s *Server) SetPeerRuntime(runtime peertransport.RuntimeAPI) error {
	if s.peers == nil || runtime == nil || runtime.PeerID() != s.peers.config.Infrastructure.PeerID || !bytes.Equal(runtime.PublicKey(), s.peers.config.Infrastructure.PublicKey) || s.peers.runtime != nil {
		return errors.New("peer runtime does not match the Master identity")
	}
	directory, err := s.store.PeerDirectory(time.Now(), s.nodeMaxAge)
	if err != nil {
		return err
	}
	if err := runtime.SetDirectory(directory); err != nil {
		return err
	}
	runtime.SetAuthorizer(func(ctx context.Context, id string) bool {
		if ctx.Err() != nil {
			return false
		}
		allowed, err := s.store.PeerAllowed(id, time.Now(), s.nodeMaxAge)
		return err == nil && allowed
	})
	resolver := func(ctx context.Context, addr string) (peerhttp.PeerDialer, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		endpoint, err := s.store.PeerEndpointByAddr(addr, time.Now(), s.nodeMaxAge)
		if err != nil {
			return nil, err
		}
		directory, err := s.store.PeerDirectory(time.Now(), s.nodeMaxAge)
		if err != nil {
			return nil, err
		}
		if err := runtime.SetDirectory(directory); err != nil {
			return nil, err
		}
		return func(dialCtx context.Context) peerhttp.PeerDial {
			path, _ := peerhttp.RequiredPath(dialCtx)
			result := runtime.Dial(dialCtx, endpoint, directory.Infrastructure, path).PeerDial
			if result.Conn != nil || dialCtx.Err() != nil {
				return result
			}
			updated, err := s.store.PeerEndpointByAddr(addr, time.Now(), s.nodeMaxAge)
			if err != nil {
				return peerhttp.PeerDial{Err: err}
			}
			fresh, err := s.store.PeerDirectory(time.Now(), s.nodeMaxAge)
			if err != nil {
				return peerhttp.PeerDial{Err: err}
			}
			if err := runtime.SetDirectory(fresh); err != nil {
				return peerhttp.PeerDial{Err: err}
			}
			return runtime.Dial(dialCtx, updated, fresh.Infrastructure, path).PeerDial
		}, nil
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = s.tlsCfg.Clone()
	transport, err := peerhttp.NewTransport(base, peerhttp.WithMaster(s.peers.config.Origin), peerhttp.WithResolver(resolver))
	if err != nil {
		return err
	}
	if err := runtime.EnableRelay(); err != nil {
		transport.Close()
		return err
	}
	s.peers.runtime = runtime
	s.peers.transport = transport
	return nil
}

func (s *Server) StartPeers(ctx context.Context) {
	if s.peers == nil || s.peers.runtime == nil {
		return
	}
	s.peers.startOnce.Do(func() {
		s.peers.wg.Add(1)
		go func() {
			defer s.peers.wg.Done()
			ticker := time.NewTicker(25 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					infrastructure := s.peers.config.Infrastructure
					infrastructure.Addresses = s.peers.runtime.Addresses()
					if err := s.store.ConfigurePeerDirectory(s.peers.config.Origin, infrastructure); err != nil {
						log.Printf("peer infrastructure address publication failed: %v", err)
					}
				}
			}
		}()
	})
}

func (s *Server) WaitPeers() {
	if s.peers != nil {
		s.peers.wg.Wait()
		if s.peers.transport != nil {
			s.peers.transport.Close()
		}
	}
}

func (s *Server) servePeers(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/peers/") {
		return false
	}
	if s.peers == nil {
		httpError(w, http.StatusConflict, "peer directory is disabled")
		return true
	}
	peertrace.Mark(r.Context(), "authorization_start")
	now := time.Now()
	token := bearer(r)
	isDevice := strings.HasPrefix(token, "nd1_")
	var spaceID uint64
	if isDevice {
		if _, err := s.store.DeviceForSession(token, now); err != nil {
			httpError(w, http.StatusUnauthorized, "device authentication failed")
			return true
		}
	} else {
		user, err := s.store.UserForSession(token, now)
		if err != nil {
			httpError(w, http.StatusUnauthorized, "authentication failed")
			return true
		}
		spaceID, err = requestSpace(r)
		if err != nil {
			httpError(w, http.StatusForbidden, "space required")
			return true
		}
		if _, err := s.store.AuthorizeSpace(user.ID, spaceID, false); err != nil {
			httpError(w, http.StatusForbidden, "access denied")
			return true
		}
	}
	peertrace.Mark(r.Context(), "authorization_done")
	key := r.Method + " " + r.URL.Path
	if key != "GET /peers/client-self" && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
		httpError(w, http.StatusBadRequest, "peer operation does not accept query parameters")
		return true
	}
	switch key {
	case "GET /peers/directory":
		peertrace.Mark(r.Context(), "directory_read_start")
		directory, err := s.store.PeerDirectory(now, s.nodeMaxAge)
		peertrace.Mark(r.Context(), "directory_read_done")
		if err != nil {
			httpError(w, http.StatusServiceUnavailable, "peer directory unavailable")
			break
		}
		writeJSON(w, http.StatusOK, directory)
		peertrace.Mark(r.Context(), "response_written")
	case "GET /peers/self":
		if !isDevice {
			httpError(w, http.StatusForbidden, "device operation required")
			break
		}
		state, err := s.store.NodePeerState(token, now)
		if err != nil {
			httpError(w, http.StatusForbidden, "peer state denied")
			break
		}
		writeJSON(w, http.StatusOK, state)
	case "GET /peers/client-self":
		if isDevice {
			httpError(w, http.StatusForbidden, "user operation required")
			break
		}
		query := r.URL.Query()
		if len(query) != 1 || len(query["peer_id"]) != 1 || !peerauth.ValidID(query.Get("peer_id")) || r.URL.ForceQuery {
			httpError(w, http.StatusBadRequest, "invalid client peer query")
			break
		}
		state, err := s.store.ClientPeerState(token, spaceID, query.Get("peer_id"), now)
		if err != nil {
			httpError(w, http.StatusForbidden, "client peer state denied")
			break
		}
		writeJSON(w, http.StatusOK, state)
	case "POST /peers/address":
		if !isDevice {
			httpError(w, http.StatusForbidden, "device operation required")
			break
		}
		var req peerauth.AddressPublication
		if err := peerauth.DecodeJSON(r.Body, &req); err != nil {
			httpError(w, http.StatusBadRequest, "invalid peer address publication")
			break
		}
		endpoint, err := s.store.PublishPeerAddress(token, req, time.Now())
		if err != nil {
			httpError(w, http.StatusConflict, "peer address publication rejected")
			break
		}
		writeJSON(w, http.StatusOK, endpoint)
	case "POST /peers/client":
		if isDevice {
			httpError(w, http.StatusForbidden, "user operation required")
			break
		}
		var req peerauth.ClientRegistration
		if err := peerauth.DecodeJSON(r.Body, &req); err != nil {
			httpError(w, http.StatusBadRequest, "invalid client peer registration")
			break
		}
		endpoint, err := s.store.RegisterClientPeer(token, spaceID, req, time.Now())
		if err != nil {
			httpError(w, http.StatusConflict, "client peer registration rejected")
			break
		}
		writeJSON(w, http.StatusOK, endpoint)
	case "POST /peers/client/release":
		if isDevice {
			httpError(w, http.StatusForbidden, "user operation required")
			break
		}
		var req peerauth.ClientRegistration
		if err := peerauth.DecodeJSON(r.Body, &req); err != nil {
			httpError(w, http.StatusBadRequest, "invalid client peer release")
			break
		}
		state, err := s.store.ReleaseClientPeer(token, spaceID, req, time.Now())
		if err != nil {
			httpError(w, http.StatusConflict, "client peer release rejected")
			break
		}
		writeJSON(w, http.StatusOK, state)
	default:
		httpError(w, http.StatusNotFound, "peer operation not found")
	}
	return true
}
