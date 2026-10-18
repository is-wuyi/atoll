package master

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/access"
	"atoll/pkg/types"
)

func TestWritePlanningHTTPGates(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := NewServer(store, time.Hour)
	if err = srv.EnableWritePlanning(WritePlanningConfig{}); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	for _, p := range []string{"/files", "/files/small", "/files/chunks", "/files/commit", "/auth/files/empty", "//files", "/a/../files"} {
		r := httptest.NewRequest(http.MethodPost, p, strings.NewReader("{}"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 426 {
			t.Errorf("legacy %s status=%d", p, w.Code)
		}
	}
	for _, p := range []string{"/writes", "/writes/chunks", "/writes/commit", "/writes/abort", "/protection"} {
		r := httptest.NewRequest(http.MethodPost, p, strings.NewReader("{}"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 426 {
			t.Errorf("no feature %s status=%d", p, w.Code)
		}
	}
	for _, body := range []string{`{"path":"/f","op_id":"x","size":0,"min_copies":0}`, `{"path":"/f","op_id":"x","size":0} {}`, `{"path":"/f","op_id":"x","size":0,"tier":"performance"}`} {
		r := httptest.NewRequest(http.MethodPost, "/writes", strings.NewReader(body))
		r.Header.Set(types.FeaturesHeader, types.WritePlanFeature)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Errorf("unknown/extra JSON accepted %d %s", w.Code, w.Body)
		}
	}
	badStartup := NewServer(store, time.Hour).Handler()
	for _, p := range []string{"/capabilities", "/meta?path=/", "/writes", "/files"} {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		badStartup.ServeHTTP(w, r)
		if w.Code != 503 {
			t.Errorf("missing startup flag %s status=%d", p, w.Code)
		}
	}
}

func TestWritePlanningSecureDirectUploadAndRevocation(t *testing.T) {
	cl := newSecureCluster(t, 0)
	if err := cl.srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 3}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		invite, err := cl.store.CreateDeviceInvite(time.Now().Add(time.Hour), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		cl.nodes = append(cl.nodes, cl.startNode(filepath.Join(t.TempDir(), "node"), invite))
	}
	admin, token := cl.adminLogin()
	user, space := cl.secCreateUser(token, "planneduser")
	c, login := cl.secLogin("planneduser", secUserPassword)
	data := []byte("secure planned direct payload")
	in, err := c.PutSmall("/planned", data, 99, false)
	if err != nil {
		t.Fatal(err)
	}
	if in.Content == nil || len(in.Content.Extents) != 1 {
		t.Fatalf("missing content %+v", in)
	}
	file := filepath.Join(t.TempDir(), "read")
	if err = c.Get("/planned", file); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(raw, data) {
		t.Fatal("read mismatch")
	}
	if err = c.PutReaderOverwrite("/empty", 0, bytes.NewReader(nil), 99, false); err != nil {
		t.Fatal(err)
	}
	if _, err = c.SetProtection("/", types.ProtectionSecurity); err != nil {
		t.Fatal(err)
	}
	team, err := cl.store.CreateTeam(user.ID, "planned team")
	if err != nil {
		t.Fatal(err)
	}
	member, memberSpace := cl.secCreateUser(token, "plannedmember")
	if err = cl.store.SetTeamMember(user.ID, team.ID, member.ID, meta.RoleWrite); err != nil {
		t.Fatal(err)
	}
	mc, _ := cl.secLogin("plannedmember", secUserPassword)
	if err = mc.UseSpace(team.ID); err != nil {
		t.Fatal(err)
	}
	_ = memberSpace
	base := mc.HTTP.Transport
	var revoked atomic.Bool
	mc.HTTP.Transport = writeTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/writes/commit" && !revoked.Swap(true) {
			if err := cl.store.RemoveTeamMember(user.ID, team.ID, member.ID); err != nil {
				return nil, err
			}
		}
		return base.RoundTrip(r)
	})
	if _, err = mc.PutSmall("/denied", data, 1, false); err == nil {
		t.Fatal("revoked member published")
	}
	if _, err = cl.store.ResolvePath(team.InternalPath + "/denied"); !errors.Is(err, meta.ErrNotExist) {
		t.Fatalf("revoked path visible: %v", err)
	}
	if err = admin.UseSpace(space); err != nil {
		t.Fatal(err)
	}
	if err = admin.Get("/planned", file); err != nil {
		t.Fatalf("platform admin read denied: %v", err)
	}
	if err = c.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := secRawJSON(t, http.MethodGet, cl.master.URL+"/meta?path=/planned", login.Token, space, nil)
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("revoked session=%d", r.StatusCode)
	}
}

type writeTestTransport func(*http.Request) (*http.Response, error)

func (f writeTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWritePlanningSecureCapabilitiesRequireTLS(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err = store.BootstrapSecurity("admin", secAdminPassword, time.Now()); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, time.Hour)
	if err = srv.EnableSecurity(SecurityConfig{ControlToken: secControlToken}); err != nil {
		t.Fatal(err)
	}
	if err = srv.EnableWritePlanning(WritePlanningConfig{}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/capabilities", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != 426 {
		t.Fatalf("plaintext discovery status=%d", w.Code)
	}
	tlsServer := httptest.NewTLSServer(srv.Handler())
	defer tlsServer.Close()
	resp, err := tlsServer.Client().Get(tlsServer.URL + "/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var caps types.Capabilities
	if err = json.NewDecoder(resp.Body).Decode(&caps); err != nil || !caps.WritePlanning || resp.StatusCode != 200 {
		t.Fatalf("TLS capabilities %+v %v", caps, err)
	}
}

func TestWritePlanningSecureControlCredentialNotWriter(t *testing.T) {
	cl := newSecureCluster(t, 0)
	if err := cl.srv.EnableWritePlanning(WritePlanningConfig{}); err != nil {
		t.Fatal(err)
	}
	_, token := cl.adminLogin()
	user, space := cl.secCreateUser(token, "plancontrol")
	_ = user
	for _, credential := range []string{secControlToken, secAdminToken} {
		raw, _ := json.Marshal(types.BeginWriteRequest{Path: "/f", OpID: "test", Size: 0})
		req, _ := http.NewRequest(http.MethodPost, cl.master.URL+"/writes", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+credential)
		req.Header.Set(access.SpaceHeader, strconv.FormatUint(space, 10))
		req.Header.Set(types.FeaturesHeader, types.WritePlanFeature)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("control wrote: %d", resp.StatusCode)
		}
	}
}
