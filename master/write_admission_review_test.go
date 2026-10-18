package master

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"atoll/client"
	"atoll/pkg/access"
	"atoll/pkg/types"
)

func plannedSecureJSON(t *testing.T, cl *secCluster, method, endpoint, token string, space uint64, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, cl.master.URL+endpoint, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(access.SpaceHeader, strconv.FormatUint(space, 10))
	req.Header.Set(types.FeaturesHeader, types.WritePlanFeature)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestWritePlanningHTTPActorAndReplayBinding(t *testing.T) {
	cl := newSecureCluster(t, 0)
	if err := cl.srv.EnableWritePlanning(WritePlanningConfig{}); err != nil {
		t.Fatal(err)
	}
	_, adminToken := cl.adminLogin()
	_, aliceSpace := cl.secCreateUser(adminToken, "httpalice")
	_, bobSpace := cl.secCreateUser(adminToken, "httpbob")
	_, alice := cl.secLogin("httpalice", secUserPassword)
	_, bob := cl.secLogin("httpbob", secUserPassword)
	begin := types.BeginWriteRequest{Path: "/empty", OpID: "begin-actor", Size: 0}
	resp := plannedSecureJSON(t, cl, http.MethodPost, "/writes", alice.Token, aliceSpace, begin)
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		t.Fatal(resp.StatusCode)
	}
	var out types.BeginWriteResponse
	secDecode(t, resp, &out)
	commit := types.CommitWriteRequest{WriteBinding: types.WriteBinding{UploadID: out.Upload.ID, PlanID: out.Upload.PlanID, Revision: out.Upload.Revision}, OpID: "commit-actor", Size: 0}
	for _, tc := range []struct {
		name, token string
		space       uint64
	}{
		{"other-user", bob.Token, aliceSpace},
		{"other-space", alice.Token, bobSpace},
		{"admin-not-origin", adminToken, aliceSpace},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := plannedSecureJSON(t, cl, http.MethodPost, "/writes/commit", tc.token, tc.space, commit)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("foreign actor committed upload: status=%d", resp.StatusCode)
			}
		})
	}
	resp = plannedSecureJSON(t, cl, http.MethodPost, "/writes/commit", alice.Token, aliceSpace, commit)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatal(resp.StatusCode)
	}
	var first types.CommitWriteResponse
	secDecode(t, resp, &first)
	resp = plannedSecureJSON(t, cl, http.MethodPost, "/writes/commit", alice.Token, aliceSpace, commit)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatal(resp.StatusCode)
	}
	var replay types.CommitWriteResponse
	secDecode(t, resp, &replay)
	if replay.Inode.ID != first.Inode.ID || replay.Inode.Generation != first.Inode.Generation || replay.Inode.Content.ID != first.Inode.Content.ID {
		t.Fatal("commit replay changed published identity")
	}
	commit.Size = 1
	resp = plannedSecureJSON(t, cl, http.MethodPost, "/writes/commit", alice.Token, aliceSpace, commit)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("changed commit replay status=%d", resp.StatusCode)
	}
}

func TestWritePlanningNodeRevokedAfterUploadCannotPublish(t *testing.T) {
	cl := newSecureCluster(t, 0)
	if err := cl.srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 1}); err != nil {
		t.Fatal(err)
	}
	invite, err := cl.store.CreateDeviceInvite(time.Now().Add(time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	n := cl.startNode(filepath.Join(t.TempDir(), "node"), invite)
	cl.nodes = append(cl.nodes, n)
	_, token := cl.adminLogin()
	_, _ = cl.secCreateUser(token, "revokeplanned")
	c, _ := cl.secLogin("revokeplanned", secUserPassword)
	base := c.HTTP.Transport
	var revoked atomic.Bool
	c.HTTP.Transport = writeTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/writes/commit" && !revoked.Swap(true) {
			if err := cl.store.RevokeDevice(n.node.NodeIDForTest()); err != nil {
				if r.Body != nil {
					r.Body.Close()
				}
				return nil, err
			}
			resp, err := base.RoundTrip(r)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Error("revoked required node was accepted for publication")
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			return &http.Response{StatusCode: http.StatusConflict, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(`{"code":"write_plan_conflict","error":"test stops after checking first commit"}`)), Request: r}, nil
		}
		return base.RoundTrip(r)
	})
	_, err = c.PutSmall("/blocked", []byte("persist but do not publish"), 1, false)
	if err == nil || !client.IsPlannedWriteError(err) || !revoked.Load() {
		t.Fatalf("upload result=%v revoked=%v", err, revoked.Load())
	}
	if _, _, err := c.Lookup("/blocked"); err == nil {
		t.Fatal("revoked node upload became visible")
	}
}

func TestWritePlanningProtectedRootPathRejection(t *testing.T) {
	cl := newSecureCluster(t, 0)
	if err := cl.srv.EnableWritePlanning(WritePlanningConfig{}); err != nil {
		t.Fatal(err)
	}
	admin, token := cl.adminLogin()
	_ = admin
	_, space := cl.secCreateUser(token, "plannedpaths")
	_, user := cl.secLogin("plannedpaths", secUserPassword)
	for i, path := range []string{"/", "/../escape", "/dir/../../escape", "/bad\\path", "/bad\x00path"} {
		resp := plannedSecureJSON(t, cl, http.MethodPost, "/writes", user.Token, space, types.BeginWriteRequest{Path: path, Size: 0, OpID: fmt.Sprint("path-", i)})
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			t.Errorf("invalid path accepted %q", path)
		}
	}
}
