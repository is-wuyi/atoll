package master

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
)

func TestSecureDeviceTicketAuthenticationStatus(t *testing.T) {
	c := newSecureCluster(t, 0)
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	login := func(now time.Time, invite string) access.DeviceSession {
		t.Helper()
		ch, err := c.store.NewDeviceChallenge(access.DeviceChallengeRequest{
			PublicKey: id.PublicKey(), Addr: "127.0.0.1:59811", TotalBytes: 1024, Invite: invite,
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := id.Sign(ch.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := c.store.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, now)
		if err != nil {
			t.Fatal(err)
		}
		return sess
	}
	check := func(label, token string, want int) {
		t.Helper()
		res := secRawJSON(t, http.MethodPost, c.master.URL+"/security/tickets", token, 0,
			access.TicketRequest{NodeAddr: "127.0.0.1:59811", Method: http.MethodGet, Path: "/objects/42"})
		res.Body.Close()
		if res.StatusCode != want {
			t.Errorf("%s status = %d, want %d", label, res.StatusCode, want)
		}
	}
	old := time.Now().Add(-time.Hour)
	invite, err := c.store.CreateDeviceInvite(old.Add(time.Hour), old)
	if err != nil {
		t.Fatal(err)
	}
	expired := login(old, invite)
	check("unknown session", "nd1_unknown", http.StatusUnauthorized)
	check("expired session", expired.Token, http.StatusUnauthorized)
	current := login(time.Now(), "")
	check("authenticated but unauthorized object", current.Token, http.StatusForbidden)
	rotated := login(time.Now(), "")
	check("rotated session", current.Token, http.StatusUnauthorized)
	if err := c.store.RevokeDevice(rotated.NodeID); err != nil {
		t.Fatal(err)
	}
	check("revoked device", rotated.Token, http.StatusUnauthorized)
}

func TestSecureNodeRenewsInvalidatedFreshSession(t *testing.T) {
	c := newSecureCluster(t, 1)
	user, _ := c.adminLogin()
	body := []byte("fresh session recovery must contact the real master")
	in, err := user.PutSmall("/session-recovery", body, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	waitSecureCopies(t, c, in.ObjID, 1)
	n := c.nodes[0]
	before, err := c.store.DeviceByNode(n.node.NodeIDForTest())
	if err != nil {
		t.Fatal(err)
	}
	id, err := edgeidentity.LoadOrCreate(filepath.Join(filepath.Dir(n.node.DataDirForTest()), "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	ch, err := c.store.NewDeviceChallenge(access.DeviceChallengeRequest{
		PublicKey: id.PublicKey(), Addr: n.addr(), TotalBytes: 1 << 30,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := id.Sign(ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CompleteDeviceChallenge(access.DeviceLoginRequest{ChallengeID: ch.ID, Signature: sig}, time.Now()); err != nil {
		t.Fatal(err)
	}
	res, err := user.HTTP.Get(n.server.URL + fmt.Sprintf("/objects/%d", in.ObjID))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != http.StatusOK || !bytes.Equal(got, body) {
		t.Fatalf("node did not renew its rejected fresh session: status %d, error %v", res.StatusCode, err)
	}
	after, err := c.store.DeviceByNode(n.node.NodeIDForTest())
	if err != nil || after.SessionVersion != before.SessionVersion+2 {
		t.Fatalf("expected one invalidation and one renewal, versions %d -> %d, error %v", before.SessionVersion, after.SessionVersion, err)
	}
}
