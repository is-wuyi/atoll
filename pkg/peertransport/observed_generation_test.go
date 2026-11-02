package peertransport

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"atoll/pkg/peerauth"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func TestAuthenticatedObservationChangesReplaceOnlyThatConnection(t *testing.T) {
	o, conn, infra := observationFixture(t)
	first := ma.StringCast("/ip4/1.1.1.1/tcp/44123")
	second := ma.StringCast("/ip4/1.1.1.1/tcp/44124")
	o.record(event.EvtPeerIdentificationCompleted{Peer: conn.RemotePeer(), Conn: conn, ObservedAddr: first})
	o.record(event.EvtPeerIdentificationCompleted{Peer: conn.RemotePeer(), Conn: conn, ObservedAddr: second})
	if addresses := o.Addrs(1); len(addresses) != 1 || !addresses[0].Equal(second) {
		t.Fatal("old transport mapping remained active")
	}
	_, key, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.Raw()
	if err != nil {
		t.Fatal(err)
	}
	changed := peerauth.Infrastructure{PeerID: id.String(), PublicKey: public, Addresses: infra.Addresses, Relay: true}
	o.setInfrastructure(changed)
	if addresses := o.Addrs(1); len(addresses) != 0 {
		t.Fatal("infrastructure binding change kept prior mapping")
	}
}

func TestLateObservationCannotUseReplacedAuthorizer(t *testing.T) {
	o, conn, infra := observationFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	o.auth.setAuthorizer(func(context.Context, string) bool { close(entered); <-release; return true })
	done := make(chan struct{})
	go func() {
		o.record(event.EvtPeerIdentificationCompleted{Peer: conn.RemotePeer(), Conn: conn, ObservedAddr: ma.StringCast("/ip4/1.1.1.1/tcp/44123")})
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("observation did not reach authorizer")
	}
	o.auth.setAuthorizer(allowIDs(infra.PeerID))
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("old observation did not return")
	}
	if len(o.Addrs(1)) != 0 {
		t.Fatal("old authorization result became a new-generation candidate")
	}
}
