package peertransport

import (
	"context"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/peerauth"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

type candidateNetwork struct {
	network.Network
	listen []ma.Multiaddr
}

func (n *candidateNetwork) ListenAddresses() []ma.Multiaddr {
	return append([]ma.Multiaddr(nil), n.listen...)
}
func (*candidateNetwork) Notify(network.Notifiee)     {}
func (*candidateNetwork) StopNotify(network.Notifiee) {}

type candidateConn struct {
	network.Conn
	id                string
	local, remote     ma.Multiaddr
	localID, remoteID peer.ID
	key               crypto.PubKey
	closed            atomic.Bool
}

func (c *candidateConn) ID() string                     { return c.id }
func (c *candidateConn) LocalMultiaddr() ma.Multiaddr   { return c.local }
func (c *candidateConn) RemoteMultiaddr() ma.Multiaddr  { return c.remote }
func (c *candidateConn) LocalPeer() peer.ID             { return c.localID }
func (c *candidateConn) RemotePeer() peer.ID            { return c.remoteID }
func (c *candidateConn) RemotePublicKey() crypto.PubKey { return c.key }
func (c *candidateConn) IsClosed() bool                 { return c.closed.Load() }

func observationFixture(t *testing.T) (*trustedObservations, *candidateConn, peerauth.Infrastructure) {
	t.Helper()
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
	infra := peerauth.Infrastructure{PeerID: id.String(), PublicKey: public, Addresses: []string{"/ip4/8.8.4.4/tcp/1234"}, Relay: true}
	gate := newProtocolGate(context.Background())
	gate.setDirectory(peerauth.Directory{Infrastructure: infra})
	gate.setAuthorizer(allowIDs(id.String()))
	o := newTrustedObservations(context.Background(), gate, true, nil)
	o.network = &candidateNetwork{listen: []ma.Multiaddr{ma.StringCast("/ip4/0.0.0.0/tcp/29572")}}
	o.setInfrastructure(infra)
	t.Cleanup(func() { _ = o.Close() })
	c := &candidateConn{id: "observed-1", local: ma.StringCast("/ip4/192.168.1.2/tcp/29572"), remote: ma.StringCast("/ip4/8.8.4.4/tcp/1234"), remoteID: id, localID: testPeerID(t), key: key}
	return o, c, infra
}

func TestSingleInfrastructureObservationSuppliesPublicCandidate(t *testing.T) {
	o, conn, _ := observationFixture(t)
	address := ma.StringCast("/ip4/1.1.1.1/tcp/44123")
	o.record(event.EvtPeerIdentificationCompleted{Peer: conn.RemotePeer(), Conn: conn, ObservedAddr: address})
	for _, list := range [][]ma.Multiaddr{o.Addrs(4), o.AddrsFor(ma.StringCast("/ip4/0.0.0.0/tcp/29572")), o.AddrsFor(conn.local)} {
		if len(list) != 1 || !list[0].Equal(address) {
			t.Fatalf("trusted single observation not available as candidate: %v", list)
		}
	}
	if list := o.AddrsFor(ma.StringCast("/ip4/0.0.0.0/tcp/9999")); len(list) != 0 {
		t.Fatal("mapping was applied to a different listener")
	}
	conn.closed.Store(true)
	if len(o.Addrs(1)) != 0 {
		t.Fatal("closed connection retained its candidate")
	}
}

func TestObservationRejectsWrongIdentityTransportAndPrivateMapping(t *testing.T) {
	for _, name := range []string{"unknown-peer", "wrong-key", "wrong-local-port", "private-observed", "cgnat-observed", "different-transport", "different-family", "private-observer"} {
		t.Run(name, func(t *testing.T) {
			o, c, _ := observationFixture(t)
			observed := ma.StringCast("/ip4/1.1.1.1/tcp/44123")
			switch name {
			case "unknown-peer":
				c.remoteID = testPeerID(t)
			case "wrong-key":
				_, key, _ := crypto.GenerateEd25519Key(rand.Reader)
				c.key = key
			case "wrong-local-port":
				c.local = ma.StringCast("/ip4/192.168.1.2/tcp/9999")
			case "private-observed":
				observed = ma.StringCast("/ip4/192.168.0.4/tcp/44123")
			case "cgnat-observed":
				observed = ma.StringCast("/ip4/100.64.0.4/tcp/44123")
			case "different-transport":
				observed = ma.StringCast("/ip4/1.1.1.1/udp/44123/quic-v1")
			case "different-family":
				observed = ma.StringCast("/ip6/2606:4700:4700::1111/tcp/44123")
			case "private-observer":
				c.remote = ma.StringCast("/ip4/10.126.126.126/tcp/1234")
			}
			o.record(event.EvtPeerIdentificationCompleted{Peer: c.RemotePeer(), Conn: c, ObservedAddr: observed})
			if len(o.Addrs(1)) != 0 {
				t.Fatal("invalid public observation accepted")
			}
		})
	}
}

func TestObservationExpiresWithDirectoryAndAuthorizerGeneration(t *testing.T) {
	o, c, infra := observationFixture(t)
	record := func() {
		o.record(event.EvtPeerIdentificationCompleted{Peer: c.RemotePeer(), Conn: c, ObservedAddr: ma.StringCast("/ip4/1.1.1.1/tcp/44123")})
	}
	record()
	o.mu.Lock()
	o.until = time.Now().Add(-time.Second)
	o.mu.Unlock()
	if len(o.Addrs(1)) != 0 {
		t.Fatal("expired infrastructure kept public candidates")
	}
	o.setInfrastructure(infra)
	record()
	o.auth.setAuthorizer(func(context.Context, string) bool { return false })
	if len(o.Addrs(1)) != 0 {
		t.Fatal("authorizer change retained old positive observation")
	}
	o.auth.setAuthorizer(allowIDs(infra.PeerID))
	record()
	if len(o.Addrs(1)) != 1 {
		t.Fatal("fresh authorized observation missing")
	}
	o.Disconnected(nil, c)
	if len(o.Addrs(1)) != 0 {
		t.Fatal("disconnect kept candidate")
	}
}

func TestObservationConcurrentSnapshotAndDirectoryRefresh(t *testing.T) {
	o, c, infra := observationFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				if index%2 == 0 {
					o.setInfrastructure(infra)
					o.record(event.EvtPeerIdentificationCompleted{Peer: c.RemotePeer(), Conn: c, ObservedAddr: ma.StringCast("/ip4/1.1.1.1/tcp/44123")})
				} else {
					_ = o.Addrs(1)
					_ = o.AddrsFor(c.local)
				}
			}
		}(i)
	}
	wg.Wait()
	_ = o.Close()
	if len(o.Addrs(1)) != 0 {
		t.Fatal("closed observer returned addresses")
	}
}

func TestQUICObservationMatchesListenerWithoutInventingTCPMapping(t *testing.T) {
	o, c, _ := observationFixture(t)
	o.network = &candidateNetwork{listen: []ma.Multiaddr{ma.StringCast("/ip4/0.0.0.0/udp/29572/quic-v1")}}
	c.local = ma.StringCast("/ip4/0.0.0.0/udp/29572/quic-v1")
	c.remote = ma.StringCast("/ip4/8.8.4.4/udp/1234/quic-v1")
	address := ma.StringCast("/ip4/1.1.1.1/udp/44123/quic-v1")
	o.record(event.EvtPeerIdentificationCompleted{Peer: c.RemotePeer(), Conn: c, ObservedAddr: address})
	if list := o.AddrsFor(c.local); len(list) != 1 || !list[0].Equal(address) {
		t.Fatal("observed QUIC mapping missing")
	}
	if list := o.AddrsFor(ma.StringCast("/ip4/0.0.0.0/tcp/29572")); len(list) != 0 {
		t.Fatal("UDP observation became TCP candidate")
	}
}
