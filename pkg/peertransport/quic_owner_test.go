package peertransport

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	basichost "github.com/libp2p/go-libp2p/p2p/host/basic"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2ptcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"go.uber.org/fx"
)

func TestQUICManagerOwnerClosesOnceAcrossFxFailures(t *testing.T) {
	for _, phase := range []string{"invoke", "start", "running"} {
		t.Run(phase, func(t *testing.T) {
			owner := new(quicManagerOwner)
			var constructed host.Host
			opts := []libp2p.Option{
				libp2p.NoListenAddrs, libp2p.DisableRelay(),
				libp2p.Security(noise.ID, noise.New),
				libp2p.Transport(libp2ptcp.NewTCPTransport), libp2p.Transport(quic.NewTransport),
				libp2p.ResourceManager(finiteResourceManager(probeConnectionBudget)),
				libp2p.ConnectionManager(noTrimConnMgr()), owner.option(),
				libp2p.WithFxOption(fx.Invoke(func(h *basichost.BasicHost, life fx.Lifecycle) error {
					constructed = h
					if phase == "invoke" {
						return errors.New("fixture invoke failure after host construction")
					}
					if phase == "start" {
						life.Append(fx.Hook{OnStart: func(context.Context) error { return errors.New("fixture start failure") }})
					}
					return nil
				})),
			}
			h, err := libp2p.New(opts...)
			if phase == "running" && err != nil || phase != "running" && err == nil {
				t.Fatalf("unexpected constructor result in %s: %v", phase, err)
			}
			if h != nil {
				if err := h.Close(); err != nil {
					t.Fatal(err)
				}
			} else if constructed != nil {
				if err := constructed.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if owner.manager == nil {
				t.Fatal("failure fixture did not reach the actual manager constructor")
			}
			var wg sync.WaitGroup
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); _ = owner.Close() }()
			}
			wg.Wait()
		})
	}
}
