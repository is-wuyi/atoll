package peertransport

import (
	"context"
	"net"
	"sync"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"
	"go.uber.org/fx"
)

// Fx can fail before OnStart or roll back after it. The manager's library Close
// is not idempotent, so both paths share one owner rather than closing it twice.
type quicManagerOwner struct {
	manager *quicreuse.ConnManager
	once    sync.Once
	err     error
}

func (o *quicManagerOwner) option() libp2p.Option {
	return libp2p.QUICReuse(func(reset quic.StatelessResetKey, token quic.TokenGeneratorKey, resources network.ResourceManager, life fx.Lifecycle) (*quicreuse.ConnManager, error) {
		manager, err := quicreuse.NewConnManager(reset, token,
			quicreuse.ConnContext(func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
				address, _ := quicreuse.ToQuicMultiaddr(info.RemoteAddr, quic.Version1)
				scope, err := resources.OpenConnection(network.DirInbound, false, address)
				if err != nil {
					return ctx, err
				}
				ctx = network.WithConnManagementScope(ctx, scope)
				context.AfterFunc(ctx, scope.Done)
				return ctx, nil
			}),
			quicreuse.VerifySourceAddress(func(address net.Addr) bool { return resources.VerifySourceAddress(address) }),
			quicreuse.EnableMetrics(prometheus.DefaultRegisterer),
		)
		if err != nil {
			return nil, err
		}
		o.manager = manager
		life.Append(fx.StopHook(o.Close))
		return manager, nil
	})
}

func (o *quicManagerOwner) Close() error {
	if o.manager == nil {
		return nil
	}
	o.once.Do(func() { o.err = o.manager.Close() })
	return o.err
}
