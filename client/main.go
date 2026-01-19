package client

import (
	"context"
	"time"

	"aether/common"
)

// Config controls the SOCKS5 listener that feeds the DNS tunnel.
type Config struct {
	// ListenAddr is where the SOCKS5 endpoint listens.
	ListenAddr string
	// QueueSize caps the buffered packet queue that hands payloads to the DNS layer.
	QueueSize int
	// IdleTimeout prevents connections from hanging forever.
	IdleTimeout time.Duration
}

// RunClient wires up the router, SOCKS proxy, scheduler, and downstream dispatcher.
func RunClient(ctx context.Context, cfg Config, schedulerCfg SchedulerConfig, routerPath string, dialer Dialer) error {
	if dialer == nil {
		dialer = &DefaultDialer{}
	}

	manager := NewSessionManager()
	downstream := make(chan DownstreamMessage, cfg.QueueSize)

	proxy := NewSocksProxy(cfg, dialer, manager)

	if routerPath == "" {
		routerPath = defaultRouterFile
	}

	router := common.NewRouter()
	if err := router.LoadCIDRs(ctx, routerPath); err != nil {
		return err
	}

	schedulerCfg.Queue = proxy.Queue()
	schedulerCfg.Router = router
	schedulerCfg.Downstream = downstream
	if schedulerCfg.Dialer == nil {
		schedulerCfg.Dialer = dialer
	}

	scheduler, err := NewScheduler(schedulerCfg)
	if err != nil {
		return err
	}

	errCh := make(chan error, 3)

	go manager.Dispatch(ctx, downstream)
	go func() {
		errCh <- proxy.Serve(ctx)
	}()
	go func() {
		errCh <- scheduler.Serve(ctx)
		close(downstream)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}
