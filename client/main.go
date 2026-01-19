package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"aether/common"
)

const (
	defaultRouterFile = "iran_ips.txt"
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

// SocksPayload carries the destination metadata and bytes that will be tunneled.
type SocksPayload struct {
	Dest       net.IP
	DestPort   uint16
	RemoteAddr string
	Data       []byte
}

// Dialer is a minimal interface around dialing so mobile clients can protect sockets before connecting.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DefaultDialer wraps net.Dialer in case no other dialer is supplied.
type DefaultDialer struct {
	net.Dialer
}

// DialContext forwards to the embedded net.Dialer.
func (d *DefaultDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, address)
}

// SocksProxy manages the SOCKS5 listener loop and hands sessions to the packet queue.
type SocksProxy struct {
	cfg      Config
	dialer   Dialer
	listener net.Listener
	queue    chan SocksPayload
	wg       sync.WaitGroup
}

// NewSocksProxy creates a proxy instance that can be invoked from gomobile bindings.
func NewSocksProxy(cfg Config, dialer Dialer) *SocksProxy {
	if dialer == nil {
		dialer = &DefaultDialer{}
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	return &SocksProxy{
		cfg:    cfg,
		dialer: dialer,
		queue:  make(chan SocksPayload, cfg.QueueSize),
	}
}

// Serve listens for SOCKS5 connections until the provided context is canceled.
func (s *SocksProxy) Serve(ctx context.Context) error {
	if s.cfg.ListenAddr == "" {
		return errors.New("listen address is required")
	}

	var err error
	s.listener, err = net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	defer s.listener.Close()

	acceptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go s.acceptLoop(acceptCtx)

	<-ctx.Done()
	s.listener.Close()
	s.wg.Wait()
	return ctx.Err()
}

// Queue exposes the buffered channel used by the scheduler for packet dispatch.
func (s *SocksProxy) Queue() <-chan SocksPayload {
	return s.queue
}

func (s *SocksProxy) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			continue
		}

		s.wg.Add(1)
		go s.handleSession(ctx, conn)
	}
}

func (s *SocksProxy) handleSession(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	sessionCtx, cancel := context.WithTimeout(ctx, s.cfg.IdleTimeout)
	defer cancel()

	destIP, destPort, remoteAddr, err := s.performHandshake(conn)
	if err != nil {
		return
	}

	buf := make([]byte, 2048)
	for {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			s.enqueuePayload(SocksPayload{
				Dest:       destIP,
				DestPort:   destPort,
				RemoteAddr: remoteAddr,
				Data:       append([]byte(nil), buf[:n]...),
			})
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-sessionCtx.Done():
					return
				default:
					continue
				}
			}
			return
		}

		select {
		case <-sessionCtx.Done():
			return
		default:
		}
	}
}

func (s *SocksProxy) enqueuePayload(p SocksPayload) {
	select {
	case s.queue <- p:
	default:
		select {
		case <-s.queue:
		default:
		}
		s.queue <- p
	}
}

func (s *SocksProxy) performHandshake(conn net.Conn) (net.IP, uint16, string, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, 0, "", err
	}
	if buf[0] != 0x05 {
		return nil, 0, "", errors.New("unsupported socks version")
	}
	methods := make([]byte, int(buf[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, 0, "", err
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return nil, 0, "", err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return nil, 0, "", err
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		return nil, 0, "", errors.New("only CONNECT command supported")
	}

	atyp := req[3]
	var destIP net.IP
	var remoteAddr string
	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, 0, "", err
		}
		destIP = net.IP(addr)
		remoteAddr = destIP.String()
	case 0x03:
		lengthBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			return nil, 0, "", err
		}
		domainLen := int(lengthBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, 0, "", err
		}
		remoteAddr = string(domain)
		ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", remoteAddr)
		if err != nil || len(ips) == 0 {
			return nil, 0, "", errors.New("unable to resolve domain")
		}
		destIP = ips[0]
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, 0, "", err
		}
		destIP = net.IP(addr)
		remoteAddr = destIP.String()
	default:
		return nil, 0, "", errors.New("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, 0, "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return nil, 0, "", err
	}
	return destIP, port, remoteAddr, nil
}

// RunClient loads the router, starts the SOCKS5 listener, and runs the scheduler.
func RunClient(ctx context.Context, cfg Config, schedulerCfg SchedulerConfig, routerPath string, dialer Dialer) error {
	if dialer == nil {
		dialer = &DefaultDialer{}
	}

	proxy := NewSocksProxy(cfg, dialer)

	if routerPath == "" {
		routerPath = defaultRouterFile
	}

	router := common.NewRouter()
	if err := router.LoadCIDRs(ctx, routerPath); err != nil {
		return err
	}

	schedulerCfg.Queue = proxy.Queue()
	schedulerCfg.Router = router
	if schedulerCfg.Dialer == nil {
		schedulerCfg.Dialer = dialer
	}

	scheduler, err := NewScheduler(schedulerCfg)
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)
	go func() { errCh <- proxy.Serve(ctx) }()
	go func() { errCh <- scheduler.Serve(ctx) }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}
