package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const defaultRouterFile = "iran_ips.txt"

// Dialer allows platform-specific socket wrapping before the session starts.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DefaultDialer is used when no custom dialer is supplied.
type DefaultDialer struct {
	net.Dialer
}

func (d *DefaultDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, address)
}

// SocksPayload carries the destination metadata and bytes that will be tunneled.
type SocksPayload struct {
	SessionID  uint32
	Dest       net.IP
	DestPort   uint16
	RemoteAddr string
	Data       []byte
}

// DownstreamMessage routes a payload back to a specific TCP session.
type DownstreamMessage struct {
	SessionID uint32
	Payload   []byte
}

// SessionManager keeps track of active socks sessions and writes downstream data.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[uint32]net.Conn
	next     uint32
}

// NewSessionManager builds an empty session map.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint32]net.Conn),
	}
}

// Register stores the connection and returns a freshly minted session ID.
func (m *SessionManager) Register(conn net.Conn) uint32 {
	id := atomic.AddUint32(&m.next, 1)
	m.mu.Lock()
	m.sessions[id] = conn
	m.mu.Unlock()
	return id
}

// Unregister removes the session and closes the connection if still open.
func (m *SessionManager) Unregister(sessionID uint32) {
	m.mu.Lock()
	if conn, ok := m.sessions[sessionID]; ok {
		conn.Close()
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()
}

// Dispatch reads downstream messages and writes them to the corresponding connection.
func (m *SessionManager) Dispatch(ctx context.Context, downstream <-chan DownstreamMessage) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-downstream:
			if !ok {
				return
			}
			conn := m.get(msg.SessionID)
			if conn == nil {
				continue
			}
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write(msg.Payload); err != nil {
				m.Unregister(msg.SessionID)
			}
		}
	}
}

func (m *SessionManager) get(sessionID uint32) net.Conn {
	m.mu.RLock()
	conn := m.sessions[sessionID]
	m.mu.RUnlock()
	return conn
}

// SocksProxy manages the SOCKS5 listener loop and hands sessions to the packet queue.
type SocksProxy struct {
	cfg        Config
	dialer     Dialer
	listener   net.Listener
	queue      chan SocksPayload
	wg         sync.WaitGroup
	sessionMgr *SessionManager
}

// NewSocksProxy creates a proxy instance that can be invoked from gomobile bindings.
func NewSocksProxy(cfg Config, dialer Dialer, mgr *SessionManager) *SocksProxy {
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
		cfg:        cfg,
		dialer:     dialer,
		queue:      make(chan SocksPayload, cfg.QueueSize),
		sessionMgr: mgr,
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
	sessionID := s.sessionMgr.Register(conn)
	defer s.sessionMgr.Unregister(sessionID)

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
				SessionID:  sessionID,
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
