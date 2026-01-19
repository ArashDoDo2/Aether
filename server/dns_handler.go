package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"aether/common"

	"golang.org/x/crypto/chacha20poly1305"
)

// PayloadSink can be implemented to receive contiguous data after reassembly.
type PayloadSink interface {
	Deliver(sessionID uint32, data []byte)
}

// ServerConfig carries the tunable values for the DNS handler.
type ServerConfig struct {
	Addr         string
	PSK          []byte
	Dictionary   []byte
	DomainSuffix string
	PayloadSink  PayloadSink
}

// Server accepts encrypted DNS queries and reassembles the upstream stream.
type Server struct {
	cfg      ServerConfig
	cipher   *common.Cipher
	codec    *common.ZstdCodec
	conn     *net.UDPConn
	mu       sync.Mutex
	sessions map[uint32]*sessionState
}

// NewServer constructs a DNS tunneling server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Addr == "" {
		return nil, errors.New("addr is required")
	}
	if len(cfg.PSK) != 32 {
		return nil, errors.New("psk must be 32 bytes")
	}
	if cfg.DomainSuffix == "" {
		return nil, errors.New("domain suffix is required")
	}
	cipher, err := common.NewCipher(cfg.PSK)
	if err != nil {
		return nil, err
	}
	codec, err := common.NewZstdCodec(cfg.Dictionary)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:      cfg,
		cipher:   cipher,
		codec:    codec,
		sessions: make(map[uint32]*sessionState),
	}, nil
}

// Serve listens for DNS queries until the context is canceled.
func (s *Server) Serve(ctx context.Context) error {
	defer s.codec.Close()
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	s.conn = conn

	// Start background cleanup (Garbage Collector)
	go s.runCleanupLoop(ctx)

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}

		resp, err := s.handlePacket(buf[:n])
		if err != nil {
			continue
		}
		if resp != nil {
			conn.WriteToUDP(resp, remote)
		}
	}
}

// runCleanupLoop periodically checks for and removes inactive sessions.
func (s *Server) runCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *Server) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, state := range s.sessions {
		state.mu.Lock()
		idle := now.Sub(state.lastActive)
		state.mu.Unlock()

		if idle > 5*time.Minute {
			state.closeRemote()
			delete(s.sessions, id)
		}
	}
}

// QueueDownstream schedules data to be sent back to the client.
func (s *Server) QueueDownstream(sessionID uint32, data []byte) {
	state := s.getSession(sessionID)
	state.enqueueDownstream(data)
}

func (s *Server) handlePacket(req []byte) ([]byte, error) {
	if len(req) < 12 {
		return nil, errors.New("invalid dns packet")
	}
	id := binary.BigEndian.Uint16(req[0:2])
	domain, offset, err := readName(req, 12)
	if err != nil {
		return nil, err
	}
	if offset+4 > len(req) {
		return nil, errors.New("truncated question")
	}
	qtype := binary.BigEndian.Uint16(req[offset : offset+2])
	qclass := binary.BigEndian.Uint16(req[offset+2 : offset+4])

	encoded, err := s.decodeDomain(domain)
	if err != nil {
		return nil, err
	}
	packet, err := s.decodePayload(encoded)
	if err != nil {
		return nil, err
	}

	header, payload, err := common.DeserializePacket(packet)
	if err != nil {
		return nil, err
	}

	state := s.getSession(header.SessionID)
	switch header.Type {
	case common.PacketTypeCtrl:
		if err := s.handleMeta(header.SessionID, payload, state); err != nil {
			return nil, err
		}
	case common.PacketTypeData:
		state.insert(header.Sequence, payload)
		if contiguous := state.drainContiguous(); len(contiguous) > 0 {
			if err := s.forwardToRemote(header.SessionID, contiguous); err != nil {
				return nil, err
			}
		}
	}

	respPacket := s.buildResponsePayload(header.SessionID, header.Sequence, state)
	encodedResp, err := s.prepareResponsePayload(respPacket)
	if err != nil {
		return nil, err
	}
	return buildDNSResponse(id, domain, encodedResp, qtype, qclass)
}

func (s *Server) decodeDomain(domain string) (string, error) {
	if s.cfg.DomainSuffix == "" {
		return strings.ReplaceAll(domain, ".", ""), nil
	}
	if domain == s.cfg.DomainSuffix {
		return "", errors.New("missing payload")
	}
	if !strings.HasSuffix(domain, "."+s.cfg.DomainSuffix) {
		return "", errors.New("domain suffix mismatch")
	}
	value := strings.TrimSuffix(domain, "."+s.cfg.DomainSuffix)
	return strings.ReplaceAll(value, ".", ""), nil
}

func (s *Server) decodePayload(encoded string) ([]byte, error) {
	raw, err := common.DecodeBase64URL(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) < chacha20poly1305.NonceSize {
		return nil, errors.New("encrypted payload too short")
	}
	nonce := raw[:chacha20poly1305.NonceSize]
	ciphertext := raw[chacha20poly1305.NonceSize:]
	decrypted, err := s.cipher.Decrypt(nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return s.codec.Decompress(decrypted)
}

func (s *Server) prepareResponsePayload(payload []byte) (string, error) {
	compressed, err := s.codec.Compress(payload)
	if err != nil {
		return "", err
	}
	nonce, ciphertext, err := s.cipher.Encrypt(compressed, nil)
	if err != nil {
		return "", err
	}
	return common.EncodeBase64URL(append(nonce, ciphertext...)), nil
}

func (s *Server) buildResponsePayload(sessionID uint32, ackSeq uint16, state *sessionState) []byte {
	if data := state.popDownstream(); len(data) > 0 {
		header := common.PacketHeader{
			Type:      common.PacketTypeData,
			Sequence:  state.nextDownstreamSeq(),
			SessionID: sessionID,
		}
		return common.SerializePacket(header, data)
	}
	ack := common.PacketHeader{
		Type:      common.PacketTypeAck,
		Sequence:  ackSeq,
		SessionID: sessionID,
	}
	return common.SerializePacket(ack, nil)
}

func (s *Server) getSession(sessionID uint32) *sessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.sessions[sessionID]
	if !ok {
		state = &sessionState{
			pending:    make(map[uint16][]byte),
			lastActive: time.Now(),
		}
		s.sessions[sessionID] = state
	}
	state.mu.Lock()
	state.lastActive = time.Now()
	state.mu.Unlock()
	return state
}

func readName(msg []byte, offset int) (string, int, error) {
	var labels []string
	for {
		if offset >= len(msg) {
			return "", 0, errors.New("invalid dns label")
		}
		length := int(msg[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xC0 == 0xC0 {
			if offset >= len(msg) {
				return "", 0, errors.New("invalid pointer")
			}
			ptr := ((length &^ 0xC0) << 8) | int(msg[offset])
			offset++
			label, _, err := readName(msg, ptr)
			if err != nil {
				return "", 0, err
			}
			labels = append(labels, label)
			break
		}
		if offset+length > len(msg) {
			return "", 0, errors.New("invalid label length")
		}
		labels = append(labels, string(msg[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, "."), offset, nil
}

func buildDNSResponse(id uint16, domain, txt string, qtype, qclass uint16) ([]byte, error) {
	var buf bytes.Buffer
	header := struct {
		ID      uint16
		Flags   uint16
		QDCount uint16
		ANCount uint16
		NSCount uint16
		ARCount uint16
	}{ID: id, Flags: 0x8180, QDCount: 1, ANCount: 1}
	if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
		return nil, err
	}
	writeName(&buf, domain)
	if err := binary.Write(&buf, binary.BigEndian, qtype); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, qclass); err != nil {
		return nil, err
	}

	// Answer
	buf.WriteByte(0xc0)
	buf.WriteByte(0x0c)
	if err := binary.Write(&buf, binary.BigEndian, uint16(16)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(1)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(5)); err != nil {
		return nil, err
	}

	rdata := buildTXTRData(txt)
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(rdata))); err != nil {
		return nil, err
	}
	buf.Write(rdata)
	return buf.Bytes(), nil
}

func (s *Server) handleMeta(sessionID uint32, payload []byte, state *sessionState) error {
	remoteAddr := strings.TrimSpace(string(payload))
	if remoteAddr == "" {
		return errors.New("empty remote address")
	}
	return s.establishRemote(sessionID, remoteAddr, state)
}

func (s *Server) establishRemote(sessionID uint32, remoteAddr string, state *sessionState) error {
	conn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		return err
	}
	state.setRemote(conn, remoteAddr)
	go s.copyRemote(sessionID, conn)
	return nil
}

func (s *Server) copyRemote(sessionID uint32, conn net.Conn) {
	buf := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			s.QueueDownstream(sessionID, data)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
	}
	s.cleanupRemote(sessionID)
}

func (s *Server) cleanupRemote(sessionID uint32) {
	s.mu.Lock()
	state, ok := s.sessions[sessionID]
	s.mu.Unlock()
	if !ok {
		return
	}
	state.closeRemote()
}

func (s *Server) forwardToRemote(sessionID uint32, payload []byte) error {
	s.mu.Lock()
	state, ok := s.sessions[sessionID]
	s.mu.Unlock()
	if !ok {
		return errors.New("unknown session")
	}
	conn := state.remoteConn
	if conn == nil {
		return errors.New("remote connection not established")
	}
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err := conn.Write(payload)
	return err
}

func writeName(buf *bytes.Buffer, domain string) {
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
}

func buildTXTRData(txt string) []byte {
	var holder bytes.Buffer
	for len(txt) > 0 {
		chunk := txt
		if len(chunk) > 255 {
			chunk = chunk[:255]
		}
		holder.WriteByte(byte(len(chunk)))
		holder.WriteString(chunk)
		txt = txt[len(chunk):]
	}
	if holder.Len() == 0 {
		holder.WriteByte(0)
	}
	return holder.Bytes()
}

type sessionState struct {
	mu            sync.Mutex
	expectedSeq   uint16
	pending       map[uint16][]byte
	downstream    [][]byte
	downstreamSeq uint16
	remoteConn    net.Conn
	remoteAddr    string
	lastActive    time.Time
}

func (s *sessionState) insert(seq uint16, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(payload) == 0 {
		return
	}
	if s.pending == nil {
		s.pending = make(map[uint16][]byte)
	}
	if _, ok := s.pending[seq]; ok {
		return
	}
	s.pending[seq] = append([]byte(nil), payload...)
}

func (s *sessionState) drainContiguous() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var collected []byte
	for {
		chunk, ok := s.pending[s.expectedSeq]
		if !ok {
			break
		}
		collected = append(collected, chunk...)
		delete(s.pending, s.expectedSeq)
		s.expectedSeq++
	}
	return collected
}

func (s *sessionState) enqueueDownstream(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(data) == 0 {
		return
	}
	s.downstream = append(s.downstream, append([]byte(nil), data...))
}

func (s *sessionState) popDownstream() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.downstream) == 0 {
		return nil
	}
	chunk := s.downstream[0]
	s.downstream = s.downstream[1:]
	return chunk
}

func (s *sessionState) nextDownstreamSeq() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.downstreamSeq
	s.downstreamSeq++
	return seq
}

func (s *sessionState) setRemote(conn net.Conn, addr string) {
	s.mu.Lock()
	if s.remoteConn != nil {
		s.remoteConn.Close()
	}
	s.remoteConn = conn
	s.remoteAddr = addr
	s.mu.Unlock()
}

func (s *sessionState) closeRemote() {
	s.mu.Lock()
	if s.remoteConn != nil {
		s.remoteConn.Close()
		s.remoteConn = nil
	}
	s.mu.Unlock()
}
