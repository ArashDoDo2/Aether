package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"aether/common"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	defaultRateLimit       = 15
	defaultChunkSize       = 110
	defaultDNSTimeout      = 5 * time.Second
	maxDNSQueryID          = 0xffff
	maxDNSDomainLength     = common.MaxDomainLength
	maxRetransmitAttempts  = 5
	minimumEncodedChunkLen = chacha20poly1305.NonceSize + 1
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// SchedulerConfig controls how SOCKS5 traffic is converted into DNS packets.
type SchedulerConfig struct {
	Queue        <-chan SocksPayload
	DNSServer    string
	DomainSuffix string
	PSK          []byte
	Dictionary   []byte
	RateLimit    int
	MaxChunkSize int
	Timeout      time.Duration
	Router       *common.Router
	Dialer       Dialer
	Downstream   chan<- []byte
}

type sendTask struct {
	seq      uint16
	buf      []byte
	dest     net.IP
	destPort uint16
}

// Scheduler batches payloads and sends them through DNS while respecting rate limits.
type Scheduler struct {
	cfg        SchedulerConfig
	queue      <-chan SocksPayload
	cipher     *common.Cipher
	codec      *common.ZstdCodec
	sessionID  uint32
	sequence   uint32
	retries    map[uint16]int
	retransmit []sendTask
}

// NewScheduler creates and validates a scheduler instance.
func NewScheduler(cfg SchedulerConfig) (*Scheduler, error) {
	if cfg.Queue == nil {
		return nil, errors.New("scheduler queue is required")
	}
	if cfg.DNSServer == "" {
		return nil, errors.New("dns server address is required")
	}
	if cfg.DomainSuffix == "" {
		return nil, errors.New("domain suffix is required")
	}
	if len(cfg.PSK) != 32 {
		return nil, errors.New("psk must be 32 bytes")
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = defaultRateLimit
	}
	if cfg.MaxChunkSize <= 0 {
		cfg.MaxChunkSize = defaultChunkSize
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultDNSTimeout
	}
	if cfg.Dialer == nil {
		cfg.Dialer = &DefaultDialer{}
	}

	cipher, err := common.NewCipher(cfg.PSK)
	if err != nil {
		return nil, err
	}
	codec, err := common.NewZstdCodec(cfg.Dictionary)
	if err != nil {
		return nil, err
	}

	return &Scheduler{
		cfg:       cfg,
		queue:     cfg.Queue,
		cipher:    cipher,
		codec:     codec,
		sessionID: rand.Uint32(),
		retries:   make(map[uint16]int),
	}, nil
}

// Serve processes the packet queue, honoring rate limits, retransmissions, and router bypasses.
func (s *Scheduler) Serve(ctx context.Context) error {
	defer s.codec.Close()

	interval := time.Second / time.Duration(s.cfg.RateLimit)
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if len(s.retransmit) > 0 {
			task := s.popRetransmit()
			if err := s.sendWithRate(ctx, task, ticker.C); err != nil {
				s.scheduleRetransmit(task)
			}
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case payload, ok := <-s.queue:
			if !ok {
				return nil
			}
			if err := s.handlePayload(ctx, payload, ticker.C); err != nil {
				return err
			}
		}
	}
}

func (s *Scheduler) handlePayload(ctx context.Context, payload SocksPayload, tick <-chan time.Time) error {
	if len(payload.Data) == 0 {
		return nil
	}
	if payload.Dest != nil && s.cfg.Router != nil && !payload.Dest.IsUnspecified() && s.cfg.Router.Match(payload.Dest) {
		go s.handleBypass(ctx, payload)
		return nil
	}

	tasks := s.prepareTasks(payload.Data, payload.Dest, payload.DestPort)
	for _, task := range tasks {
		if err := s.sendWithRate(ctx, task, tick); err != nil {
			s.scheduleRetransmit(task)
		}
	}
	return nil
}

func (s *Scheduler) prepareTasks(payload []byte, dest net.IP, destPort uint16) []sendTask {
	if len(payload) == 0 {
		return nil
	}
	maxSize := s.cfg.MaxChunkSize
	if maxSize <= 0 || maxSize > defaultChunkSize {
		maxSize = defaultChunkSize
	}
	var ret []sendTask
	for len(payload) > 0 {
		n := maxSize
		if len(payload) < n {
			n = len(payload)
		}
		chunk := append([]byte(nil), payload[:n]...)
		ret = append(ret, sendTask{
			seq:      s.nextSequence(),
			buf:      chunk,
			dest:     dest,
			destPort: destPort,
		})
		payload = payload[n:]
	}
	return ret
}

func (s *Scheduler) sendWithRate(ctx context.Context, task sendTask, tick <-chan time.Time) error {
	if err := s.waitForTick(ctx, tick); err != nil {
		return err
	}
	return s.sendChunk(ctx, task)
}

func (s *Scheduler) waitForTick(ctx context.Context, tick <-chan time.Time) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tick:
		return nil
	}
}

func (s *Scheduler) sendChunk(ctx context.Context, task sendTask) error {
	header := common.PacketHeader{
		Type:      common.PacketTypeData,
		Sequence:  task.seq,
		SessionID: s.sessionID,
	}
	payload := common.SerializePacket(header, task.buf)

	compressed, err := s.codec.Compress(payload)
	if err != nil {
		return err
	}

	nonce, ciphertext, err := s.cipher.Encrypt(compressed, nil)
	if err != nil {
		return err
	}

	full := append(nonce, ciphertext...)
	if len(full) < minimumEncodedChunkLen {
		return errors.New("ciphertext too short")
	}

	encoded := common.EncodeBase64URL(full)
	labels, err := common.SplitIntoLabels(encoded)
	if err != nil {
		return err
	}

	domain, err := buildDomain(labels, s.cfg.DomainSuffix)
	if err != nil {
		return err
	}

	query, err := buildDNSQuery(domain)
	if err != nil {
		return err
	}

	resp, err := s.sendQueryWithResponse(ctx, query)
	if err != nil {
		return err
	}

	return s.handleResponse(resp)
}

func (s *Scheduler) sendQueryWithResponse(ctx context.Context, query []byte) ([]byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	conn, err := s.cfg.Dialer.DialContext(dialCtx, "udp", s.cfg.DNSServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.Timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.Timeout))
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *Scheduler) handleResponse(resp []byte) error {
	txt, err := extractFirstTXT(resp)
	if err != nil {
		return err
	}
	decoded, err := common.DecodeBase64URL(txt)
	if err != nil {
		return err
	}
	if len(decoded) < chacha20poly1305.NonceSize {
		return errors.New("response payload too short")
	}
	nonce := decoded[:chacha20poly1305.NonceSize]
	ciphertext := decoded[chacha20poly1305.NonceSize:]
	decrypted, err := s.cipher.Decrypt(nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	decompressed, err := s.codec.Decompress(decrypted)
	if err != nil {
		return err
	}

	header, payload, err := common.DeserializePacket(decompressed)
	if err != nil {
		return err
	}
	if header.SessionID != s.sessionID {
		return errors.New("session mismatch")
	}

	switch header.Type {
	case common.PacketTypeAck:
		delete(s.retries, header.Sequence)
		return nil
	case common.PacketTypeData:
		delete(s.retries, header.Sequence)
		s.handleDownstream(payload)
		return nil
	default:
		return errors.New("unexpected packet type")
	}
}

func (s *Scheduler) handleDownstream(payload []byte) {
	if len(payload) == 0 || s.cfg.Downstream == nil {
		return
	}
	select {
	case s.cfg.Downstream <- append([]byte(nil), payload...):
	default:
	}
}

func (s *Scheduler) handleBypass(ctx context.Context, payload SocksPayload) {
	if payload.Dest == nil || payload.DestPort == 0 {
		return
	}
	addr := net.JoinHostPort(payload.Dest.String(), strconv.Itoa(int(payload.DestPort)))
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	conn, err := s.cfg.Dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	if len(payload.Data) == 0 {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.Timeout))
	conn.Write(payload.Data)
}

func (s *Scheduler) scheduleRetransmit(task sendTask) {
	if s.retries[task.seq] >= maxRetransmitAttempts {
		delete(s.retries, task.seq)
		return
	}
	s.retries[task.seq]++
	s.retransmit = append(s.retransmit, task)
}

func (s *Scheduler) popRetransmit() sendTask {
	task := s.retransmit[0]
	s.retransmit = s.retransmit[1:]
	return task
}

func (s *Scheduler) nextSequence() uint16 {
	return uint16(atomic.AddUint32(&s.sequence, 1) & 0xffff)
}

func buildDomain(labels []string, suffix string) (string, error) {
	domain := strings.Join(labels, ".")
	if suffix != "" {
		domain = domain + "." + suffix
	}
	if len(domain) > maxDNSDomainLength {
		return "", errors.New("encoded domain exceeds DNS limit")
	}
	return domain, nil
}

func buildDNSQuery(domain string) ([]byte, error) {
	var buf bytes.Buffer
	id := uint16(rand.Uint32() & maxDNSQueryID)
	header := struct {
		ID      uint16
		Flags   uint16
		QDCount uint16
	}{ID: id, Flags: 0x0100, QDCount: 1}

	if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
		return nil, err
	}

	for _, label := range strings.Split(domain, ".") {
		if len(label) > 63 {
			return nil, errors.New("label too long for DNS query")
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	if err := binary.Write(&buf, binary.BigEndian, uint16(16)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(1)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func extractFirstTXT(resp []byte) (string, error) {
	if len(resp) < 12 {
		return "", errors.New("truncated dns response")
	}
	qdCount := binary.BigEndian.Uint16(resp[4:6])
	anCount := binary.BigEndian.Uint16(resp[6:8])
	if qdCount == 0 || anCount == 0 {
		return "", errors.New("no answers")
	}

	offset := 12
	for i := 0; i < int(qdCount); i++ {
		var err error
		if offset, err = skipName(resp, offset); err != nil {
			return "", err
		}
		if offset+4 > len(resp) {
			return "", errors.New("truncated question")
		}
		offset += 4
	}

	for i := 0; i < int(anCount); i++ {
		var err error
		if offset, err = skipName(resp, offset); err != nil {
			return "", err
		}
		if offset+10 > len(resp) {
			return "", errors.New("truncated answer")
		}
		rdataLen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		if offset+10+rdataLen > len(resp) {
			return "", errors.New("incomplete txt data")
		}
		if binary.BigEndian.Uint16(resp[offset:offset+2]) != 16 {
			offset += 10 + rdataLen
			continue
		}
		rdata := resp[offset+10 : offset+10+rdataLen]
		var txtBuilder strings.Builder
		for idx := 0; idx < len(rdata); {
			length := int(rdata[idx])
			idx++
			if idx+length > len(rdata) {
				return "", errors.New("malformed txt segment")
			}
			txtBuilder.Write(rdata[idx : idx+length])
			idx += length
		}
		return txtBuilder.String(), nil
	}
	return "", errors.New("no txt answers found")
}

func skipName(msg []byte, offset int) (int, error) {
	for {
		if offset >= len(msg) {
			return 0, errors.New("invalid dns label")
		}
		length := int(msg[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xC0 == 0xC0 {
			if offset >= len(msg) {
				return 0, errors.New("invalid pointer")
			}
			offset++
			break
		}
		offset += length
	}
	return offset, nil
}
