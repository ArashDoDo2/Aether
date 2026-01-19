package common

import (
	"encoding/binary"
	"errors"
)

const (
	HeaderSize      = 8
	MaxLabelLength  = 63
	MaxDomainLength = 253
)

type PacketType uint8

const (
	PacketTypeData PacketType = 0x01
	PacketTypeAck  PacketType = 0x02
	PacketTypeCtrl PacketType = 0x03
)

// PacketHeader is prepended to every DNS payload to track framing.
type PacketHeader struct {
	Type      PacketType
	Sequence  uint16
	SessionID uint32
	Flags     byte // reserved for future use
}

// Marshal serializes the header using big-endian fields.
func (h PacketHeader) Marshal() []byte {
	buf := make([]byte, HeaderSize)
	buf[0] = byte(h.Type)
	binary.BigEndian.PutUint16(buf[1:3], h.Sequence)
	binary.BigEndian.PutUint32(buf[3:7], h.SessionID)
	buf[7] = h.Flags
	return buf
}

// ParseHeader deserializes a header from the start of a packet.
func ParseHeader(b []byte) (PacketHeader, error) {
	if len(b) < HeaderSize {
		return PacketHeader{}, errors.New("header too short")
	}
	return PacketHeader{
		Type:      PacketType(b[0]),
		Sequence:  binary.BigEndian.Uint16(b[1:3]),
		SessionID: binary.BigEndian.Uint32(b[3:7]),
		Flags:     b[7],
	}, nil
}

// SerializePacket concatenates header data with payload bytes.
func SerializePacket(header PacketHeader, payload []byte) []byte {
	return append(header.Marshal(), payload...)
}

// DeserializePacket splits the packet into header/payload pieces.
func DeserializePacket(packet []byte) (PacketHeader, []byte, error) {
	header, err := ParseHeader(packet)
	if err != nil {
		return PacketHeader{}, nil, err
	}
	return header, packet[HeaderSize:], nil
}

// SplitIntoLabels enforces the DNS label limits for the encoded payload.
func SplitIntoLabels(encoded string) ([]string, error) {
	if len(encoded) == 0 {
		return nil, errors.New("payload is empty")
	}

	var labels []string
	for len(encoded) > 0 {
		end := MaxLabelLength
		if len(encoded) < end {
			end = len(encoded)
		}
		labels = append(labels, encoded[:end])
		encoded = encoded[end:]
	}

	totalLength := 0
	for _, label := range labels {
		totalLength += len(label) + 1 // include dot separator
	}
	if totalLength > MaxDomainLength {
		return nil, errors.New("encoded payload exceeds DNS limit")
	}

	return labels, nil
}
