package common

import (
	"encoding/base64"
	"errors"
	"sync"

	"github.com/klauspost/compress/zstd"
)

var urlSafeEncoding = base64.RawURLEncoding

// DefaultStaticDictionary contains a handful of repeated tokens typical for
// DNS tunneling so that small payloads benefit from compression.
var DefaultStaticDictionary = []byte("aether-dns-static-dictionary-seed")

// EncodeBase64URL encodes bytes using the URL-safe variant without padding.
func EncodeBase64URL(src []byte) string {
	return urlSafeEncoding.EncodeToString(src)
}

// DecodeBase64URL decodes a URL-safe string produced by EncodeBase64URL.
func DecodeBase64URL(payload string) ([]byte, error) {
	return urlSafeEncoding.DecodeString(payload)
}

// ZstdCodec wraps a compressor/decompressor pair that can optionally share
// a static dictionary, which is ideal for short, repetitive DNS packets.
type ZstdCodec struct {
	mu      sync.Mutex
	encoder *zstd.Encoder
	decoder *zstd.Decoder
	dict    []byte
}

// NewZstdCodec initializes a codec and applies the provided dictionary bytes.
// Passing nil reuses vanilla compression; supplying DefaultStaticDictionary
// enables fixed-data gains for small chunks.
func NewZstdCodec(dictionary []byte) (*ZstdCodec, error) {
	codec := &ZstdCodec{}
	if err := codec.reload(dictionary); err != nil {
		return nil, err
	}
	return codec, nil
}

// UpdateDictionary rebuilds the encoder/decoder with a new dictionary.
func (z *ZstdCodec) UpdateDictionary(dictionary []byte) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.reload(dictionary)
}

// Compress turns plaintext bytes into zstd-compressed output.
func (z *ZstdCodec) Compress(src []byte) ([]byte, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.encoder == nil {
		return nil, errors.New("zstd encoder not initialized")
	}
	return z.encoder.EncodeAll(src, nil), nil
}

// Decompress restores bytes compressed via Compress().
func (z *ZstdCodec) Decompress(src []byte) ([]byte, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.decoder == nil {
		return nil, errors.New("zstd decoder not initialized")
	}
	return z.decoder.DecodeAll(src, nil)
}

// Close releases the encoder/decoder resources.
func (z *ZstdCodec) Close() error {
	z.mu.Lock()
	defer z.mu.Unlock()
	var err error
	if z.encoder != nil {
		err = z.encoder.Close()
		z.encoder = nil
	}
	if z.decoder != nil {
		z.decoder.Close()
		z.decoder = nil
	}
	return err
}

func (z *ZstdCodec) reload(dictionary []byte) error {
	optsEnc := []zstd.EOption{}
	optsDec := []zstd.DOption{}
	if len(dictionary) > 0 {
		optsEnc = append(optsEnc, zstd.WithEncoderDict(dictionary))
		optsDec = append(optsDec, zstd.WithDecoderDicts(dictionary))
	}

	encoder, err := zstd.NewWriter(nil, optsEnc...)
	if err != nil {
		return err
	}

	decoder, err := zstd.NewReader(nil, optsDec...)
	if err != nil {
		encoder.Close()
		return err
	}

	z.dict = append([]byte(nil), dictionary...)
	z.encoder = encoder
	z.decoder = decoder
	return nil
}
