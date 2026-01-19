package common

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher wraps the ChaCha20-Poly1305 AEAD cipher with helper utilities.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher returns a helper bound to the supplied 32-byte PSK.
func NewCipher(psk []byte) (*Cipher, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, errors.New("psk must be 32 bytes")
	}

	aead, err := chacha20poly1305.New(psk)
	if err != nil {
		return nil, err
	}

	return &Cipher{aead: aead}, nil
}

// Encrypt seals plaintext and returns the nonce plus ciphertext.
func (c *Cipher) Encrypt(plaintext, additional []byte) ([]byte, []byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := c.aead.Seal(nil, nonce, plaintext, additional)
	return nonce, ciphertext, nil
}

// Decrypt opens ciphertext with the provided nonce and associated data.
func (c *Cipher) Decrypt(nonce, ciphertext, additional []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, errors.New("invalid nonce size")
	}
	return c.aead.Open(nil, nonce, ciphertext, additional)
}
