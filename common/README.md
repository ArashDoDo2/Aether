# Common Library

This directory contains the shared core logic used by both the Client and Server. It ensures protocol consistency and centralized cryptographic handling.

## 📚 Modules

### 1. Encoding (`encoding.go`)
*   **Standard**: **Base32** (RFC 4648).
*   **Configuration**: Lowercase alphabet, No Padding.
*   **Reason**: DNS labels are case-insensitive. Base64 is not safe for DNS transport as `A` and `a` might be normalized by intermediate resolvers, corrupting data. Base32 avoids this.
*   **Compression**: **Zstandard (zstd)** with an optional static dictionary preset to optimize for small DNS payloads.

### 2. Cryptography (`crypto.go`)
*   **Algorithm**: **ChaCha20-Poly1305** (AEAD).
*   **Key Size**: 32 bytes (256-bit).
*   **Nonce**: Unique random nonce per packet.
*   **Usage**: `Encrypt(plaintext)` returns `nonce || ciphertext`.

### 3. Protocol Definition (`protocol.go`)
Defines the binary packet headers used inside the encrypted payload.

**Header Format (8 Bytes):**
```
[ Type (1B) | Sequence (2B) | SessionID (4B) | Flags (1B) ]
```

*   **Type**: Data (0x01), Ack (0x02), Control (0x03).
*   **Sequence**: For reordering and reliability logic.
*   **SessionID**: Multiplexes multiple TCP streams over a single DNS tunnel.

### 4. Router (`router.go`)
A generic **Radix Tree** implementation for CIDR matching.
*   Used for "Split Tunneling".
*   Efficiently matches an IP against thousands of prefixes (e.g., country-wide IP blocks).
