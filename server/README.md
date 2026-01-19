# Aether Server

The server acts as a specialized, authoritative DNS nameserver. It listens for incoming encrypted queries, decapsulates the tunnel traffic, and proxies it to the public internet.

## ⚙️ How it Works

1.  **Ingestion**: Listens on UDP Port 53 (or 5353 for dev).
2.  **Decapsulation**:
    *   Parses the DNS Query Name (QNAME).
    *   Decodes from **Base32**.
    *   Decrypts using **ChaCha20-Poly1305**.
    *   Decompresses using **Zstd**.
3.  **State Management**:
    *   Maintains a `sessionState` for each active user connection.
    *   Reassembles fragmented 110-byte chunks into a continuous stream.
4.  **Egress**:
    *   Opens a real TCP connection to the target requested by the client.
    *   Reads response data from the target.
5.  **Response**:
    *   Packets response data into DNS **TXT Records**.
    *   Encrypts -> Compresses -> Encodes -> Sends back to client.

## 🧹 Garbage Collection

Since DNS is stateless (UDP), the server has no explicit way to know when a client has disconnected abnormally.
*   **Mechanism**: A background "Garbage Collector" runs every **1 minute**.
*   **Policy**: Any session with no activity for **> 5 minutes** is forcefully closed and removed from memory.
*   **Benefit**: Prevents memory leaks on low-resource VPS or router deployments.

## 🐳 Deployment (Docker & Mikrotik)

The server is optimized to run as a single static binary in a scratch/alpine container.

### Docker Compose
```yaml
version: '3'
services:
  aether-server:
    image: aether-server:latest
    network_mode: host
    restart: always
    environment:
      - AETHER_PSK=your_secret_key
      - AETHER_DOMAIN=ns1.example.com
      - AETHER_LISTEN_ADDR=0.0.0.0:53
```
*Note: `network_mode: host` is recommended for UDP performance.*
