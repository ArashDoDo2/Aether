# Aether Client

The client module runs a **SOCKS5 Proxy** that intercepts TCP connections, encapsulates them into DNS packets, and forwards them to the Aether Server.

## 🧠 Core Components

### 1. SOCKS5 Listener & Session Manager (`socks5.go`)
*   Listens on a local TCP port (default `1080`).
*   Performs standard SOCKS5 handshakes (No Auth).
*   Manages active TCP sessions using a `Map[uint32]net.Conn`.
*   Assigns a unique `SessionID` to each connection.

### 2. The Scheduler (`scheduler.go`)
The heart of the client. It handles the conversion of stream data into packetized DNS queries.
*   **Chunking**: Splits stream data into **110-byte** chunks to fit safely within DNS limits (after encryption/encoding).
*   **Rate Limiting**: Controls the outgoing Query-Per-Second (QPS) to avoid flooding and detection.
*   **Reliability**: Implements a "Stop-and-Wait" style ARQ with retransmissions for lost packets.
*   **Encryption**: Wraps every packet in ChaCha20-Poly1305.

### 3. Smart Routing (Radix Tree)
Before tunneling, the client checks the destination IP against a loaded list of CIDRs (e.g., `iran_ips.txt`).
*   **Match**: Traffic is dialed **directly** (Bypass tunnel).
*   **No Match**: Traffic is tunneled through DNS.

## 📱 Mobile & Library Usage

The client package is designed to be embedded in Android applications using `gomobile`.

### Exported Interface
```go
// Start the client from Java/Kotlin
func RunClient(ctx context.Context, cfg Config, schedulerCfg SchedulerConfig, routerPath string, dialer Dialer) error
```

*   **Dialer Interface**: Allows Android's `VpnService.protect()` to be injected, ensuring tunnel traffic (UDP port 53) doesn't loop back into the VPN interface.

## 🔧 Configuration flags

When running as a standalone CLI:

```bash
-listen  <ip:port>   # SOCKS5 Listen Address
-dns     <ip:port>   # Actual Aether Server IP
-domain  <string>    # Domain suffix 
-psk     <string>    # 32-byte Key
-router  <path>      # Path to CIDR file for bypass
```
