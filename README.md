# Aether 🌌
**A High-Performance Stealth DNS Tunneling Tool**

Aether is a lightweight, secure, and fast DNS tunneling solution specifically designed to run on resource-constrained environments like **MikroTik containers** and **Android devices**.

## ✨ Key Features
- **Maximum Payload:** Optimized DNS label packing (up to 253 chars per query).
- **Fast Compression:** Powered by `zstd` for maximum data throughput.
- **Modern Encryption:** Uses `ChaCha20-Poly1305` (ARM-optimized) with Pre-Shared Keys (PSK).
- **Stealthy:** Mimics standard DNS traffic patterns to bypass DPI firewalls.
- **SOCKS5 Interface:** Seamless integration with any browser or OS.

## 🛠 Project Structure
- `/common`: Core protocol logic, compression, and encryption.
- `/client`: SOCKS5 proxy server and DNS query scheduler.
- `/server`: Authoritative DNS-style listener and packet reassembler.

## 🚀 Quick Start (Docker Test)
1. **Clone the project** and navigate to the directory.
2. **Configure:** Edit `config.json` with your server IP and PSK.
3. **Build & Run:**
   ```bash
   docker-compose up --build
