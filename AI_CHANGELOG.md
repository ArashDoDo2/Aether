# AI Development Log & Architectural Decisions

This document records the architectural changes and optimizations applied to the Aether project. It is intended to provide context for future AI agents or developers working on this codebase.

## 1. Protocol Encoding: Base64 -> Base32
*   **File**: `common/encoding.go`
*   **Change**: Switched the encoding scheme from Base64 (URL-safe) to Base32 (Standard, No Padding, Lowercase).
*   **Reasoning**: 
    *   **DNS Case Insensitivity**: The DNS protocol is inherently case-insensitive (RFC 1035). Resolvers and intermediate servers often normalize domain names to lowercase.
    *   **Data Corruption Risk**: Base64 relies on case sensitivity (`A` and `a` are different bits). Transmitting Base64 encoded data via DNS labels poses a high risk of corruption if any hop normalizes the case.
    *   **Solution**: Base32 uses a limited character set (A-Z, 2-7) which is safe for case-insensitive transport. We explicitly force lowercase encoding to match standard DNS behavior.

## 2. Server-Side Session Garbage Collection
*   **File**: `server/dns_handler.go`
*   **Change**: Implemented a background goroutine (`runCleanupLoop`) and a `lastActive` timestamp in `sessionState`.
*   **Reasoning**:
    *   **Stateless Transport**: Since the upstream transport is DNS (UDP), there are no TCP FIN packets to signal the end of a session.
    *   **Memory Leaks**: Without a timeout mechanism, if a client crashes or changes networks, the server would retain the session state and sockets indefinitely.
    *   **Implementation**: A "Mark-and-Sweep" style logic runs every 1 minute, removing any session that hasn't seen activity for 5 minutes.

## 3. Binary Size Optimization
*   **Files**: `Dockerfile`, `Makefile`
*   **Change**: Added `-ldflags="-s -w"` to the `go build` commands.
*   **Reasoning**:
    *   **Storage Constraints**: The target environment includes Mikrotik routers (container mode) which often have very limited storage (< 15MB).
    *   **Effect**: 
        *   `-s`: Omit the symbol table and debug information.
        *   `-w`: Omit the DWARF symbol table.
    *   This reduces the final binary size significantly (often by 20-30%) without affecting functionality.

## 4. Cross-Compilation Workflow
*   **File**: `Makefile`
*   **Change**: Added specific build targets for the required platforms.
*   **Targets**:
    *   `build-server`: Linux/AMD64 (Cloud VPS).
    *   `build-mikrotik`: Linux/ARMv7 (Router/IoT devices).
    *   `build-windows`: Windows/AMD64 (Client).
*   **Reasoning**: Ensures consistent build commands and valid environment variables (`CGO_ENABLED=0`, `GOOS`, `GOARCH`) for reproducible builds across different development environments.
