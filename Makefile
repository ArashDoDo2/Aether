.PHONY: all build-server build-mikrotik build-windows clean

all: build-server build-mikrotik build-windows

build-server:
	@echo "Building Server (Linux/AMD64)..."
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/aether-server-linux-amd64 ./cmd/server

build-mikrotik:
	@echo "Building Server (Mikrotik/ARMv7)..."
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o bin/aether-server-mikrotik-armv7 ./cmd/server

build-windows:
	@echo "Building Client (Windows/AMD64)..."
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/aether-client-windows-amd64.exe ./cmd/client

clean:
	@echo "Cleaning bin directory..."
	@rm -rf bin
