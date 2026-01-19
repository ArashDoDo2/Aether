package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aether/server"
	"github.com/joho/godotenv"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:5353", "UDP listen address")
	psk := flag.String("psk", "", "32-byte pre-shared key (raw bytes)")
	domain := flag.String("domain", "aether.local", "DNS suffix used for tunneling")
	dictPath := flag.String("dict", "", "optional path to zstd dictionary")
	flag.Parse()

	loadEnv()

	resolvedPSK, pskSource := resolveConfig(*psk, "AETHER_PSK", "")
	if resolvedPSK == "" {
		log.Fatal("psk must be provided via flag or AETHER_PSK")
	}
	log.Printf("Using PSK from %s", pskSource)

	addrValue, addrSource := resolveConfig(*addr, "AETHER_LISTEN_ADDR", "0.0.0.0:5353")
	log.Printf("Using listen address from %s", addrSource)

	domainValue, domainSource := resolveConfig(*domain, "AETHER_DOMAIN", "aether.local")
	log.Printf("Using domain suffix from %s", domainSource)

	var dict []byte
	if *dictPath != "" {
		data, err := os.ReadFile(*dictPath)
		if err != nil {
			log.Fatalf("loading dictionary: %v", err)
		}
		dict = data
	}

	cfg := server.ServerConfig{
		Addr:         addrValue,
		PSK:          []byte(resolvedPSK),
		DomainSuffix: domainValue,
		Dictionary:   dict,
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("unable to create server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("listening on %s for domain %s\n", addrValue, domainValue)
	if err := srv.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("server error: %v", err)
	}

	fmt.Println("server stopped")
	time.Sleep(100 * time.Millisecond)
}

func loadEnv() {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		log.Printf("failed to load .env: %v", err)
	}
}

func resolveConfig(flagVal, envKey, def string) (string, string) {
	if flagVal != "" {
		return flagVal, "flag"
	}
	if envKey != "" {
		if v := os.Getenv(envKey); v != "" {
			return v, fmt.Sprintf("environment variable %s", envKey)
		}
	}
	return def, "default"
}
