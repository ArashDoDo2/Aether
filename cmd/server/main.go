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
)

func main() {
	addr := flag.String("addr", "0.0.0.0:5353", "UDP listen address")
	psk := flag.String("psk", "", "32-byte pre-shared key (raw bytes)")
	domain := flag.String("domain", "aether.local", "DNS suffix used for tunneling")
	dictPath := flag.String("dict", "", "optional path to zstd dictionary")
	flag.Parse()

	if len(*psk) != 32 {
		log.Fatalf("psk must be exactly 32 bytes, got %d", len(*psk))
	}

	var dict []byte
	if *dictPath != "" {
		data, err := os.ReadFile(*dictPath)
		if err != nil {
			log.Fatalf("loading dictionary: %v", err)
		}
		dict = data
	}

	cfg := server.ServerConfig{
		Addr:         *addr,
		PSK:          []byte(*psk),
		DomainSuffix: *domain,
		Dictionary:   dict,
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("unable to create server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("listening on %s for domain %s\n", *addr, *domain)
	if err := srv.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("server error: %v", err)
	}

	fmt.Println("server stopped")
	time.Sleep(100 * time.Millisecond)
}
