package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aether/client"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	dnsServer := flag.String("dns", "127.0.0.1:5353", "DNS server endpoint")
	domain := flag.String("domain", "aether.local", "DNS suffix for tunneling queries")
	psk := flag.String("psk", "", "32-byte pre-shared key")
	router := flag.String("router", "iran_ips.txt", "path to domestic CIDR list")
	flag.Parse()

	if len(*psk) != 32 {
		log.Fatalf("psk must be exactly 32 bytes, got %d", len(*psk))
	}

	cfg := client.Config{
		ListenAddr:  *listen,
		IdleTimeout: 2 * time.Minute,
	}
	schedulerCfg := client.SchedulerConfig{
		DNSServer:    *dnsServer,
		DomainSuffix: *domain,
		PSK:          []byte(*psk),
	}

	ctxt, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Printf("starting SOCKS5 on %s -> DNS %s (%s)\n", *listen, *dnsServer, *domain)
	if err := client.RunClient(ctxt, cfg, schedulerCfg, *router, nil); err != nil {
		log.Fatalf("client error: %v", err)
	}

	fmt.Println("client shut down")
}
