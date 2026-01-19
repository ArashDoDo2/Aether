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
	"github.com/joho/godotenv"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	dnsServer := flag.String("dns", "127.0.0.1:5353", "DNS server endpoint")
	domain := flag.String("domain", "aether.local", "DNS suffix for tunneling queries")
	psk := flag.String("psk", "", "32-byte pre-shared key")
	router := flag.String("router", "iran_ips.txt", "path to domestic CIDR list")
	flag.Parse()

	loadEnv()

	resolvedPSK, pskSource := resolveConfig(*psk, "AETHER_PSK", "")
	if resolvedPSK == "" {
		log.Fatal("psk must be provided via flag or AETHER_PSK")
	}
	log.Printf("Using PSK from %s", pskSource)

	dnsValue, dnsSource := resolveConfig(*dnsServer, "AETHER_DNS_SERVER", "127.0.0.1:5353")
	log.Printf("Using DNS server from %s", dnsSource)

	domainValue, domainSource := resolveConfig(*domain, "AETHER_DOMAIN", "aether.local")
	log.Printf("Using domain suffix from %s", domainSource)

	cfg := client.Config{
		ListenAddr:  *listen,
		IdleTimeout: 2 * time.Minute,
	}
	schedulerCfg := client.SchedulerConfig{
		DNSServer:    dnsValue,
		DomainSuffix: domainValue,
		PSK:          []byte(resolvedPSK),
	}

	ctxt, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Printf("starting SOCKS5 on %s -> DNS %s (%s)\n", *listen, dnsValue, domainValue)
	if err := client.RunClient(ctxt, cfg, schedulerCfg, *router, nil); err != nil {
		log.Fatalf("client error: %v", err)
	}

	fmt.Println("client shut down")
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
