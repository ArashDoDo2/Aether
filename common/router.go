package common

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
)

// Router is a compact radix tree keyed by CIDR prefixes.
type Router struct {
	mu   sync.RWMutex
	ipv4 *radixNode
	ipv6 *radixNode
}

// NewRouter builds an empty router instance.
func NewRouter() *Router {
	return &Router{
		ipv4: &radixNode{},
		ipv6: &radixNode{},
	}
}

// LoadCIDRs populates the tree with CIDRs read from a newline-separated file.
func (r *Router) LoadCIDRs(ctx context.Context, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		if err := r.AddCIDR(line); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// AddCIDR inserts a CIDR range into the radix tree.
func (r *Router) AddCIDR(cidr string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ones, bits := ipnet.Mask.Size()
	if ones < 0 || ones > bits {
		return errors.New("invalid prefix length")
	}
	normalized := normalizeIP(ip)
	if normalized == nil {
		return errors.New("unsupported IP version")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(normalized) == net.IPv4len {
		if r.ipv4 == nil {
			r.ipv4 = &radixNode{}
		}
		r.ipv4.insert(normalized, ones)
		return nil
	}
	if r.ipv6 == nil {
		r.ipv6 = &radixNode{}
	}
	r.ipv6.insert(normalized, ones)
	return nil
}

// Match returns true if the IP address belongs to any stored CIDR.
func (r *Router) Match(ip net.IP) bool {
	normalized := normalizeIP(ip)
	if normalized == nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(normalized) == net.IPv4len {
		if r.ipv4 == nil {
			return false
		}
		return r.ipv4.match(normalized)
	}
	if r.ipv6 == nil {
		return false
	}
	return r.ipv6.match(normalized)
}

type radixNode struct {
	children [2]*radixNode
	isLeaf   bool
}

func (n *radixNode) insert(ip net.IP, prefixLen int) {
	if n == nil {
		return
	}
	current := n
	maxBits := len(ip) * 8
	if prefixLen > maxBits {
		prefixLen = maxBits
	}
	for depth := 0; depth < prefixLen; depth++ {
		if current.isLeaf {
			return
		}
		bit := bitAt(ip, depth)
		if current.children[bit] == nil {
			current.children[bit] = &radixNode{}
		}
		current = current.children[bit]
	}
	current.isLeaf = true
}

func (n *radixNode) match(ip net.IP) bool {
	if n == nil {
		return false
	}
	current := n
	totalBits := len(ip) * 8
	for depth := 0; depth <= totalBits; depth++ {
		if current == nil {
			return false
		}
		if current.isLeaf {
			return true
		}
		if depth == totalBits {
			break
		}
		bit := bitAt(ip, depth)
		current = current.children[bit]
	}
	return current != nil && current.isLeaf
}

func bitAt(ip net.IP, depth int) int {
	byteIdx := depth / 8
	bitIdx := 7 - uint(depth%8)
	return int((ip[byteIdx] >> bitIdx) & 1)
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return append(net.IP(nil), ipv4...)
	}
	if ipv6 := ip.To16(); ipv6 != nil {
		return append(net.IP(nil), ipv6...)
	}
	return nil
}
