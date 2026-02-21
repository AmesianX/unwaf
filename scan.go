package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

func isPortOpen(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func checkWebServer(ctx context.Context, ip string, portTimeout time.Duration, wg *sync.WaitGroup, mu *sync.Mutex, results *[]webServerResult, bar ProgressUpdater, total int) {
	defer wg.Done()
	var openPorts []int
	for _, port := range webPorts {
		if ctx.Err() != nil {
			break
		}
		if isPortOpen(ctx, ip, port, portTimeout) {
			openPorts = append(openPorts, port)
		}
	}

	mu.Lock()
	if len(openPorts) > 0 {
		*results = append(*results, webServerResult{IP: ip, Ports: openPorts})
	}
	if bar != nil {
		bar.Increment()
	}
	mu.Unlock()
}

// expandToNeighborhood expands confirmed IPs to their /24 subnets.
func expandToNeighborhood(ips []string) []string {
	subnets := make(map[string]bool)
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		ipv4 := parsed.To4()
		if ipv4 == nil {
			continue // skip IPv6 for neighbor scanning
		}
		subnet := fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
		subnets[subnet] = true
	}

	var neighbors []string
	existingIPs := make(map[string]bool)
	for _, ip := range ips {
		existingIPs[ip] = true
	}

	for subnet := range subnets {
		expanded, err := expandIPRange(subnet)
		if err != nil {
			continue
		}
		for _, ip := range expanded {
			if !existingIPs[ip] && !isWAFIP(ip) && !isPrivateIP(ip) {
				neighbors = append(neighbors, ip)
			}
		}
	}
	return neighbors
}
