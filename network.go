package main

import (
	"fmt"
	"net"
	"strings"
)

// Subdomains commonly pointing to origin (not behind WAF)
var originSubdomains = []string{
	"mail", "webmail", "smtp", "pop", "imap",
	"ftp", "sftp",
	"cpanel", "whm", "plesk", "webmin",
	"direct", "origin", "origin-www", "direct-connect",
	"dev", "staging", "stage", "test", "qa", "uat",
	"api", "backend", "admin", "panel",
	"old", "legacy", "backup", "bak",
	"ns1", "ns2", "dns",
	"vpn", "remote", "gateway",
	"mx", "mx1", "mx2", "mailgw",
	"autodiscover", "autoconfig",
	"portal", "intranet", "internal",
}

// Ports to check for web servers
var webPorts = []int{80, 443, 8080, 8443, 8000, 8008, 8888, 9443}

func extractMainDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

// sanitizeDomain strips scheme, port, path, trailing slashes from user input.
func sanitizeDomain(input string) string {
	d := strings.TrimSpace(input)
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if idx := strings.IndexAny(d, "/?#"); idx != -1 {
		d = d[:idx]
	}
	if host, _, err := net.SplitHostPort(d); err == nil {
		d = host
	}
	d = strings.TrimRight(d, "./")
	return d
}

func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func expandIPRange(cidr string) ([]string, error) {
	var ips []string
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, bits := ipnet.Mask.Size()
	if bits-ones > 8 {
		return nil, fmt.Errorf("CIDR range /%d too large, skipping (max /24)", ones)
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) <= 2 {
		return ips, nil
	}
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func unique(items []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, item := range items {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; !exists {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
