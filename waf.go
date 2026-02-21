package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Known WAF/CDN IP ranges (CIDR prefixes) to filter out
var wafCIDRs = []string{
	// Cloudflare IPv4
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
	"131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
	"172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
	"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
	// Cloudflare IPv6
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
	"2c0f:f248::/32",
	// Akamai (common ranges)
	"23.0.0.0/12", "104.64.0.0/10",
	// Akamai IPv6
	"2600:1400::/24", "2600:1480::/24",
	// Fastly
	"151.101.0.0/16",
	// Fastly IPv6
	"2a04:4e40::/32", "2a04:4e42::/32",
	// Imperva / Incapsula
	"199.83.128.0/21", "198.143.32.0/19",
	// Sucuri
	"192.88.134.0/23", "185.93.228.0/22",
	// AWS CloudFront (common)
	"13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14",
	"18.64.0.0/14", "18.154.0.0/15", "18.160.0.0/12",
	"52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16",
	"54.230.0.0/17", "54.239.128.0/18", "99.84.0.0/16",
	"143.204.0.0/16", "205.251.192.0/19", "204.246.164.0/22",
	// AWS CloudFront IPv6
	"2600:9000::/28",
}

// Known WAF signatures in HTTP response headers
var wafSignatures = map[string][]string{
	"Cloudflare":        {"cf-ray", "cf-cache-status", "cf-request-id"},
	"Akamai":            {"x-akamai-transformed", "akamai-origin-hop"},
	"AWS CloudFront":    {"x-amz-cf-id", "x-amz-cf-pop"},
	"Fastly":            {"x-fastly-request-id", "fastly-io-info"},
	"Sucuri":            {"x-sucuri-id", "x-sucuri-cache"},
	"Imperva/Incapsula": {"x-iinfo", "x-cdn"},
	"Varnish":           {"x-varnish"},
	"StackPath":         {"x-sp-url", "x-sp-waf"},
	"Barracuda":         {"barra_counter_session"},
	"F5 BIG-IP":         {"x-wa-info", "x-cnection"},
	"DDoS-Guard":        {"ddos-guard"},
	"ArvanCloud":        {"ar-asg", "ar-poweredby"},
	"Fortinet FortiWeb": {"fortiwafsid"},
	"Radware":           {"x-rdwr"},
	"Azure Front Door":  {"x-azure-ref", "x-fd-healthprobe"},
	"Google Cloud Armor": {"x-goog-bot-verification"},
	"Vercel":            {"x-vercel-id", "x-vercel-cache"},
	"Netlify":           {"x-nf-request-id"},
}

var wafCIDRsMu sync.Mutex

// responseHasWAFHeaders returns true if the HTTP response headers contain
// signatures of a known WAF/CDN. This indicates the response was routed
// through the WAF, so accessing this IP is NOT a bypass.
func responseHasWAFHeaders(headers http.Header) bool {
	if headers == nil {
		return false
	}
	for _, sigHeaders := range wafSignatures {
		for _, h := range sigHeaders {
			if headers.Get(h) != "" {
				return true
			}
		}
	}
	// Also check Server header for known WAF names
	server := strings.ToLower(headers.Get("Server"))
	for _, name := range []string{"cloudflare", "akamaighost", "akamai", "sucuri", "incapsula", "imperva", "ddos-guard", "fortiweb", "netlify"} {
		if strings.Contains(server, name) {
			return true
		}
	}
	return false
}

func isWAFIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	wafCIDRsMu.Lock()
	cidrs := make([]string, len(wafCIDRs))
	copy(cidrs, wafCIDRs)
	wafCIDRsMu.Unlock()

	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func detectWAF(ctx context.Context, domain string, client *http.Client) string {
	urls := []string{
		"https://" + domain,
		"http://" + domain,
	}

	for _, u := range urls {
		if ctx.Err() != nil {
			return "Unknown"
		}
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check headers
		for waf, headers := range wafSignatures {
			for _, header := range headers {
				if resp.Header.Get(header) != "" {
					return waf
				}
			}
		}

		// Check Server header
		server := strings.ToLower(resp.Header.Get("Server"))
		switch {
		case strings.Contains(server, "cloudflare"):
			return "Cloudflare"
		case strings.Contains(server, "akamaighost") || strings.Contains(server, "akamai"):
			return "Akamai"
		case strings.Contains(server, "sucuri"):
			return "Sucuri"
		case strings.Contains(server, "incapsula") || strings.Contains(server, "imperva"):
			return "Imperva/Incapsula"
		case strings.Contains(server, "ddos-guard"):
			return "DDoS-Guard"
		case strings.Contains(server, "fortiweb"):
			return "Fortinet FortiWeb"
		case strings.Contains(server, "netlify"):
			return "Netlify"
		}
	}
	return "Unknown"
}

// fetchCloudflareRanges dynamically fetches Cloudflare IP ranges and appends them.
func fetchCloudflareRanges(ctx context.Context, client *http.Client) {
	urls := []string{
		"https://www.cloudflare.com/ips-v4",
		"https://www.cloudflare.com/ips-v6",
	}
	var newCIDRs []string
	for _, u := range urls {
		if ctx.Err() != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		body, _, err := doFetchRawBytes(client, req)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		for _, line := range lines {
			cidr := strings.TrimSpace(line)
			if cidr == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(cidr); err == nil {
				newCIDRs = append(newCIDRs, cidr)
			}
		}
	}
	if len(newCIDRs) > 0 {
		existing := make(map[string]bool)
		wafCIDRsMu.Lock()
		for _, c := range wafCIDRs {
			existing[c] = true
		}
		for _, c := range newCIDRs {
			if !existing[c] {
				wafCIDRs = append(wafCIDRs, c)
			}
		}
		wafCIDRsMu.Unlock()
		logVerbose(true, "Fetched %d Cloudflare CIDRs (%d new)", len(newCIDRs), len(newCIDRs)-countExisting(newCIDRs, existing))
	}
}

func countExisting(cidrs []string, existing map[string]bool) int {
	n := 0
	for _, c := range cidrs {
		if existing[c] {
			n++
		}
	}
	return n
}

// doFetchRawBytes is a helper that executes a request and returns body bytes.
// Used by fetchCloudflareRanges to avoid circular dependency with http.go.
func doFetchRawBytes(client *http.Client, req *http.Request) ([]byte, int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return body, resp.StatusCode, nil
}

func printDynamicCFStatus(count int) {
	if count > 0 {
		logInfo("Fetched %d dynamic Cloudflare CIDRs.", count)
	}
}

// countDynamicCF returns the number of new CIDRs that were added.
func countDynamicCF(before, after int) int {
	return after - before
}

func wafCIDRCount() int {
	wafCIDRsMu.Lock()
	defer wafCIDRsMu.Unlock()
	return len(wafCIDRs)
}

// formatWAFInfo returns a user-friendly WAF info line.
func formatWAFInfo(wafName string, behindWAF bool) string {
	if wafName != "Unknown" {
		return fmt.Sprintf("WAF: %s", wafName)
	}
	if behindWAF {
		return "WAF: detected (IP in known WAF/CDN range)"
	}
	return "WAF: not detected"
}
