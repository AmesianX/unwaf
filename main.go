package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/sergi/go-diff/diffmatchpatch"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

const version = "2.0.0"

const logo = `
░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░   
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█████████████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
                                                                     `

const usage = `
Author:
  Name:               Martín Martín
  Website:            https://mmartin.me/
  LinkedIn:           https://www.linkedin.com/in/martinmarting/
  GitHub:             https://github.com/mmarting/unwaf

Usage:
  -d, --domain        The domain to check (required)
  -s, --source        The source HTML file to compare (optional)
  -c, --config        The config file path (optional, default: $HOME/.unwaf.conf)
  -t, --threshold     Similarity threshold percentage (optional, default: 60)
  -w, --workers       Number of concurrent workers (optional, default: 50)
  -v, --verbose       Enable verbose output
  -q, --quiet         Silent mode: only output bypass IPs (for piping/automation)
  -h, --help          Display help information

Examples:
  1. Check a domain:
     unwaf -d example.com

  2. Check a domain with a manually provided HTML file:
     unwaf -d example.com -s original.html

  3. Check a domain with a custom location for the config file:
     unwaf -d example.com -c /path/to/config

  4. Check a domain with a lower similarity threshold:
     unwaf -d example.com -t 40

  5. Check with more concurrent workers:
     unwaf -d example.com -w 100

Discovery methods:
  [FREE]    SPF records (ip4/ip6 mechanisms)
  [FREE]    MX records (mail server IPs)
  [FREE]    Common mail/origin subdomains (DNS resolution)
  [FREE]    Certificate Transparency logs (crt.sh)
  [FREE]    WAF detection (fingerprinting)
  [FREE]    Favicon hash fingerprinting (for manual Shodan/Censys search)
  [API]     ViewDNS IP history
  [API]     SecurityTrails DNS history
  [API]     Censys SSL certificate search

Note:
  API-based methods require keys in the config file: $HOME/.unwaf.conf.
  The tool will create an example config file after first execution.
`

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type Config struct {
	ViewDNS        string `json:"viewdns"`
	SecurityTrails string `json:"securitytrails"`
	CensysID       string `json:"censys_id"`       // Legacy v2 (deprecated)
	CensysSecret   string `json:"censys_secret"`   // Legacy v2 (deprecated)
	CensysToken    string `json:"censys_token"`     // v3 Platform PAT
	CensysOrgID    string `json:"censys_org_id"`    // v3 Platform Org ID
}

var apiKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Known WAF/CDN IP ranges (CIDR prefixes) to filter out
var wafCIDRs = []string{
	// Cloudflare
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
	"131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
	"172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
	"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
	// Akamai (common ranges)
	"23.0.0.0/12", "104.64.0.0/10",
	// Fastly
	"151.101.0.0/16",
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
}

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

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

var (
	boldGreen  = color.New(color.Bold, color.FgGreen)
	boldRed    = color.New(color.Bold, color.FgRed)
	boldYellow = color.New(color.Bold, color.FgYellow)
	boldCyan   = color.New(color.Bold, color.FgCyan)
	boldWhite  = color.New(color.Bold, color.FgWhite)
	dimWhite   = color.New(color.Faint)
)

var silent bool

func showUsage() {
	fmt.Println(logo)
	fmt.Println(usage)
}

func sectionHeader(title string) {
	if silent {
		return
	}
	padLen := 60 - len(title)
	if padLen < 0 {
		padLen = 0
	}
	fmt.Println()
	boldCyan.Printf("── %s %s", title, strings.Repeat("─", padLen))
	fmt.Println()
}

func logInfo(format string, a ...interface{}) {
	if silent {
		return
	}
	fmt.Printf("  "+format+"\n", a...)
}

func logFound(format string, a ...interface{}) {
	if silent {
		return
	}
	boldGreen.Printf("  ✓ "+format+"\n", a...)
}

func logWarn(format string, a ...interface{}) {
	if silent {
		return
	}
	boldYellow.Printf("  ⚠ "+format+"\n", a...)
}

func logError(format string, a ...interface{}) {
	if silent {
		return
	}
	boldRed.Printf("  ✗ "+format+"\n", a...)
}

func logVerbose(verbose bool, format string, a ...interface{}) {
	if silent {
		return
	}
	if verbose {
		dimWhite.Printf("    "+format+"\n", a...)
	}
}

// ---------------------------------------------------------------------------
// Config management
// ---------------------------------------------------------------------------

func createDefaultConfig(configPath string) error {
	defaultConfig := `# Unwaf config file — API keys for optional discovery methods
# Free methods (SPF, MX, crt.sh, subdomains) work without any keys.

# ViewDNS.info — DNS history (https://viewdns.info/api/)
viewdns=""

# SecurityTrails — DNS history (https://securitytrails.com/corp/api)
securitytrails=""

# Censys — SSL certificate search (https://docs.censys.com/reference/get-started)
# Option 1: New Platform API (recommended, works with all accounts)
#   Get your PAT from: https://app.censys.io/account/api
censys_token=""
#   Org ID is optional (only needed for paid/org accounts, visible in Platform URL)
censys_org_id=""
# Option 2: Legacy Search API v2 (deprecated, may not work with new accounts)
censys_id=""
censys_secret=""
`
	return os.WriteFile(configPath, []byte(defaultConfig), 0600)
}

func loadConfig(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := createDefaultConfig(configPath); err != nil {
			return nil, err
		}
	}

	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		if value == "" || !apiKeyRegex.MatchString(value) {
			continue
		}
		switch key {
		case "viewdns":
			config.ViewDNS = value
		case "securitytrails":
			config.SecurityTrails = value
		case "censys_id":
			config.CensysID = value
		case "censys_secret":
			config.CensysSecret = value
		case "censys_token":
			config.CensysToken = value
		case "censys_org_id":
			config.CensysOrgID = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return config, nil
}

// ---------------------------------------------------------------------------
// Domain/IP helpers
// ---------------------------------------------------------------------------

func extractMainDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

// sanitizeDomain strips scheme, port, path, trailing slashes from user input
// so both "example.com" and "https://www.example.com/path" work.
func sanitizeDomain(input string) string {
	d := strings.TrimSpace(input)
	// Strip scheme
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	// Strip path and query
	if idx := strings.IndexAny(d, "/?#"); idx != -1 {
		d = d[:idx]
	}
	// Strip port
	if host, _, err := net.SplitHostPort(d); err == nil {
		d = host
	}
	// Strip trailing dots and slashes
	d = strings.TrimRight(d, "./")
	return d
}

func isWAFIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, cidr := range wafCIDRs {
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

	// Skip ranges larger than /24 to avoid scanning too many IPs
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

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

var defaultClient = newHTTPClient(10 * time.Second)

func fetchHTML(url string) (string, int, error) {
	return fetchHTMLWithHost(url, "")
}

func fetchHTMLWithHost(url, host string) (string, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", 0, err
	}

	if host != "" {
		req.Host = host
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")

	resp, err := defaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return "", resp.StatusCode, fmt.Errorf("server error: %d", resp.StatusCode)
	}

	reader, err := charset.NewReader(resp.Body, resp.Header.Get("Content-Type"))
	if err != nil {
		return "", resp.StatusCode, err
	}
	z := html.NewTokenizer(reader)
	var b strings.Builder
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		token := z.Token()
		if token.Type == html.TextToken {
			b.WriteString(token.Data)
		}
	}
	return b.String(), resp.StatusCode, nil
}

func fetchRawBytes(url string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// ---------------------------------------------------------------------------
// WAF detection
// ---------------------------------------------------------------------------

func detectWAF(domain string) string {
	urls := []string{
		"https://" + domain,
		"http://" + domain,
	}

	for _, url := range urls {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := defaultClient.Do(req)
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
		if strings.Contains(server, "cloudflare") {
			return "Cloudflare"
		}
		if strings.Contains(server, "akamaighost") || strings.Contains(server, "akamai") {
			return "Akamai"
		}
		if strings.Contains(server, "sucuri") {
			return "Sucuri"
		}
		if strings.Contains(server, "incapsula") || strings.Contains(server, "imperva") {
			return "Imperva/Incapsula"
		}
		if strings.Contains(server, "ddos-guard") {
			return "DDoS-Guard"
		}
	}
	return "Unknown"
}

// ---------------------------------------------------------------------------
// Favicon hash (for manual Shodan/Censys lookup)
// ---------------------------------------------------------------------------

func getFaviconHashes(domain string) (string, string) {
	urls := []string{
		"https://" + domain + "/favicon.ico",
		"http://" + domain + "/favicon.ico",
	}

	for _, url := range urls {
		body, statusCode, err := fetchRawBytes(url)
		if err != nil || statusCode != 200 || len(body) == 0 {
			continue
		}
		md5Hash := fmt.Sprintf("%x", md5.Sum(body))
		sha256Hash := fmt.Sprintf("%x", sha256.Sum256(body))
		return md5Hash, sha256Hash
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// Discovery: SPF records
// ---------------------------------------------------------------------------

func extractIPsFromSPF(domain string) ([]string, error) {
	var ips []string
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return nil, err
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			parts := strings.Fields(txt)
			for _, part := range parts {
				if strings.HasPrefix(part, "ip4:") {
					ip := strings.TrimPrefix(part, "ip4:")
					if strings.Contains(ip, "/") {
						rangedIps, err := expandIPRange(ip)
						if err != nil {
							continue
						}
						ips = append(ips, rangedIps...)
					} else {
						ips = append(ips, ip)
					}
				} else if strings.HasPrefix(part, "ip6:") {
					ip := strings.TrimPrefix(part, "ip6:")
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: MX records
// ---------------------------------------------------------------------------

func extractIPsFromMX(domain string) ([]string, error) {
	var ips []string
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
	}

	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		// Skip third-party mail services
		lowerHost := strings.ToLower(host)
		if strings.Contains(lowerHost, "google") ||
			strings.Contains(lowerHost, "outlook") ||
			strings.Contains(lowerHost, "microsoft") ||
			strings.Contains(lowerHost, "mimecast") ||
			strings.Contains(lowerHost, "proofpoint") ||
			strings.Contains(lowerHost, "barracuda") ||
			strings.Contains(lowerHost, "pphosted") {
			continue
		}

		addrs, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		ips = append(ips, addrs...)
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: Common subdomains
// ---------------------------------------------------------------------------

func extractIPsFromSubdomains(domain string, verbose bool) []string {
	var ips []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, sub := range originSubdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			fqdn := subdomain + "." + domain
			addrs, err := net.LookupHost(fqdn)
			if err != nil {
				return
			}
			mu.Lock()
			for _, addr := range addrs {
				if !isWAFIP(addr) && !isPrivateIP(addr) {
					ips = append(ips, addr)
					logVerbose(verbose, "Subdomain %s → %s", fqdn, addr)
				}
			}
			mu.Unlock()
		}(sub)
	}
	wg.Wait()
	return ips
}

// ---------------------------------------------------------------------------
// Discovery: Certificate Transparency (crt.sh)
// ---------------------------------------------------------------------------

type CrtShEntry struct {
	NameValue string `json:"name_value"`
}

func extractIPsFromCrtSh(domain string, verbose bool) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	client := newHTTPClient(30 * time.Second)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []CrtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response: %w", err)
	}

	// Extract unique subdomain names
	subdomainSet := make(map[string]bool)
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if name != "" && !subdomainSet[name] {
				subdomainSet[name] = true
			}
		}
	}

	logInfo("Found %d unique subdomains in CT logs.", len(subdomainSet))

	// Resolve subdomains to IPs, filtering WAF IPs
	var ips []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // limit concurrent DNS lookups

	for subdomain := range subdomainSet {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addrs, err := net.LookupHost(sub)
			if err != nil {
				return
			}
			mu.Lock()
			for _, addr := range addrs {
				if !isWAFIP(addr) && !isPrivateIP(addr) {
					ips = append(ips, addr)
					logVerbose(verbose, "CT subdomain %s → %s", sub, addr)
				}
			}
			mu.Unlock()
		}(subdomain)
	}
	wg.Wait()
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: ViewDNS
// ---------------------------------------------------------------------------

func fetchIPsFromViewDNS(domain, apiKey string) ([]string, error) {
	var ips []string
	url := fmt.Sprintf("https://api.viewdns.info/iphistory/?domain=%s&apikey=%s&output=json", domain, apiKey)
	resp, err := defaultClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("received non-200 response code: %d", resp.StatusCode)
	}

	var result struct {
		Query    map[string]string `json:"query"`
		Response struct {
			Records []struct {
				IP string `json:"ip"`
			} `json:"records"`
		} `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	for _, record := range result.Response.Records {
		ips = append(ips, record.IP)
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: SecurityTrails
// ---------------------------------------------------------------------------

func fetchIPsFromSecurityTrails(domain, apiKey string) ([]string, error) {
	var ips []string
	url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", apiKey)

	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("received non-200 response code: %d", resp.StatusCode)
	}

	var result struct {
		Records []struct {
			Values []struct {
				IP string `json:"ip"`
			} `json:"values"`
		} `json:"records"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	for _, record := range result.Records {
		for _, value := range record.Values {
			ips = append(ips, value.IP)
		}
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: Censys SSL certificate search
// ---------------------------------------------------------------------------

// fetchIPsFromCensysV3 uses the new Platform API (Bearer token auth)
func fetchIPsFromCensysV3(domain, token, orgID string) ([]string, error) {
	var ips []string

	// Search for hosts presenting certificates matching the domain
	// org_id is optional for free accounts, required for paid/org accounts
	searchURL := "https://api.platform.censys.io/v3/global/search/query"
	if orgID != "" {
		searchURL += "?organization_id=" + orgID
	}

	query := fmt.Sprintf("cert.names: %s", domain)
	bodyData := fmt.Sprintf(`{"query":"%s","page_size":50}`, query)

	req, err := http.NewRequest("POST", searchURL, strings.NewReader(bodyData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if orgID != "" {
		req.Header.Set("X-Organization-ID", orgID)
	}

	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		hint := ""
		if resp.StatusCode == 403 {
			hint = " (ensure your user has the 'API Access' role in Censys Platform Settings > Members)"
		}
		if resp.StatusCode == 401 {
			hint = " (check your PAT is valid at https://app.censys.io/account/api)"
		}
		return nil, fmt.Errorf("Censys Platform API returned status %d%s: %s", resp.StatusCode, hint, truncateStr(string(body), 200))
	}

	var searchResult struct {
		Result struct {
			Hits []struct {
				IP       string `json:"ip"`
				Services []struct {
					IP string `json:"ip"`
				} `json:"services"`
			} `json:"hits"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
		return nil, fmt.Errorf("failed to parse Censys response: %v", err)
	}

	for _, hit := range searchResult.Result.Hits {
		if hit.IP != "" && !isWAFIP(hit.IP) {
			ips = append(ips, hit.IP)
		}
		for _, svc := range hit.Services {
			if svc.IP != "" && !isWAFIP(svc.IP) {
				ips = append(ips, svc.IP)
			}
		}
	}

	return ips, nil
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// fetchIPsFromCensysV2 uses the legacy Search API v2 (BasicAuth, deprecated)
func fetchIPsFromCensysV2(domain, apiID, apiSecret string) ([]string, error) {
	var ips []string

	// Step 1: Search for certificates matching the domain
	searchURL := "https://search.censys.io/api/v2/certificates/search"

	query := fmt.Sprintf("names: %s", domain)
	bodyData := fmt.Sprintf(`{"q":"%s","per_page":100}`, query)

	req, err := http.NewRequest("POST", searchURL, strings.NewReader(bodyData))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(apiID, apiSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Censys Search API v2 returned status %d (v2 is deprecated for new accounts — use censys_token + censys_org_id instead)", resp.StatusCode)
	}

	var certResult struct {
		Result struct {
			Hits []struct {
				Fingerprint string `json:"fingerprint_sha256"`
			} `json:"hits"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&certResult); err != nil {
		return nil, err
	}

	// Step 2: For each certificate, look up which hosts present it
	for _, hit := range certResult.Result.Hits {
		hostsURL := fmt.Sprintf("https://search.censys.io/api/v2/certificates/%s/hosts", hit.Fingerprint)
		hReq, err := http.NewRequest("GET", hostsURL, nil)
		if err != nil {
			continue
		}
		hReq.SetBasicAuth(apiID, apiSecret)

		hResp, err := defaultClient.Do(hReq)
		if err != nil {
			continue
		}

		var hostResult struct {
			Result struct {
				Hosts []struct {
					IP string `json:"ip"`
				} `json:"hosts"`
			} `json:"result"`
		}

		if err := json.NewDecoder(hResp.Body).Decode(&hostResult); err != nil {
			hResp.Body.Close()
			continue
		}
		hResp.Body.Close()

		for _, host := range hostResult.Result.Hosts {
			if !isWAFIP(host.IP) {
				ips = append(ips, host.IP)
			}
		}
	}

	return ips, nil
}

// fetchIPsFromCensys tries v3 first, falls back to v2
func fetchIPsFromCensys(domain string, config *Config) ([]string, error) {
	// Prefer v3 Platform API (only token required, org_id optional)
	if config.CensysToken != "" {
		logVerbose(true, "Using Censys Platform API v3 (Bearer token)")
		return fetchIPsFromCensysV3(domain, config.CensysToken, config.CensysOrgID)
	}

	// Fallback to legacy v2
	if config.CensysID != "" && config.CensysSecret != "" {
		logVerbose(true, "Using Censys Search API v2 (legacy, deprecated)")
		return fetchIPsFromCensysV2(domain, config.CensysID, config.CensysSecret)
	}

	return nil, fmt.Errorf("no Censys credentials configured")
}

// ---------------------------------------------------------------------------
// Port scanning & web server detection
// ---------------------------------------------------------------------------

func isPortOpen(ip string, port int) bool {
	timeout := 2 * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

type webServerResult struct {
	IP    string
	Ports []int
}

func checkWebServer(ip string, wg *sync.WaitGroup, mu *sync.Mutex, results *[]webServerResult, runningCounter *int, checkedCounter *int, total int) {
	defer wg.Done()
	var openPorts []int
	for _, port := range webPorts {
		if isPortOpen(ip, port) {
			openPorts = append(openPorts, port)
		}
	}

	mu.Lock()
	(*checkedCounter)++
	if len(openPorts) > 0 {
		*results = append(*results, webServerResult{IP: ip, Ports: openPorts})
		(*runningCounter)++
	}
	if !silent {
		fmt.Printf("\r  Scanning: %d/%d IPs with web server (%d checked, %.1f%%)",
			*runningCounter, total, *checkedCounter, float64(*checkedCounter)/float64(total)*100)
	}
	mu.Unlock()
}

// ---------------------------------------------------------------------------
// HTML comparison
// ---------------------------------------------------------------------------

func compareHTML(original, fetched string) float64 {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(original, fetched, false)
	similarity := 0
	for _, diff := range diffs {
		if diff.Type == diffmatchpatch.DiffEqual {
			similarity += len(diff.Text)
		}
	}
	totalLength := len(original) + len(fetched)
	if totalLength == 0 {
		return 1.0
	}
	return float64(similarity*2) / float64(totalLength)
}

// ---------------------------------------------------------------------------
// Unique helper
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

type BypassResult struct {
	IP         string
	Port       int
	Similarity float64
	Method     string // "direct" or "host-header"
}

// ---------------------------------------------------------------------------
// Main processing
// ---------------------------------------------------------------------------

func processDomain(domain, source, configPath string, threshold float64, workers int, verbose bool) {
	config, err := loadConfig(configPath)
	if err != nil {
		config = &Config{}
	}

	mainDomain := extractMainDomain(domain)

	// ── WAF Detection ──
	sectionHeader("WAF Detection")

	// Resolve current A records for the domain
	currentIPs, dnsErr := net.LookupHost(domain)
	if dnsErr != nil {
		logError("Could not resolve domain %s: %v", domain, dnsErr)
		return
	}

	// Build a set of current IPs for fast lookup
	currentIPSet := make(map[string]bool)
	for _, ip := range currentIPs {
		currentIPSet[ip] = true
	}

	// Check if current IPs belong to known WAF/CDN ranges
	behindWAF := false
	for _, ip := range currentIPs {
		if isWAFIP(ip) {
			behindWAF = true
			break
		}
	}

	wafName := detectWAF(domain)

	if wafName != "Unknown" {
		logFound("Detected WAF: %s", wafName)
		behindWAF = true
	} else if behindWAF {
		logFound("Domain resolves to known WAF/CDN IP range.")
	}

	logInfo("Current DNS A records: %s", strings.Join(currentIPs, ", "))

	if !behindWAF {
		logWarn("Domain does NOT appear to be behind a WAF/CDN.")
		logWarn("Current IPs (%s) are not in known WAF/CDN ranges.", strings.Join(currentIPs, ", "))
		logWarn("The domain may be directly accessible — no bypass needed.")
		logInfo("Continuing anyway in case of an unrecognized WAF...")
	}

	// ── Favicon Hashes ──
	sectionHeader("Favicon Fingerprint")
	md5Hash, sha256Hash := getFaviconHashes(domain)
	if md5Hash != "" {
		logFound("Favicon MD5:    %s", md5Hash)
		logFound("Favicon SHA256: %s", sha256Hash)
		logInfo("Use these hashes to search Shodan/Censys for servers with the same favicon.")
		logInfo("  Shodan:  http.favicon.hash:<mmh3_hash>")
	} else {
		logWarn("No favicon found or could not be fetched.")
	}

	// ── Fetch original HTML ──
	sectionHeader("Reference HTML")
	var originalHTML string
	if source != "" {
		content, err := os.ReadFile(source)
		if err != nil {
			logError("Error reading source HTML file: %v", err)
			return
		}
		originalHTML = string(content)
		logFound("Loaded reference HTML from file: %s", source)
	} else {
		originalHTML, _, err = fetchHTML("https://" + domain)
		if err != nil {
			originalHTML, _, err = fetchHTML("http://" + domain)
			if err != nil {
				logError("Error fetching original HTML. The WAF might be blocking.")
				logInfo("Try providing the HTML manually using --source / -s.")
				return
			}
		}
		logFound("Fetched reference HTML from %s (%d chars)", domain, len(originalHTML))
	}

	// ── IP Discovery ──
	sectionHeader("IP Discovery")
	var allIPs []string
	ipSources := make(map[string]string) // IP → source label

	addIPs := func(source string, ips []string) {
		for _, ip := range ips {
			if !isWAFIP(ip) && !isPrivateIP(ip) {
				if _, exists := ipSources[ip]; !exists {
					ipSources[ip] = source
				}
			}
		}
		allIPs = append(allIPs, ips...)
	}

	// 1. SPF
	if !silent {
		fmt.Println()
		boldWhite.Println("  [1/7] SPF Records")
	}
	spfIPs, err := extractIPsFromSPF(mainDomain)
	if err != nil {
		logWarn("Error fetching SPF records: %v", err)
	} else {
		logInfo("Found %d IP(s) from SPF.", len(spfIPs))
		addIPs("SPF", spfIPs)
	}

	// 2. MX Records
	if !silent {
		boldWhite.Println("  [2/7] MX Records")
	}
	mxIPs, err := extractIPsFromMX(mainDomain)
	if err != nil {
		logWarn("Error fetching MX records: %v", err)
	} else {
		logInfo("Found %d IP(s) from MX records.", len(mxIPs))
		addIPs("MX", mxIPs)
	}

	// 3. Common subdomains
	if !silent {
		boldWhite.Println("  [3/7] Common Origin Subdomains")
	}
	subIPs := extractIPsFromSubdomains(mainDomain, verbose)
	logInfo("Found %d non-WAF IP(s) from %d subdomain probes.", len(subIPs), len(originSubdomains))
	addIPs("Subdomain", subIPs)

	// 4. Certificate Transparency
	if !silent {
		boldWhite.Println("  [4/7] Certificate Transparency (crt.sh)")
	}
	ctIPs, err := extractIPsFromCrtSh(mainDomain, verbose)
	if err != nil {
		logWarn("crt.sh error: %v", err)
	} else {
		logInfo("Found %d non-WAF IP(s) from CT logs.", len(ctIPs))
		addIPs("CT/crt.sh", ctIPs)
	}

	// 5. ViewDNS
	if !silent {
		boldWhite.Println("  [5/7] ViewDNS IP History")
	}
	if config.ViewDNS != "" {
		viewdnsIPs, err := fetchIPsFromViewDNS(mainDomain, config.ViewDNS)
		if err != nil {
			logWarn("ViewDNS error: %v", err)
		} else {
			logInfo("Found %d IP(s) from ViewDNS history.", len(viewdnsIPs))
			addIPs("ViewDNS", viewdnsIPs)
		}
	} else if !silent {
		dimWhite.Println("    Skipped — no API key. Add viewdns=<key> to config.")
	}

	// 6. SecurityTrails
	if !silent {
		boldWhite.Println("  [6/7] SecurityTrails DNS History")
	}
	if config.SecurityTrails != "" {
		stIPs, err := fetchIPsFromSecurityTrails(mainDomain, config.SecurityTrails)
		if err != nil {
			logWarn("SecurityTrails error: %v", err)
		} else {
			logInfo("Found %d IP(s) from SecurityTrails.", len(stIPs))
			addIPs("SecurityTrails", stIPs)
		}
	} else if !silent {
		dimWhite.Println("    Skipped — no API key. Add securitytrails=<key> to config.")
	}

	// 7. Censys
	if !silent {
		boldWhite.Println("  [7/7] Censys SSL Certificate Search")
	}
	hasCensysV3 := config.CensysToken != ""
	hasCensysV2 := config.CensysID != "" && config.CensysSecret != ""
	if hasCensysV3 || hasCensysV2 {
		censysIPs, err := fetchIPsFromCensys(mainDomain, config)
		if err != nil {
			logWarn("Censys error: %v", err)
		} else {
			logInfo("Found %d non-WAF IP(s) from Censys.", len(censysIPs))
			addIPs("Censys", censysIPs)
		}
	} else if !silent {
		dimWhite.Println("    Skipped — no API key. Add censys_token to config.")
		dimWhite.Println("    Get your PAT at: https://app.censys.io/account/api")
	}

	// Filter and deduplicate
	uniqueIPs := unique(allIPs)

	// Remove known WAF/CDN IPs and current domain IPs (same IP = not a bypass)
	var candidateIPs []string
	for _, ip := range uniqueIPs {
		if !isWAFIP(ip) && !isPrivateIP(ip) && !currentIPSet[ip] {
			candidateIPs = append(candidateIPs, ip)
		}
	}

	sectionHeader("Summary")
	logInfo("Total IPs collected: %d", len(allIPs))
	logInfo("Unique IPs: %d", len(uniqueIPs))
	logInfo("After filtering WAF/CDN + current domain IPs: %d candidate(s)", len(candidateIPs))

	if len(candidateIPs) == 0 {
		if !silent {
			fmt.Println()
			boldRed.Println("  ✗ No candidate IPs found. WAF bypass not possible with passive methods.")
			fmt.Println()
		}
		return
	}

	// ── Port Scanning ──
	sectionHeader("Web Server Detection")
	logInfo("Scanning %d candidate IPs on ports %v...", len(candidateIPs), webPorts)

	var webServers []webServerResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	runningCounter := 0
	checkedCounter := 0
	sem := make(chan struct{}, workers)

	for _, ip := range candidateIPs {
		wg.Add(1)
		go func(ip string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			checkWebServer(ip, &wg, &mu, &webServers, &runningCounter, &checkedCounter, len(candidateIPs))
		}(ip)
	}
	wg.Wait()
	if !silent {
		fmt.Printf("\r  Scanning complete: %d/%d IPs have a web server.                    \n", runningCounter, len(candidateIPs))
	}

	if len(webServers) == 0 {
		if !silent {
			fmt.Println()
			boldRed.Println("  ✗ No web servers found on candidate IPs. WAF bypass not found.")
			fmt.Println()
		}
		return
	}

	// ── HTML Comparison ──
	sectionHeader("Origin Server Verification")
	logInfo("Comparing HTML responses from %d web servers (threshold: %.0f%%)...", len(webServers), threshold)
	logInfo("Testing both direct IP access and Host-header injection.\n")

	var bypassResults []BypassResult

	checked := 0
	total := len(webServers)

	for _, ws := range webServers {
		checked++
		for _, port := range ws.Ports {
			var scheme string
			switch port {
			case 443, 8443, 9443:
				scheme = "https"
			default:
				scheme = "http"
			}

			url := fmt.Sprintf("%s://%s:%d", scheme, ws.IP, port)

			// Method 1: Direct IP access
			fetchedHTML, statusCode, err := fetchHTML(url)
			if err == nil && statusCode < 500 {
				similarity := compareHTML(originalHTML, fetchedHTML) * 100
				if similarity > threshold {
					bypassResults = append(bypassResults, BypassResult{
						IP: ws.IP, Port: port, Similarity: similarity, Method: "direct",
					})
				}
			}

			// Method 2: Host header injection
			fetchedHTML2, statusCode2, err := fetchHTMLWithHost(url, domain)
			if err == nil && statusCode2 < 500 {
				similarity2 := compareHTML(originalHTML, fetchedHTML2) * 100
				if similarity2 > threshold {
					bypassResults = append(bypassResults, BypassResult{
						IP: ws.IP, Port: port, Similarity: similarity2, Method: "host-header",
					})
				}
			}
		}
		if !silent {
			fmt.Printf("\r  Verified %d/%d web servers...", checked, total)
		}
	}
	if !silent {
		fmt.Println()
	}

	// ── Results ──
	sectionHeader("Results")

	if len(bypassResults) > 0 {
		// Sort by similarity descending
		sort.Slice(bypassResults, func(i, j int) bool {
			return bypassResults[i].Similarity > bypassResults[j].Similarity
		})

		// Deduplicate by IP+Port, keeping highest similarity
		seen := make(map[string]bool)
		var dedupResults []BypassResult
		for _, r := range bypassResults {
			key := fmt.Sprintf("%s:%d", r.IP, r.Port)
			if !seen[key] {
				seen[key] = true
				dedupResults = append(dedupResults, r)
			}
		}

		if silent {
			// Silent mode: one IP per line, nothing else
			printedIPs := make(map[string]bool)
			for _, r := range dedupResults {
				if !printedIPs[r.IP] {
					fmt.Println(r.IP)
					printedIPs[r.IP] = true
				}
			}
		} else {
			for _, r := range dedupResults {
				src := ipSources[r.IP]
				if src == "" {
					src = "unknown"
				}

				var scheme string
				switch r.Port {
				case 443, 8443, 9443:
					scheme = "https"
				default:
					scheme = "http"
				}

				fmt.Println()
				boldGreen.Printf("  ✓ POSSIBLE WAF BYPASS FOUND\n")
				logInfo("IP:         %s", r.IP)
				logInfo("Port:       %d", r.Port)
				logInfo("Method:     %s", r.Method)
				logInfo("Similarity: %.1f%%", r.Similarity)
				logInfo("Source:     %s", src)
				logInfo("Verify:     curl -sk -H \"Host: %s\" %s://%s:%d/", domain, scheme, r.IP, r.Port)
			}
		}
	} else if !silent {
		boldRed.Println("  ✗ WAF bypass not found with passive techniques.")
		fmt.Println()
		logInfo("Suggestions:")
		logInfo("  • Try lowering the threshold with -t 40")
		logInfo("  • Provide the HTML manually with -s if the WAF blocks fetching")
		logInfo("  • Add API keys for ViewDNS, SecurityTrails, Censys")
		logInfo("  • Search Shodan/Censys manually with the favicon hashes above")
		logInfo("  • Censys: get token + org ID at https://app.censys.io/account/api")
		logInfo("  • Look for SSRF vulnerabilities to induce outbound connections")
	}
	if !silent {
		fmt.Println()
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	domain := flag.String("domain", "", "The domain to check")
	flag.StringVar(domain, "d", "", "The domain to check (shorthand)")
	source := flag.String("source", "", "The source HTML file to compare")
	flag.StringVar(source, "s", "", "The source HTML file to compare (shorthand)")
	configPath := flag.String("config", filepath.Join(os.Getenv("HOME"), ".unwaf.conf"), "The config file path")
	flag.StringVar(configPath, "c", filepath.Join(os.Getenv("HOME"), ".unwaf.conf"), "The config file path (shorthand)")
	threshold := flag.Float64("threshold", 60, "Similarity threshold percentage")
	flag.Float64Var(threshold, "t", 60, "Similarity threshold percentage (shorthand)")
	numWorkers := flag.Int("workers", 50, "Number of concurrent workers")
	flag.IntVar(numWorkers, "w", 50, "Number of concurrent workers (shorthand)")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.BoolVar(verbose, "v", false, "Enable verbose output (shorthand)")
	quiet := flag.Bool("quiet", false, "Silent mode: only output bypass IPs, one per line")
	flag.BoolVar(quiet, "q", false, "Silent mode (shorthand)")
	help := flag.Bool("help", false, "Display help information")
	flag.BoolVar(help, "h", false, "Display help information (shorthand)")

	flag.Parse()

	if *help || *domain == "" {
		showUsage()
		os.Exit(1)
	}

	// Normalize: strip scheme, path, port, trailing slashes
	*domain = sanitizeDomain(*domain)
	if *domain == "" {
		fmt.Println("Error: invalid domain after sanitization.")
		os.Exit(1)
	}

	silent = *quiet

	if !silent {
		fmt.Println(logo)
		dimWhite.Printf("  v%s — Passive WAF bypass tool by Martín Martín\n", version)
		dimWhite.Printf("  Target: %s\n", *domain)
	}

	processDomain(*domain, *source, *configPath, *threshold, *numWorkers, *verbose)
}
