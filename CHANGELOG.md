# Changelog

## v3.0.0

### New discovery methods
- **AlienVault OTX** — free passive DNS lookup (optional API key raises rate limits)
- **RapidDNS** — free subdomain enumeration via HTML scraping
- **HackerTarget** — free host search API (50 req/day)
- **Wayback Machine** — extracts unique hostnames from archived URLs via CDX API
- **Shodan API** — searches by SSL cert CN, hostname, and favicon MMH3 hash (API key required)
- **DNSDB/Farsight** — historical DNS record lookup via NDJSON API (API key required)

### New verification techniques
- **SSL certificate fingerprint matching** — compares serial number (50%), Subject CN (25%), and SAN overlap (25%) on TLS ports
- **HTTP response header comparison** — compares Server, X-Powered-By, and Set-Cookie name headers
- **Status code matching** — 5% boost for matching success codes, 20% penalty for success/error mismatch, 10% penalty for matching error codes
- **Overall scoring system** — 60% HTML similarity + 25% cert match + 15% header match ± status adjustment
- **CIDR neighbor scanning** (`--scan-neighbors`) — scans /24 neighbors of confirmed bypass IPs
- **WAF header detection on candidates** — discards candidates whose responses contain WAF-specific headers (cf-ray, x-amz-cf-id, etc.), indicating traffic is still routed through the WAF
- **Header match suppression for error pages** — header similarity forced to 0% when candidate returns 4xx; generic error pages share headers that don't indicate origin identity
- **4xx reference response warning** — warns when the reference HTML fetch returns 4xx and suggests `--source / -s`

### Anti-bot evasion
- **uTLS Chrome TLS fingerprint** — replaces Go's default TLS stack with uTLS `HelloChrome_Auto`, impersonating Chrome's JA3/JA4 fingerprint to bypass WAFs like Cloudflare that detect Go's TLS stack
- **HTTP/2 support** — HTTPS requests use `http2.Transport` (h2-first with h1 fallback); Cloudflare and other WAFs reject HTTP/1.1-only TLS connections as non-browser
- **Browser-realistic headers** — `Sec-Fetch-*`, `Sec-Ch-Ua-*`, `Upgrade-Insecure-Requests`, and `Cache-Control` headers to mimic real Chrome navigation requests

### New features
- **MMH3 favicon hash** — computes MurmurHash3 for direct `http.favicon.hash` Shodan queries
- **JSON output** (`--json`) — structured JSON output for automation and pipeline integration
- **Batch mode** (`-l domains.txt`) — process multiple domains from a file
- **File output** (`-o results.txt`) — write results to a file
- **ASN lookup** — identifies ASN and organization for confirmed bypass IPs via ip-api.com
- **Progress bars** — visual progress tracking for port scanning and verification phases
- **Context/cancellation** — clean Ctrl+C handling with graceful shutdown via signal.NotifyContext
- **Configurable timeout** (`--timeout N`) — adjustable HTTP timeout (default 10s)
- **Rate limiting** (`--rate-limit N`) — control requests per second to avoid bans
- **Retry logic** — automatic retry with exponential backoff on HTTP 429/5xx responses
- **Proxy support** (`--proxy URL`) — HTTP and SOCKS5 proxy support
- **`--version` flag** — prints `unwaf v3.0.0` and exits

### WAF detection improvements
- **Dynamic Cloudflare CIDRs** — fetches live IP ranges from cloudflare.com/ips-v4 and ips-v6 at runtime
- **IPv6 WAF CIDRs** — added Cloudflare, Akamai, Fastly, and AWS CloudFront IPv6 ranges
- **New WAF signatures** — FortiWeb, Radware, Azure Front Door, Google Cloud Armor, Vercel, Netlify

### Code quality
- **Multi-file architecture** — split monolithic main.go into 13 files (types, config, display, network, waf, http, favicon, discovery, discovery_new, verify, scan, output, progress, main)
- **Dynamic step counter** — discovery steps automatically adjust based on configured API keys
- **Context threading** — `ctx context.Context` threaded through all HTTP/discovery functions
- **New dependencies** — golang.org/x/time/rate, github.com/spaolacci/murmur3, github.com/schollz/progressbar/v3, github.com/refraction-networking/utls

---

## v2.0.0

### New discovery methods
- **MX records** — resolves self-hosted mail servers, skips third-party providers (Google, Microsoft, etc.)
- **Subdomain probing** — resolves 30+ common subdomains that often bypass WAF (mail, dev, staging, cpanel, origin, api, admin, vpn, etc.)
- **Certificate Transparency** — queries crt.sh for all subdomains in CT logs, resolves them, filters out WAF IPs
- **Censys SSL certificate search** — finds hosts presenting SSL certs matching the domain (API key required)

### New verification techniques
- **Host-header injection** — sends requests to candidate IPs with `Host: target.com`, catching virtual hosts that only respond to the correct hostname
- **WAF confirmation** — resolves the domain's A records at startup and checks if they belong to known WAF/CDN ranges; warns clearly if the target isn't behind a WAF
- **Current IP exclusion** — filters out IPs that match the domain's current DNS resolution (same IP ≠ bypass)
- **WAF/CDN IP filtering** — discards IPs in known Cloudflare, Akamai, CloudFront, Fastly, Sucuri, Imperva ranges

### New features
- **WAF fingerprinting** — identifies 12 WAF vendors via HTTP response headers
- **Favicon hashing** — generates MD5/SHA256 of favicon.ico for manual Shodan/Censys searches
- **Extended port scanning** — checks 8 ports: 80, 443, 8080, 8443, 8000, 8008, 8888, 9443
- **Quiet mode** (`-q`) — outputs only bypass IPs, one per line, for piping into nuclei/httpx/etc.
- **Smart domain input** — strips scheme, path, port from input (`https://example.com/path` → `example.com`)
- **Configurable threshold** (`-t`) — adjust similarity percentage for stricter or looser matching
- **Configurable concurrency** (`-w`) — control number of parallel workers
- **Verbose mode** (`-v`) — shows every subdomain/IP resolution for debugging

### Improvements
- Updated Go version: 1.22.5 → 1.23
- Updated dependencies: fatih/color 1.17→1.18, golang.org/x/net 0.27→0.34, golang.org/x/sys 0.22→0.29, golang.org/x/text 0.16→0.21
- Improved HTTP client: connection pooling, redirect limits, updated User-Agent
- Color-coded output with section headers
- Ready-to-use `curl` verification commands in results
- Config file permissions tightened to 0600
- Config file now supports comments and blank lines
