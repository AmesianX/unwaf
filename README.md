
# Unwaf v3.0

[![Go Version](https://img.shields.io/github/go-mod/go-version/mmarting/unwaf)](https://go.dev/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Unwaf is a Go tool designed to help identify WAF bypasses using **passive techniques**. It automates the process of discovering the real origin IP behind a WAF/CDN by combining multiple discovery methods and verifying candidates through HTML similarity comparison, SSL certificate fingerprinting, and HTTP header analysis.

Unwaf is automating the steps I explained on this LinkedIn Post: [Passive WAF bypassing](https://www.linkedin.com/posts/martinmarting_bugbounty-bugbountytips-pentesting-activity-7217385665729093632-oZEP)

## What's new in v3.0

- **6 new discovery methods** — AlienVault OTX, RapidDNS, HackerTarget, Wayback Machine, Shodan, DNSDB/Farsight
- **MMH3 favicon hashing** — computes MurmurHash3 for direct Shodan `http.favicon.hash` queries
- **Shodan API integration** — searches by SSL cert CN, hostname, and favicon hash
- **DNSDB/Farsight integration** — historical DNS record lookup via NDJSON API
- **SSL certificate fingerprint matching** — compares serial numbers, CN, and SAN overlap between domain and candidate
- **HTTP response header comparison** — compares Server, X-Powered-By, and Set-Cookie headers
- **Status code matching** — boosts or penalizes candidates based on HTTP status code alignment
- **Overall scoring system** — 60% HTML similarity + 25% cert match + 15% header match + status adjustment
- **CIDR neighbor scanning** (`--scan-neighbors`) — scans /24 neighbors of confirmed bypass IPs
- **JSON output** (`--json`) — structured JSON for automation and integration
- **Batch mode** (`-l domains.txt`) — process multiple domains from a file
- **File output** (`-o results.txt`) — write results to a file
- **ASN lookup** — identifies the ASN and organization for confirmed bypass IPs
- **Progress bars** — visual progress tracking for port scanning and verification
- **Context/cancellation** — clean Ctrl+C handling with graceful shutdown
- **Configurable timeout** (`--timeout`) — adjustable HTTP timeout
- **Rate limiting** (`--rate-limit`) — control request rate to avoid bans
- **Retry logic** — automatic retry with exponential backoff on 429/5xx
- **Proxy support** (`--proxy`) — HTTP and SOCKS5 proxy support
- **Dynamic Cloudflare CIDRs** — fetches live IP ranges from Cloudflare at runtime
- **IPv6 WAF CIDRs** — Cloudflare, Akamai, Fastly, and CloudFront IPv6 ranges
- **More WAF signatures** — FortiWeb, Radware, Azure Front Door, Google Cloud Armor, Vercel, Netlify
- **Dynamic step counter** — discovery steps adjust based on which API keys are configured
- **Multi-file codebase** — split into 13 files for maintainability

## Discovery methods

| Method | Type | Description |
|---|---|---|
| SPF records | Free | Extracts IPs from `ip4:`/`ip6:` SPF mechanisms |
| MX records | Free | Resolves mail server hostnames (skips Google/Microsoft/etc.) |
| Subdomain probing | Free | Resolves 30+ common subdomains (mail, dev, staging, cpanel, origin, etc.) |
| Certificate Transparency | Free | Queries crt.sh for all subdomains, resolves to non-WAF IPs |
| AlienVault OTX | Free | Passive DNS records (optional API key raises rate limits) |
| RapidDNS | Free | Subdomain enumeration via HTML scraping |
| HackerTarget | Free | Host search API (50 req/day) |
| Wayback Machine | Free | Extracts hostnames from archived URLs via CDX API |
| WAF detection | Free | Fingerprints the WAF vendor via HTTP headers |
| Favicon hashing | Free | Generates MD5, SHA256, and MMH3 hashes for Shodan/Censys search |
| Shodan host search | API (free tier) | Searches by SSL cert CN, hostname, and favicon hash |
| SecurityTrails history | API (free tier) | Historical DNS A records (50 req/month free) |
| ViewDNS history | API (paid) | Historical DNS A records |
| Censys SSL search | API (paid) | Finds hosts presenting SSL certs matching the domain |
| DNSDB/Farsight | API (paid) | Historical DNS records via NDJSON API |

## Verification methods

| Method | Weight | Description |
|---|---|---|
| HTML similarity | 60% | Diff-based text comparison with reference page |
| SSL certificate | 25% | Serial number (50%), CN match (25%), SAN overlap (25%) |
| HTTP headers | 15% | Server, X-Powered-By, and Set-Cookie name comparison |
| Status code | ±5-20% | Bonus for match, penalty for success/error mismatch |

## Installation

```sh
go install github.com/mmarting/unwaf@latest
```

## Usage

```sh
unwaf -h
```

## Options

    -d, --domain        The domain to check (required unless -l is used)
    -s, --source        The source HTML file to compare (optional)
    -c, --config        The config file path (optional, default: $HOME/.unwaf.conf)
    -t, --threshold     Similarity threshold percentage (optional, default: 60)
    -w, --workers       Number of concurrent workers (optional, default: 50)
    -v, --verbose       Enable verbose output
    -q, --quiet         Silent mode: only output bypass IPs (for piping/automation)
    --timeout           HTTP timeout in seconds (optional, default: 10)
    --rate-limit        Max HTTP requests per second, 0=unlimited (optional, default: 0)
    --proxy             Proxy URL (http:// or socks5://) (optional)
    --scan-neighbors    Scan /24 neighbors of confirmed bypass IPs (optional)
    --json              Output results as JSON
    -l, --list          File containing domains to check, one per line
    -o, --output        Write results to file
    --version           Print version and exit
    -h, --help          Display help information

## Examples

Check a domain (free methods only, no API keys needed):

```sh
unwaf -d example.com
```

Both bare domains and full URLs work:

```sh
unwaf -d https://example.com/path
```

Check with a manually saved HTML file (useful when WAF blocks the tool):

```sh
unwaf -d example.com -s original.html
```

Lower the similarity threshold to catch partial matches:

```sh
unwaf -d example.com -t 40
```

Increase concurrency for faster scanning:

```sh
unwaf -d example.com -w 100
```

Verbose mode to see every resolved subdomain/IP:

```sh
unwaf -d example.com -v
```

Silent mode for automation — outputs only IPs, one per line:

```sh
unwaf -q -d example.com
```

JSON output for automation:

```sh
unwaf -d example.com --json
```

Batch mode with domain list:

```sh
unwaf -l domains.txt --json -o results.json
```

Use a proxy (Tor, Burp, etc.):

```sh
unwaf -d example.com --proxy socks5://127.0.0.1:9050
```

Scan /24 neighbors of bypass IPs:

```sh
unwaf -d example.com --scan-neighbors
```

Rate-limit requests to 2/sec with a 5s timeout:

```sh
unwaf -d example.com --rate-limit 2 --timeout 5
```

### Piping into other tools

```sh
# Feed into nuclei
unwaf -q -d target.com | nuclei -l - -t waf-bypass.yaml

# Feed into httpx
unwaf -q -d target.com | httpx -silent

# Batch recon
cat domains.txt | while read d; do unwaf -q -d "$d" | sed "s/^/$d,/"; done > results.csv

# JSON + jq
unwaf -d target.com --json | jq '.bypasses[].ip'
```

## Configuration

On first run, Unwaf creates `$HOME/.unwaf.conf` with this template:

```ini
# Unwaf config file — API keys for optional discovery methods
# Free methods (SPF, MX, crt.sh, subdomains, OTX, RapidDNS, HackerTarget, Wayback) work without any keys.

# ViewDNS.info — DNS history (https://viewdns.info/api/)
viewdns=""

# SecurityTrails — DNS history (https://securitytrails.com/corp/api)
securitytrails=""

# Censys — SSL certificate search (requires a PAID license)
censys_token=""
censys_org_id=""

# AlienVault OTX — passive DNS (optional, raises rate limits)
otx_api_key=""

# Shodan — host search by SSL cert, hostname, favicon hash
shodan_api_key=""

# DNSDB/Farsight — historical DNS records
dnsdb_api_key=""
```

## How it works

1. **Dynamic WAF CIDRs** — Fetches live Cloudflare IP ranges and combines with hardcoded WAF/CDN ranges (including IPv6).
2. **WAF Confirmation** — Resolves the domain's current A records, checks if they fall in known WAF/CDN ranges, and fingerprints via HTTP headers.
3. **Favicon Hashing** — Fetches favicon.ico and generates MD5, SHA256, and MMH3 (Shodan) hashes.
4. **IP Discovery** — Runs all enabled methods (up to 13 sources) to collect candidate origin IPs.
5. **Filtering** — Discards IPs belonging to known WAF/CDN ranges and IPs that match the domain's current DNS resolution.
6. **Port Scanning** — Checks candidates on 8 common web ports concurrently with progress bar.
7. **Origin Verification** — For each web server:
   - Fetches HTML (direct IP + Host-header injection) and compares with reference
   - Compares SSL certificate fingerprints on TLS ports
   - Compares HTTP response headers
   - Calculates overall score (60% HTML + 25% cert + 15% headers ± status)
8. **Neighbor Scanning** (optional) — Expands confirmed bypass IPs to /24 subnets and scans neighbors.
9. **ASN Lookup** — Identifies ASN and organization for confirmed bypass IPs.
10. **Results** — Reports matches above the threshold with scores, ASN info, and `curl` verification commands.

## Author

**Martín Martín**

[My website](https://mmartin.me/) · [LinkedIn](https://www.linkedin.com/in/martinmarting/)

## License

`unwaf` is distributed under GPL v3 License.
