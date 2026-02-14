# Changelog

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
