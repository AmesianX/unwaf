
# unwaf

Unwaf is a Go tool designed to help identify WAF bypasses using **passive techniques**. It automates the process of discovering the real origin IP behind a WAF/CDN by combining multiple discovery methods and verifying candidates through HTML similarity comparison.

Unwaf is automating the steps I explained on this LinkedIn Post: [Passive WAF bypassing](https://www.linkedin.com/posts/martinmarting_bugbounty-bugbountytips-pentesting-activity-7217385665729093632-oZEP)

## What's new in v2.0

- **4 new free discovery methods** (MX records, subdomain probing, Certificate Transparency, WAF detection)
- **Censys SSL certificate search** (optional, API key)
- **WAF fingerprinting** — identifies Cloudflare, Akamai, AWS CloudFront, Fastly, Sucuri, Imperva, and more
- **Favicon hashing** — generates MD5/SHA256 hashes for manual Shodan/Censys lookups
- **Host-header injection** — tests candidate IPs with the original Host header (catches vhosts)
- **WAF/CDN IP filtering** — automatically discards IPs belonging to known CDN ranges
- **Extended port scanning** — checks ports 80, 443, 8080, 8443, 8000, 8008, 8888, 9443
- **Configurable threshold and concurrency** (`-t`, `-w` flags)
- **Verbose mode** (`-v`) for debugging
- **Updated dependencies** (Go 1.23, latest library versions)
- **Improved output** with color-coded sections and actionable `curl` verification commands

## Discovery methods

| Method | Type | Description |
|---|---|---|
| SPF records | Free | Extracts IPs from `ip4:`/`ip6:` SPF mechanisms |
| MX records | Free | Resolves mail server hostnames (skips Google/Microsoft/etc.) |
| Subdomain probing | Free | Resolves 30+ common subdomains (mail, dev, staging, cpanel, origin, etc.) |
| Certificate Transparency | Free | Queries crt.sh for all subdomains, resolves to non-WAF IPs |
| WAF detection | Free | Fingerprints the WAF vendor via HTTP headers |
| Favicon hashing | Free | Generates hashes for manual Shodan/Censys favicon search |
| ViewDNS history | API key | Historical DNS A records |
| SecurityTrails history | API key | Historical DNS A records |
| Censys SSL search | API key | Finds hosts presenting SSL certs matching the domain |

## Installation

```sh
go install github.com/mmarting/unwaf@latest
```

## Usage

```sh
unwaf -h
```

## Options

    -d, --domain        The domain to check (required)
    -s, --source        The source HTML file to compare (optional)
    -c, --config        The config file path (optional, default: $HOME/.unwaf.conf)
    -t, --threshold     Similarity threshold percentage (optional, default: 60)
    -w, --workers       Number of concurrent workers (optional, default: 50)
    -v, --verbose       Enable verbose output
    -h, --help          Display help information

## Examples

Check a domain (free methods only, no API keys needed):

```sh
unwaf -d example.com
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

## Configuration

On first run, Unwaf creates `$HOME/.unwaf.conf` with this template:

```ini
# Unwaf config file — API keys for optional discovery methods
# Free methods (SPF, MX, crt.sh, subdomains) work without any keys.

# ViewDNS.info — DNS history (https://viewdns.info/api/)
viewdns=""

# SecurityTrails — DNS history (https://securitytrails.com/corp/api)
securitytrails=""

# Censys — SSL certificate search (https://search.censys.io/account/api)
censys_id=""
censys_secret=""
```

## How it works

1. **WAF Detection** — Fingerprints the WAF via HTTP response headers
2. **Favicon Hashing** — Fetches favicon.ico and generates hashes for external search
3. **IP Discovery** — Runs all enabled methods to collect candidate origin IPs
4. **WAF/CDN Filtering** — Discards IPs belonging to known Cloudflare, Akamai, CloudFront, Fastly, etc. ranges
5. **Port Scanning** — Checks candidates on 8 common web ports concurrently
6. **HTML Comparison** — Fetches HTML from each web server (direct + Host header) and compares with the reference using diff-based similarity
7. **Results** — Reports matches above the threshold with a ready-to-use `curl` command

## Author

**Martín Martín**

[My website](https://mmartin.me/) · [LinkedIn](https://www.linkedin.com/in/martinmarting/)

## License

`unwaf` is distributed under GPL v3 License.
