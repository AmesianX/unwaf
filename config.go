package main

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

var apiKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func createDefaultConfig(configPath string) error {
	defaultConfig := `# Unwaf config file — API keys for optional discovery methods
# Free methods (SPF, MX, crt.sh, subdomains, OTX, RapidDNS, HackerTarget, Wayback) work without any keys.

# ViewDNS.info — DNS history (https://viewdns.info/api/)
viewdns=""

# SecurityTrails — DNS history (https://securitytrails.com/corp/api)
securitytrails=""

# Censys — SSL certificate search (requires a PAID license)
#   API access is only available with a paid Censys account that has an Organization ID.
#   Free accounts cannot use the API — see https://docs.censys.com/reference/get-started
#   Get your PAT from: https://app.censys.io/account/api
censys_token=""
#   Org ID (required) — visible in your Censys Platform URL or Settings > Organization
censys_org_id=""

# AlienVault OTX — passive DNS (optional, raises rate limits)
#   Get your key from: https://otx.alienvault.com/api
otx_api_key=""

# Shodan — host search by SSL cert, hostname, favicon hash
#   Get your key from: https://account.shodan.io/
shodan_api_key=""

# DNSDB/Farsight — historical DNS records
#   Get your key from: https://www.farsightsecurity.com/solutions/dnsdb/
dnsdb_api_key=""
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
		case "censys_token":
			config.CensysToken = value
		case "censys_org_id":
			config.CensysOrgID = value
		case "otx_api_key":
			config.OTXAPIKey = value
		case "shodan_api_key":
			config.ShodanAPIKey = value
		case "dnsdb_api_key":
			config.DNSDBAPIKey = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return config, nil
}
