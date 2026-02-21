package main

// BypassResult holds a verified WAF bypass candidate.
type BypassResult struct {
	IP          string  `json:"ip"`
	Port        int     `json:"port"`
	Similarity  float64 `json:"similarity"`
	Method      string  `json:"method"` // "direct" or "host-header"
	StatusCode  int     `json:"status_code,omitempty"`
	CertMatch   float64 `json:"cert_match,omitempty"`
	HeaderMatch float64 `json:"header_match,omitempty"`
	OverallScore float64 `json:"overall_score"`
	Source      string  `json:"source"`
	ASN         string  `json:"asn,omitempty"`
	ASNOrg      string  `json:"asn_org,omitempty"`
}

type webServerResult struct {
	IP    string
	Ports []int
}

// Config holds API keys loaded from the config file.
type Config struct {
	ViewDNS        string `json:"viewdns"`
	SecurityTrails string `json:"securitytrails"`
	CensysToken    string `json:"censys_token"`
	CensysOrgID    string `json:"censys_org_id"`
	OTXAPIKey      string `json:"otx_api_key"`
	ShodanAPIKey   string `json:"shodan_api_key"`
	DNSDBAPIKey    string `json:"dnsdb_api_key"`
}

// JSONOutput is the top-level structure for --json output.
type JSONOutput struct {
	Version       string          `json:"version"`
	Timestamp     string          `json:"timestamp"`
	Domain        string          `json:"domain"`
	WAFDetected   bool            `json:"waf_detected"`
	WAFName       string          `json:"waf_name"`
	CurrentIPs    []string        `json:"current_ips"`
	FaviconMD5    string          `json:"favicon_md5,omitempty"`
	FaviconSHA256 string          `json:"favicon_sha256,omitempty"`
	FaviconMMH3   int32           `json:"favicon_mmh3,omitempty"`
	CandidateIPs  int             `json:"candidate_ips"`
	WebServers    int             `json:"web_servers"`
	Bypasses      []BypassResult  `json:"bypasses"`
	Sources       map[string]int  `json:"sources"`
}

// CrtShEntry represents a crt.sh JSON response entry.
type CrtShEntry struct {
	NameValue string `json:"name_value"`
}
