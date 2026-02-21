package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// writeJSONOutput marshals JSONOutput and writes to stdout or a file.
func writeJSONOutput(output *JSONOutput, outputFile string) error {
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	if outputFile != "" {
		return os.WriteFile(outputFile, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

// writeTextOutput writes bypass IPs to a file (one per line).
func writeTextOutput(results []BypassResult, outputFile string) error {
	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	printed := make(map[string]bool)
	for _, r := range results {
		if !printed[r.IP] {
			fmt.Fprintln(f, r.IP)
			printed[r.IP] = true
		}
	}
	return nil
}

// lookupASN queries ip-api.com for ASN info (free, 45 req/min).
func lookupASN(ctx context.Context, ip string, client *http.Client) (string, string) {
	urlStr := fmt.Sprintf("http://ip-api.com/json/%s?fields=as,org", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return "", ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", ""
	}

	var result struct {
		AS  string `json:"as"`
		Org string `json:"org"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", ""
	}
	return result.AS, result.Org
}

// lookupASNBatch looks up ASN for a list of unique IPs with rate limiting.
func lookupASNBatch(ctx context.Context, results []BypassResult, client *http.Client) {
	seen := make(map[string]int) // IP -> index of first occurrence
	for i := range results {
		if _, ok := seen[results[i].IP]; !ok {
			seen[results[i].IP] = i
		}
	}

	// Cache results
	cache := make(map[string][2]string)
	for ip := range seen {
		if ctx.Err() != nil {
			break
		}
		asn, org := lookupASN(ctx, ip, client)
		cache[ip] = [2]string{asn, org}
		// Respect rate limit: ~45 req/min => sleep ~1.5s between requests
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-ctx.Done():
			return
		}
	}

	// Apply to all results
	for i := range results {
		if info, ok := cache[results[i].IP]; ok {
			results[i].ASN = info[0]
			results[i].ASNOrg = info[1]
		}
	}
}
