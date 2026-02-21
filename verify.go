package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sergi/go-diff/diffmatchpatch"
)

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
// SSL Certificate Fingerprint Matching
// ---------------------------------------------------------------------------

// fetchTLSCert connects to host:port with the given SNI and returns the peer cert.
func fetchTLSCert(ctx context.Context, host, sni string, port int) (*x509.Certificate, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned")
	}
	return certs[0], nil
}

// compareTLSCerts compares the TLS certificate of the candidate IP against the domain's cert.
// Returns a 0-1 similarity score: 50% serial match, 25% CN match, 25% SAN overlap.
func compareTLSCerts(ctx context.Context, domain, candidateIP string, port int) float64 {
	if ctx.Err() != nil {
		return 0
	}

	// Fetch reference cert from domain
	refCert, err := fetchTLSCert(ctx, domain, domain, port)
	if err != nil {
		return 0
	}

	// Fetch candidate cert
	candCert, err := fetchTLSCert(ctx, candidateIP, domain, port)
	if err != nil {
		return 0
	}

	score := 0.0

	// 50%: Serial number match
	if refCert.SerialNumber != nil && candCert.SerialNumber != nil {
		if refCert.SerialNumber.Cmp(candCert.SerialNumber) == 0 {
			score += 0.50
		}
	}

	// 25%: Subject CN match
	if refCert.Subject.CommonName != "" && refCert.Subject.CommonName == candCert.Subject.CommonName {
		score += 0.25
	}

	// 25%: SAN overlap
	refSANs := make(map[string]bool)
	for _, san := range refCert.DNSNames {
		refSANs[strings.ToLower(san)] = true
	}
	if len(refSANs) > 0 {
		overlap := 0
		for _, san := range candCert.DNSNames {
			if refSANs[strings.ToLower(san)] {
				overlap++
			}
		}
		if overlap > 0 {
			score += 0.25 * float64(overlap) / float64(len(refSANs))
		}
	}

	return score
}

// ---------------------------------------------------------------------------
// HTTP Response Header Comparison
// ---------------------------------------------------------------------------

// compareResponseHeaders compares specific response headers between domain and candidate.
// Returns 0-1 similarity score.
func compareResponseHeaders(origHeaders, candHeaders http.Header) float64 {
	if origHeaders == nil || candHeaders == nil {
		return 0
	}

	headersToCompare := []string{"Server", "X-Powered-By"}
	matches := 0
	total := 0

	for _, h := range headersToCompare {
		origVal := origHeaders.Get(h)
		candVal := candHeaders.Get(h)
		if origVal != "" || candVal != "" {
			total++
			if origVal == candVal {
				matches++
			}
		}
	}

	// Compare Set-Cookie names
	origCookies := extractCookieNames(origHeaders.Values("Set-Cookie"))
	candCookies := extractCookieNames(candHeaders.Values("Set-Cookie"))
	if len(origCookies) > 0 || len(candCookies) > 0 {
		total++
		overlap := 0
		for name := range origCookies {
			if candCookies[name] {
				overlap++
			}
		}
		if len(origCookies) > 0 && overlap > 0 {
			matches++
		}
	}

	if total == 0 {
		return 0
	}
	return float64(matches) / float64(total)
}

func extractCookieNames(cookies []string) map[string]bool {
	names := make(map[string]bool)
	for _, c := range cookies {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) > 0 {
			name := strings.TrimSpace(parts[0])
			if name != "" {
				names[name] = true
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// Status Code Matching
// ---------------------------------------------------------------------------

// statusCodeAdjustment returns a score adjustment based on status code comparison.
func statusCodeAdjustment(origStatus, candStatus int) float64 {
	if origStatus == candStatus {
		return 0.05 // 5% boost for exact match
	}
	// Penalty for error vs success mismatch
	origIsSuccess := origStatus >= 200 && origStatus < 400
	candIsSuccess := candStatus >= 200 && candStatus < 400
	if origIsSuccess != candIsSuccess {
		return -0.20 // 20% penalty
	}
	return 0
}

// ---------------------------------------------------------------------------
// Overall Score Calculation
// ---------------------------------------------------------------------------

// calculateOverallScore combines HTML similarity, cert match, and header match.
// Formula: 60% HTML + 25% cert + 15% headers + status code adjustment
func calculateOverallScore(htmlSimilarity, certMatch, headerMatch float64, origStatus, candStatus int) float64 {
	score := 0.60*htmlSimilarity + 0.25*certMatch + 0.15*headerMatch
	score += statusCodeAdjustment(origStatus, candStatus)
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score
}

// isTLSPort returns true if the port typically uses TLS.
func isTLSPort(port int) bool {
	return port == 443 || port == 8443 || port == 9443
}
