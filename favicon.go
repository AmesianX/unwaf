package main

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/spaolacci/murmur3"
)

// FaviconHashes holds all hash types for a favicon.
type FaviconHashes struct {
	MD5    string
	SHA256 string
	MMH3   int32
}

// getFaviconHashes fetches the favicon and computes MD5, SHA256, and MMH3 hashes.
func getFaviconHashes(ctx context.Context, domain string) *FaviconHashes {
	urls := []string{
		"https://" + domain + "/favicon.ico",
		"http://" + domain + "/favicon.ico",
	}

	for _, u := range urls {
		if ctx.Err() != nil {
			return nil
		}
		body, statusCode, err := fetchRawBytes(ctx, u)
		if err != nil || statusCode != 200 || len(body) == 0 {
			continue
		}

		md5Hash := fmt.Sprintf("%x", md5.Sum(body))
		sha256Hash := fmt.Sprintf("%x", sha256.Sum256(body))
		mmh3Hash := computeMMH3(body)

		return &FaviconHashes{
			MD5:    md5Hash,
			SHA256: sha256Hash,
			MMH3:   mmh3Hash,
		}
	}
	return nil
}

// computeMMH3 calculates the MurmurHash3 used by Shodan for favicon searches.
// It base64-encodes the raw body (with line breaks every 76 chars) then hashes.
func computeMMH3(body []byte) int32 {
	encoded := base64.StdEncoding.EncodeToString(body)
	// Insert newlines every 76 characters (MIME-style)
	var b strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		b.WriteString(encoded[i:end])
		b.WriteByte('\n')
	}
	return int32(murmur3.Sum32([]byte(b.String())))
}
