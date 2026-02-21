package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

var (
	appHTTPClient *http.Client
	rateLimiter   *rate.Limiter
)

// browserTransport routes HTTPS through HTTP/2 (with Chrome TLS fingerprint)
// and falls back to HTTP/1.1 when h2 is unavailable. Plain HTTP uses h1.
type browserTransport struct {
	h2 *http2.Transport
	h1 *http.Transport
}

func (t *browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		resp, err := t.h2.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		// h2 failed (server may not support it), fall back to h1
		return t.h1.RoundTrip(req)
	}
	return t.h1.RoundTrip(req)
}

// utlsDialTLS returns a dial function that establishes a TCP connection and
// performs a TLS handshake using uTLS with Chrome's fingerprint.
// When forceH1 is true, only http/1.1 is offered in ALPN (used for h1 fallback).
func utlsDialTLS(tcpDial func(ctx context.Context, network, addr string) (net.Conn, error), forceH1 bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		tcpConn, err := tcpDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		config := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		}
		if forceH1 {
			config.NextProtos = []string{"http/1.1"}
		}

		tlsConn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}
}

func newHTTPClient(timeout time.Duration, proxyURL string) *http.Client {
	baseDialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	// Default TCP dial function; overridden below for SOCKS5 proxies.
	tcpDial := baseDialer.DialContext
	var useHTTPProxy bool

	h1Transport := &http.Transport{
		// Fallback TLS config for proxied HTTPS connections
		// (DialTLSContext is only used for non-proxied connections).
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}

	if proxyURL != "" {
		parsedURL, err := url.Parse(proxyURL)
		if err == nil {
			if parsedURL.Scheme == "socks5" {
				socksDialer, err := proxy.FromURL(parsedURL, proxy.Direct)
				if err == nil {
					tcpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
						return socksDialer.Dial(network, addr)
					}
				}
			} else {
				useHTTPProxy = true
				h1Transport.Proxy = http.ProxyURL(parsedURL)
			}
		}
	}

	h1Transport.DialContext = tcpDial
	h1Transport.DialTLSContext = utlsDialTLS(tcpDial, true) // h1-only ALPN for fallback

	var transport http.RoundTripper
	if useHTTPProxy {
		// HTTP proxy: DialTLSContext only applies to non-proxied requests.
		// Proxied HTTPS uses CONNECT tunnel + standard TLS (no utls).
		transport = h1Transport
	} else {
		// Use uTLS with Chrome fingerprint for both h2 and h1.
		// h2 is tried first (full Chrome ALPN including h2); if the server
		// doesn't support h2, we fall back to h1 with http/1.1-only ALPN.
		h2DialTLS := utlsDialTLS(tcpDial, false)
		h2Transport := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return h2DialTLS(ctx, network, addr)
			},
		}
		transport = &browserTransport{h2: h2Transport, h1: h1Transport}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func waitRateLimit(ctx context.Context) error {
	if rateLimiter != nil {
		return rateLimiter.Wait(ctx)
	}
	return nil
}

// setBrowserHeaders sets request headers that mimic a real Chrome browser.
// WAFs often check for Sec-Fetch-* and Sec-Ch-Ua headers to detect bots.
func setBrowserHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="131", "Not_A Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Cache-Control", "max-age=0")
}

// doWithRetry executes an HTTP request with retry on 429/5xx.
func doWithRetry(ctx context.Context, client *http.Client, req *http.Request, maxRetries int) (*http.Response, error) {
	var resp *http.Response
	var err error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err := waitRateLimit(ctx); err != nil {
			return nil, err
		}

		// Clone the request for retry
		clonedReq := req.Clone(ctx)
		resp, err = client.Do(clonedReq)
		if err != nil {
			if attempt < maxRetries {
				backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				continue
			}
			return nil, err
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			if attempt < maxRetries {
				resp.Body.Close()
				backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				continue
			}
		}
		return resp, nil
	}
	return resp, err
}

func fetchHTML(ctx context.Context, urlStr string) (string, int, error) {
	return fetchHTMLWithHost(ctx, urlStr, "")
}

func fetchHTMLWithHost(ctx context.Context, urlStr, host string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return "", 0, err
	}

	if host != "" {
		req.Host = host
	}

	setBrowserHeaders(req)

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
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

// fetchHTMLWithHeaders fetches HTML and also returns response headers.
func fetchHTMLWithHeaders(ctx context.Context, urlStr, host string) (string, int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return "", 0, nil, err
	}

	if host != "" {
		req.Host = host
	}

	setBrowserHeaders(req)

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
	if err != nil {
		return "", 0, nil, err
	}
	defer resp.Body.Close()

	headers := resp.Header.Clone()

	if resp.StatusCode >= 500 {
		return "", resp.StatusCode, headers, fmt.Errorf("server error: %d", resp.StatusCode)
	}

	reader, err := charset.NewReader(resp.Body, resp.Header.Get("Content-Type"))
	if err != nil {
		return "", resp.StatusCode, headers, err
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
	return b.String(), resp.StatusCode, headers, nil
}

func fetchRawBytes(ctx context.Context, urlStr string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
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
