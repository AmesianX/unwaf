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

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

var (
	appHTTPClient *http.Client
	rateLimiter   *rate.Limiter
)

func newHTTPClient(timeout time.Duration, proxyURL string) *http.Client {
	transport := &http.Transport{
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
				dialer, err := proxy.FromURL(parsedURL, proxy.Direct)
				if err == nil {
					transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
						return dialer.Dial(network, addr)
					}
				}
			} else {
				transport.Proxy = http.ProxyURL(parsedURL)
			}
		}
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

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")

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

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")

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
