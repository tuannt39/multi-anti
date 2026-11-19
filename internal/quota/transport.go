package quota

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"runtime"
	"time"
)

const (
	// DefaultDailyEndpoint is the primary CloudCode PA endpoint used by agy.
	DefaultDailyEndpoint = "https://daily-cloudcode-pa.googleapis.com"
	// DefaultProdEndpoint is the fallback CloudCode PA endpoint.
	DefaultProdEndpoint = "https://cloudcode-pa.googleapis.com"
)

// DefaultEndpoints lists CloudCode PA base URLs in fallback order.
var DefaultEndpoints = []string{
	DefaultDailyEndpoint,
	DefaultProdEndpoint,
}

// DefaultUserAgent returns the agy 1.5.10 CloudCode client User-Agent string.
func DefaultUserAgent() string {
	return fmt.Sprintf(
		"antigravity/cli/1.5.10 (aidev_client; os_type=%s; arch=%s; auth_method=consumer)",
		runtime.GOOS,
		runtime.GOARCH,
	)
}

// NewCloudCodeHTTPClient creates an HTTP/1.1-forced client for CloudCode PA requests.
func NewCloudCodeHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: false,
		// Non-nil empty map disables HTTP/2 ALPN upgrade in Go's net/http transport.
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}
