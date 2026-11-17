package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPinnedProxy_AllowedEgress(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream response ok"))
	}))
	defer upstream.Close()

	uURL, _ := url.Parse(upstream.URL)
	upHost, upPort, _ := net.SplitHostPort(uURL.Host)
	upIP := net.ParseIP(upHost)

	proxy := NewPinnedProxy(PinnedProxyOptions{
		Policy: EgressPolicy{
			BlockPrivateNetworks: false, // Allow local loopback for upstream test server
			AllowDomains:         []string{"api.example.com"},
		},
		LookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "api.example.com" {
				return []net.IP{upIP}, nil
			}
			return nil, fmt.Errorf("unknown host")
		},
	})

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(t, proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://api.example.com:%s/data", upPort), nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "upstream response ok" {
		t.Errorf("expected 'upstream response ok', got %q", string(body))
	}
}

func TestPinnedProxy_SSRFMetadataBlocked(t *testing.T) {
	proxy := NewPinnedProxy(PinnedProxyOptions{
		Policy: EgressPolicy{
			BlockPrivateNetworks: true,
		},
		LookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "metadata.attacker.com" {
				return []net.IP{net.ParseIP("169.254.169.254")}, nil
			}
			return nil, fmt.Errorf("unknown host")
		},
	})

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(t, proxyServer.URL)),
		},
	}

	// 1. Domain resolving to metadata IP
	req1, _ := http.NewRequest(http.MethodGet, "http://metadata.attacker.com/latest/meta-data/", nil)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("unexpected client error: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for metadata domain, got %d", resp1.StatusCode)
	}

	// 2. Direct metadata IP literal
	req2, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("unexpected client error: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for metadata IP literal, got %d", resp2.StatusCode)
	}
}

func TestPinnedProxy_PrivateNetworkBlocked(t *testing.T) {
	proxy := NewPinnedProxy(PinnedProxyOptions{
		Policy: EgressPolicy{
			BlockPrivateNetworks: true,
		},
		LookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "internal.company.corp" {
				return []net.IP{net.ParseIP("10.0.0.5")}, nil
			}
			return nil, fmt.Errorf("unknown host")
		},
	})

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(t, proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest(http.MethodGet, "http://internal.company.corp/admin", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected client error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for private network, got %d", resp.StatusCode)
	}
}

func TestPinnedProxy_DomainAllowAndDenyLists(t *testing.T) {
	proxy := NewPinnedProxy(PinnedProxyOptions{
		Policy: EgressPolicy{
			BlockPrivateNetworks: false,
			AllowDomains:         []string{"*.zoho.com", "docs.python.org"},
			DenyDomains:          []string{"evil.zoho.com"},
		},
		LookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.1")}, nil
		},
	})

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(t, proxyServer.URL)),
		},
	}

	// 1. Deny domain (explicit deny wins over wildcard allow)
	reqDeny, _ := http.NewRequest(http.MethodGet, "http://evil.zoho.com/leak", nil)
	respDeny, err := client.Do(reqDeny)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer respDeny.Body.Close()
	if respDeny.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for denied domain, got %d", respDeny.StatusCode)
	}

	// 2. Unlisted domain (not on allowlist)
	reqUnlisted, _ := http.NewRequest(http.MethodGet, "http://attacker.example.org/", nil)
	respUnlisted, err := client.Do(reqUnlisted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer respUnlisted.Body.Close()
	if respUnlisted.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for unlisted domain, got %d", respUnlisted.StatusCode)
	}
}

func TestPinnedProxy_DNSRebindingDefeat(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("legit server"))
	}))
	defer upstream.Close()

	uURL, _ := url.Parse(upstream.URL)
	upHost, upPort, _ := net.SplitHostPort(uURL.Host)
	upIP := net.ParseIP(upHost)

	// Resolver returns legit server IP on first call, then rebinds to 169.254.169.254
	var calls int32
	mockResolver := func(ctx context.Context, host string) ([]net.IP, error) {
		count := atomic.AddInt32(&calls, 1)
		if count == 1 {
			return []net.IP{upIP}, nil
		}
		// Subsequent rebinding attempt
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}

	proxy := NewPinnedProxy(PinnedProxyOptions{
		Policy: EgressPolicy{
			BlockPrivateNetworks: false,
			AllowDomains:         []string{"rebind.attacker.com"},
		},
		LookupIP: mockResolver,
	})

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(t, proxyServer.URL)),
		},
	}

	// First request succeeds through the pinned legitimate IP
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://rebind.attacker.com:%s/ping", upPort), nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "legit server" {
		t.Errorf("expected 'legit server', got %q", string(body))
	}
}

func TestPinnedProxy_ConnectTunneling(t *testing.T) {
	// Simple TCP echo server to simulate HTTPS target
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start tcp listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // Echo
			}(conn)
		}
	}()

	tcpAddr := listener.Addr().String()
	tcpHost, tcpPort, _ := net.SplitHostPort(tcpAddr)
	tcpIP := net.ParseIP(tcpHost)

	proxy := NewPinnedProxy(PinnedProxyOptions{
		Policy: EgressPolicy{
			BlockPrivateNetworks: false,
			AllowDomains:         []string{"secure.target.com"},
		},
		LookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "secure.target.com" {
				return []net.IP{tcpIP}, nil
			}
			return nil, fmt.Errorf("unknown host")
		},
	})

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	// Dial proxy and send CONNECT request
	proxyConn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer proxyConn.Close()

	connectReq := fmt.Sprintf("CONNECT secure.target.com:%s HTTP/1.1\r\nHost: secure.target.com:%s\r\n\r\n", tcpPort, tcpPort)
	_, err = proxyConn.Write([]byte(connectReq))
	if err != nil {
		t.Fatalf("failed to send CONNECT: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := proxyConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read CONNECT response: %v", err)
	}
	respStr := string(buf[:n])
	if !strings.Contains(respStr, "200 Connection Established") {
		t.Fatalf("expected 200 Connection Established, got: %s", respStr)
	}

	// Test tunneled communication over the pinned TCP socket
	testMsg := "hello through pinned tunnel"
	_, _ = proxyConn.Write([]byte(testMsg))
	n, _ = proxyConn.Read(buf)
	if string(buf[:n]) != testMsg {
		t.Errorf("expected echo %q, got %q", testMsg, string(buf[:n]))
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse url %q: %v", raw, err)
	}
	return u
}
