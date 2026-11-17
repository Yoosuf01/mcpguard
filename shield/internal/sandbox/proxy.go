package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/netutil"
)

// EgressPolicy defines the outbound network egress restrictions.
type EgressPolicy struct {
	BlockPrivateNetworks bool     `json:"block_private_networks"`
	AllowDomains         []string `json:"allow_domains,omitempty"`
	DenyDomains          []string `json:"deny_domains,omitempty"`
}

// PinnedProxyOptions configures the DNS-pinned forward proxy.
type PinnedProxyOptions struct {
	Policy   EgressPolicy
	Timeout  time.Duration
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
}

// PinnedProxy is an HTTP/HTTPS forward proxy that resolves DNS once,
// validates the resolved IP against egress security rules, and pins the
// outbound TCP connection to that IP, closing DNS-rebinding attacks.
type PinnedProxy struct {
	policy   EgressPolicy
	timeout  time.Duration
	lookupIP func(ctx context.Context, host string) ([]net.IP, error)
}

// NewPinnedProxy constructs a DNS-pinned forward proxy.
func NewPinnedProxy(opts PinnedProxyOptions) *PinnedProxy {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	lookup := opts.LookupIP
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			ips := make([]net.IP, len(addrs))
			for i, a := range addrs {
				ips[i] = a.IP
			}
			return ips, nil
		}
	}

	return &PinnedProxy{
		policy:   opts.Policy,
		timeout:  opts.Timeout,
		lookupIP: lookup,
	}
}

func isRestrictedIP(ip net.IP, allowLoopback bool) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if !allowLoopback && (ip.IsLoopback() || ip.Equal(net.IPv4(127, 0, 0, 1))) {
		return true
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// Cloud metadata IP literals (AWS / Azure / GCP)
	if len(ip) == 4 && ip[0] == 169 && ip[1] == 254 {
		return true
	}
	return false
}

func domainMatches(host string, patterns []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSuffix(p, "."))
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:]
			if strings.HasSuffix(host, suffix) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

// resolveAndPin resolves the host once, validates the IP, and returns the pinned IP:port target.
func (p *PinnedProxy) resolveAndPin(ctx context.Context, host, port string) (string, error) {
	// 1. Check if input is a raw or non-canonically encoded IP address.
	canonical, isIP := netutil.NormalizeHost(host)
	if isIP {
		ip := net.ParseIP(canonical)
		if ip == nil {
			return "", fmt.Errorf("invalid IP %q", host)
		}
		if p.policy.BlockPrivateNetworks && isRestrictedIP(ip, false) {
			return "", fmt.Errorf("blocked request to internal address %s", ip)
		}
		if len(p.policy.AllowDomains) > 0 && !domainMatches(canonical, p.policy.AllowDomains) {
			return "", fmt.Errorf("ip %s is not on the egress allowlist", canonical)
		}
		return net.JoinHostPort(canonical, port), nil
	}

	// 2. Validate domain against allow/deny lists.
	normalizedHost := strings.ToLower(strings.TrimSuffix(host, "."))
	if domainMatches(normalizedHost, p.policy.DenyDomains) {
		return "", fmt.Errorf("domain %s is denied", host)
	}
	if len(p.policy.AllowDomains) > 0 && !domainMatches(normalizedHost, p.policy.AllowDomains) {
		return "", fmt.Errorf("domain %s is not on the egress allowlist", host)
	}

	// 3. One-shot DNS resolution.
	ips, err := p.lookupIP(ctx, normalizedHost)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("failed to resolve host %q: %w", host, err)
	}

	// 4. Validate all returned IPs against egress restrictions.
	var pinnedIP net.IP
	for _, ip := range ips {
		if p.policy.BlockPrivateNetworks && isRestrictedIP(ip, false) {
			return "", fmt.Errorf("blocked request to internal address %s (resolved from %s)", ip, host)
		}
		if pinnedIP == nil {
			pinnedIP = ip
		}
	}

	if pinnedIP == nil {
		return "", fmt.Errorf("no usable IP resolved for %s", host)
	}

	// 5. Pin connection to the single verified IP.
	return net.JoinHostPort(pinnedIP.String(), port), nil
}

func (p *PinnedProxy) dialPinned(ctx context.Context, target string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: p.timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip != nil && p.policy.BlockPrivateNetworks && isRestrictedIP(ip, false) {
				return fmt.Errorf("socket blocked: prohibited IP %s", ip)
			}
			return nil
		},
	}
	return d.DialContext(ctx, "tcp", target)
}

func (p *PinnedProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *PinnedProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "443"
	}

	pinnedTarget, err := p.resolveAndPin(r.Context(), host, port)
	if err != nil {
		http.Error(w, fmt.Sprintf("Blocked by Sentinel egress policy: %v", err), http.StatusForbidden)
		return
	}

	targetConn, err := p.dialPinned(r.Context(), pinnedTarget)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to connect to %s: %v", pinnedTarget, err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Notify client that TLS tunnel is ready
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional tunnel splicing
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()

	<-done
}

func (p *PinnedProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if host == "" {
		host = r.Host
		if strings.Contains(host, ":") {
			host, _, _ = net.SplitHostPort(host)
		}
	}
	port := r.URL.Port()
	if port == "" {
		if r.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	pinnedTarget, err := p.resolveAndPin(r.Context(), host, port)
	if err != nil {
		http.Error(w, fmt.Sprintf("Blocked by Sentinel egress policy: %v", err), http.StatusForbidden)
		return
	}

	// Create dedicated transport that dials the pinned IP directly
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return p.dialPinned(ctx, pinnedTarget)
		},
		ResponseHeaderTimeout: p.timeout,
		DisableKeepAlives:     true,
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	outReq.Header = r.Header.Clone()
	outReq.Header.Del("Proxy-Connection")

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("egress transport error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
