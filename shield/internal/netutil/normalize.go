// Package netutil provides IP/hostname normalization to defeat SSRF bypasses.
//
// Non-canonical private-IP encodings caught:
//
//	decimal    2130706433       → 127.0.0.1
//	hex        0x7f000001       → 127.0.0.1
//	octal      0177.0.0.1       → 127.0.0.1
//	short      127.1            → 127.0.0.1
//	trailing   127.0.0.1.       → 127.0.0.1
//	IPv6-map   ::ffff:127.0.0.1 → 127.0.0.1
package netutil

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// NormalizeHost returns (canonical, isIP).
// isIP is true when the input represents any IP address (in any encoding).
func NormalizeHost(host string) (string, bool) {
	// Strip trailing dot (FQDN).
	host = strings.TrimRight(host, ".")
	// URL-decode (%2E, %3A …).
	if dec, err := url.PathUnescape(host); err == nil {
		host = dec
	}
	// Strip IPv6 brackets.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	// IPv6-mapped IPv4: ::ffff:a.b.c.d
	if strings.HasPrefix(strings.ToLower(host), "::ffff:") {
		rest := host[7:]
		if ip := net.ParseIP(rest); ip != nil {
			return ip.String(), true
		}
		if n, ok := normalizeIPv4(rest); ok {
			return n, true
		}
	}
	// Pure IPv6.
	if strings.Contains(host, ":") {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String(), true
		}
		return "", false
	}
	// IPv4 in any encoding.
	if n, ok := normalizeIPv4(host); ok {
		return n, true
	}
	return host, false
}

func normalizeIPv4(s string) (string, bool) {
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), true
		}
	}
	parts := strings.Split(s, ".")
	switch len(parts) {
	case 1:
		n, e := parseOctet(parts[0], 32)
		if e != nil {
			return "", false
		}
		return fmt.Sprintf("%d.%d.%d.%d", (n>>24)&0xff, (n>>16)&0xff, (n>>8)&0xff, n&0xff), true
	case 2:
		a, e1 := parseOctet(parts[0], 8)
		b, e2 := parseOctet(parts[1], 24)
		if e1 != nil || e2 != nil {
			return "", false
		}
		return fmt.Sprintf("%d.%d.%d.%d", a, (b>>16)&0xff, (b>>8)&0xff, b&0xff), true
	case 3:
		a, e1 := parseOctet(parts[0], 8)
		b, e2 := parseOctet(parts[1], 8)
		c, e3 := parseOctet(parts[2], 16)
		if e1 != nil || e2 != nil || e3 != nil {
			return "", false
		}
		return fmt.Sprintf("%d.%d.%d.%d", a, b, (c>>8)&0xff, c&0xff), true
	case 4:
		var o [4]uint64
		for i, p := range parts {
			v, e := parseOctet(p, 8)
			if e != nil {
				return "", false
			}
			o[i] = v
		}
		return fmt.Sprintf("%d.%d.%d.%d", o[0], o[1], o[2], o[3]), true
	}
	return "", false
}

func parseOctet(s string, bits int) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty octet")
	}
	var v uint64
	var err error
	switch {
	case strings.HasPrefix(strings.ToLower(s), "0x"):
		v, err = strconv.ParseUint(s[2:], 16, 64)
	case len(s) > 1 && s[0] == '0':
		v, err = strconv.ParseUint(s[1:], 8, 64)
	default:
		v, err = strconv.ParseUint(s, 10, 64)
	}
	if err != nil {
		return 0, err
	}
	if bits < 64 && v >= (uint64(1)<<uint(bits)) {
		return 0, fmt.Errorf("value %d exceeds %d bits", v, bits)
	}
	return v, nil
}
