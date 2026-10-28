package netutil_test

import (
	"testing"

	"github.com/Yoosuf01/mcpguard/shield/internal/netutil"
)

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in, want string
		isIP     bool
	}{
		{"127.0.0.1", "127.0.0.1", true},
		{"169.254.169.254", "169.254.169.254", true},
		{"10.0.0.1", "10.0.0.1", true},
		// Decimal integer
		{"2130706433", "127.0.0.1", true},
		{"2852039166", "169.254.169.254", true},
		// Hexadecimal
		{"0x7f000001", "127.0.0.1", true},
		{"0x7F000001", "127.0.0.1", true},
		// Octal octets
		{"0177.0.0.1", "127.0.0.1", true},
		// Short form
		{"127.1", "127.0.0.1", true},
		// Trailing dot
		{"127.0.0.1.", "127.0.0.1", true},
		// IPv6 loopback
		{"::1", "::1", true},
		// IPv6-mapped IPv4
		{"::ffff:127.0.0.1", "127.0.0.1", true},
		// Hostnames must NOT be treated as IPs
		{"example.com", "example.com", false},
		{"metadata.google.internal", "metadata.google.internal", false},
		{"localhost", "localhost", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, isIP := netutil.NormalizeHost(tc.in)
			if isIP != tc.isIP {
				t.Errorf("isIP=%v want %v (got %q)", isIP, tc.isIP, got)
				return
			}
			if tc.isIP && got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}
