package edge

import (
	"net/netip"
	"testing"
)

func TestResolve(t *testing.T) {
	trusted := ParseTrusted("172.18.0.2, 10.0.0.0/8, fd00::/8")

	tests := []struct {
		name       string
		remoteAddr string
		xff        []string
		want       string
	}{
		{"trusted peer, one hop", "172.18.0.2:4000", []string{"203.0.113.7"}, "203.0.113.7"},
		{"trusted peer, rightmost untrusted wins", "172.18.0.2:4000", []string{"1.1.1.1, 203.0.113.7, 10.1.2.3"}, "203.0.113.7"},
		{"trusted peer, hops in several headers", "10.9.9.9:1", []string{"1.1.1.1", "203.0.113.7, 10.0.0.5"}, "203.0.113.7"},
		{"trusted peer, spoofed value is left of the real one", "172.18.0.2:4000", []string{"6.6.6.6, 203.0.113.7"}, "203.0.113.7"},
		{"trusted peer without header", "172.18.0.2:4000", nil, "172.18.0.2"},
		{"trusted peer, only trusted hops", "172.18.0.2:4000", []string{"10.0.0.1, 10.0.0.2"}, "172.18.0.2"},
		{"trusted peer, garbage hop", "172.18.0.2:4000", []string{"1.1.1.1, not-an-ip"}, "172.18.0.2"},
		{"untrusted peer ignores the header", "198.51.100.9:5555", []string{"6.6.6.6"}, "198.51.100.9"},
		{"untrusted peer without header", "198.51.100.9:5555", nil, "198.51.100.9"},
		{"ipv6 peer, ipv6 client", "[fd00::1]:80", []string{"2001:db8::7"}, "2001:db8::7"},
		{"peer without port", "10.0.0.1", []string{"203.0.113.7"}, "203.0.113.7"},
		{"unparseable peer is returned as is", "pipe", []string{"6.6.6.6"}, "pipe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trusted.Resolve(tt.remoteAddr, tt.xff); got != tt.want {
				t.Errorf("Resolve(%q, %q) = %q, want %q", tt.remoteAddr, tt.xff, got, tt.want)
			}
		})
	}
}

func TestParseTrusted(t *testing.T) {
	tr := ParseTrusted("192.0.2.1, 2001:db8::1 10.0.0.0/8,fd00::/8")
	tests := []struct {
		addr string
		want bool
	}{
		{"192.0.2.1", true},
		{"192.0.2.2", false},
		{"2001:db8::1", true},
		{"2001:db8::2", false},
		{"10.200.3.4", true},
		{"11.0.0.1", false},
		{"fd12::1", true},
		{"::ffff:10.0.0.9", true},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := tr.listed(netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Errorf("listed(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}
