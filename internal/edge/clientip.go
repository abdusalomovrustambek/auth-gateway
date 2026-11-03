// Package edge is what faces the internet: client IP resolution, the access
// log, the reverse proxy to shop-api and the static web app.
package edge

import (
	"net/netip"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"

	"github.com/abdusalomovrustambek/auth-gateway/internal/httpx"
)

// Trusted is the set of reverse proxies whose X-Forwarded-For is believed.
type Trusted struct {
	prefixes []netip.Prefix
}

// ParseTrusted reads a comma- or space-separated list of IPs and CIDRs, such as
// "172.18.0.2, 10.0.0.0/8". Entries that cannot be parsed are skipped.
func ParseTrusted(list string) *Trusted {
	t := &Trusted{}
	fields := strings.FieldsFunc(list, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	for _, field := range fields {
		if p, err := netip.ParsePrefix(field); err == nil {
			t.prefixes = append(t.prefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(field); err == nil {
			a = a.Unmap()
			t.prefixes = append(t.prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return t
}

// listed reports whether addr is one of the configured proxies.
func (t *Trusted) listed(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range t.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// trustsPeer reports whether the peer's X-Forwarded-For is believed.
func (t *Trusted) trustsPeer(peer netip.Addr) bool {
	return len(t.prefixes) == 0 || t.listed(peer)
}

// Resolve returns the client IP. When the peer is a trusted proxy it is the
// rightmost X-Forwarded-For address that is not itself a trusted proxy;
// otherwise, and when the header holds nothing usable, it is the peer.
func (t *Trusted) Resolve(remoteAddr string, forwardedFor []string) string {
	peer, ok := peerAddr(remoteAddr)
	if !ok {
		return remoteAddr
	}
	if !t.trustsPeer(peer) {
		return peer.String()
	}
	var hops []string
	for _, h := range forwardedFor {
		hops = append(hops, strings.Split(h, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		addr = addr.Unmap()
		if !t.listed(addr) {
			return addr.String()
		}
	}
	return peer.String()
}

func peerAddr(remoteAddr string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(remoteAddr); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// ClientIP is a middleware that resolves the client IP and stores it with
// httpx.SetClientIP.
func ClientIP(t *Trusted) gin.HandlerFunc {
	return func(c *gin.Context) {
		httpx.SetClientIP(c, t.Resolve(c.Request.RemoteAddr, c.Request.Header.Values("X-Forwarded-For")))
		c.Next()
	}
}
