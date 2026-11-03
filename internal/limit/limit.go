// Package limit has token-bucket rate limiters keyed by a string and the Gin
// middleware that answers 429 when a bucket is empty.
package limit

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/abdusalomovrustambek/auth-gateway/internal/httpx"
)

// minIdle is the shortest time an unused bucket is kept.
const minIdle = time.Minute

// Limiter keeps one token bucket per key. Buckets that have been idle long
// enough to be full again are dropped, so memory follows the active keys.
type Limiter struct {
	limit rate.Limit
	burst int
	idle  time.Duration
	now   func() time.Time

	mu        sync.Mutex
	entries   map[string]*entry
	lastSweep time.Time
}

type entry struct {
	bucket *rate.Limiter
	seen   time.Time
}

// New returns a Limiter whose buckets refill at r tokens per second and hold at
// most burst tokens.
func New(r rate.Limit, burst int) *Limiter {
	idle := minIdle
	if r > 0 && r != rate.Inf {
		if refill := time.Duration(float64(burst) / float64(r) * float64(time.Second)); refill > idle {
			idle = refill
		}
	}
	l := &Limiter{limit: r, burst: burst, idle: idle, now: time.Now, entries: make(map[string]*entry)}
	l.lastSweep = l.now()
	return l
}

// Per returns a Limiter that allows n requests per interval, with a burst of n.
func Per(n int, interval time.Duration) *Limiter {
	return New(rate.Every(interval/time.Duration(n)), n)
}

// Allow takes a token from the bucket of key. When the bucket is empty it
// returns false and how long until a token is available.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)

	e, ok := l.entries[key]
	if !ok {
		e = &entry{bucket: rate.NewLimiter(l.limit, l.burst)}
		l.entries[key] = e
	}
	e.seen = now

	res := e.bucket.ReserveN(now, 1)
	if !res.OK() {
		return false, l.idle
	}
	if wait := res.DelayFrom(now); wait > 0 {
		res.CancelAt(now)
		return false, wait
	}
	return true, 0
}

// Len is the number of buckets currently kept.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// sweep drops idle buckets, at most once per idle period. The caller holds mu.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < l.idle {
		return
	}
	for k, e := range l.entries {
		if now.Sub(e.seen) >= l.idle {
			delete(l.entries, k)
		}
	}
	l.lastSweep = now
}

// Middleware answers 429 with a Retry-After header when the bucket of key(c) is
// empty.
func Middleware(l *Limiter, key func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ok, wait := l.Allow(key(c))
		if ok {
			c.Next()
			return
		}
		secs := max(int(math.Ceil(wait.Seconds())), 1)
		c.Header("Retry-After", strconv.Itoa(secs))
		httpx.Error(c, http.StatusTooManyRequests, "too many requests")
	}
}

// OnPath runs mw only for requests whose URL path is exactly path.
func OnPath(path string, mw gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == path {
			mw(c)
			return
		}
		c.Next()
	}
}
