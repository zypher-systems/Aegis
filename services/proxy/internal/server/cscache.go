package server

import (
	"net"
	"strings"
	"sync"
)

// decisionCache is the L7 CrowdSec bouncer view: IPs and CIDRs currently
// banned, plus the decision origin (CAPI vs local) when CrowdSec sends it.
type decisionCache struct {
	mu     sync.RWMutex
	ips    map[string]string
	cidrs  []cidrBan
	origin map[string]string // value (ip or cidr) -> origin
}

type cidrBan struct {
	net    *net.IPNet
	origin string
	raw    string
}

func newDecisionCache() *decisionCache {
	return &decisionCache{
		ips:    map[string]string{},
		origin: map[string]string{},
	}
}

func (c *decisionCache) banned(ip string) (origin string, ok bool) {
	if c == nil || ip == "" {
		return "", false
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	c.mu.RLock()
	defer c.mu.RUnlock()
	if parsed != nil {
		key := parsed.String()
		if o, hit := c.ips[key]; hit {
			return o, true
		}
		for _, n := range c.cidrs {
			if n.net.Contains(parsed) {
				return n.origin, true
			}
		}
		return "", false
	}
	if o, hit := c.ips[ip]; hit {
		return o, true
	}
	return "", false
}

func (c *decisionCache) apply(added, removed []streamDecision) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range removed {
		c.removeLocked(d)
	}
	for _, d := range added {
		if !strings.EqualFold(d.Type, "ban") {
			continue
		}
		c.addLocked(d)
	}
}

func (c *decisionCache) addLocked(d streamDecision) {
	val := strings.TrimSpace(d.Value)
	if val == "" {
		return
	}
	origin := strings.TrimSpace(d.Origin)
	if ip := net.ParseIP(val); ip != nil {
		c.ips[ip.String()] = origin
		c.origin[ip.String()] = origin
		return
	}
	if _, n, err := net.ParseCIDR(val); err == nil {
		c.cidrs = append(c.cidrs, cidrBan{net: n, origin: origin, raw: n.String()})
		c.origin[n.String()] = origin
	}
}

func (c *decisionCache) removeLocked(d streamDecision) {
	val := strings.TrimSpace(d.Value)
	if val == "" {
		return
	}
	if ip := net.ParseIP(val); ip != nil {
		delete(c.ips, ip.String())
		delete(c.origin, ip.String())
		return
	}
	if _, n, err := net.ParseCIDR(val); err == nil {
		want := n.String()
		next := c.cidrs[:0]
		for _, x := range c.cidrs {
			if x.raw != want {
				next = append(next, x)
			}
		}
		c.cidrs = next
		delete(c.origin, want)
	}
}

func (c *decisionCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.ips) + len(c.cidrs)
}
