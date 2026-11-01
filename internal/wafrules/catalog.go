// Package wafrules is the shared CRS package catalog. The control plane
// exposes it on the WAF page; the proxy compiles disabled tags into
// SecRuleRemoveByTag directives.
package wafrules

import (
	"fmt"
	"strings"
)

type Package struct {
	Tag         string `json:"tag"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func Packages() []Package {
	return []Package{
		{Tag: "attack-sqli", Name: "SQL injection", Description: "OWASP CRS SQLi rules (tag attack-sqli)."},
		{Tag: "attack-xss", Name: "Cross-site scripting", Description: "OWASP CRS XSS rules (tag attack-xss)."},
		{Tag: "attack-lfi", Name: "Path traversal", Description: "OWASP CRS LFI / traversal rules (tag attack-lfi)."},
		{Tag: "attack-rce", Name: "OS command injection", Description: "OWASP CRS RCE rules (tag attack-rce)."},
		{Tag: "attack-protocol", Name: "Protocol", Description: "HTTP protocol violations (tag attack-protocol)."},
		{Tag: "attack-generic", Name: "Generic", Description: "Generic attack patterns (tag attack-generic)."},
		{Tag: "scanner", Name: "Scanner", Description: "Scanner and probe signatures (tag scanner)."},
	}
}

func KnownTags() map[string]Package {
	out := map[string]Package{}
	for _, p := range Packages() {
		out[p.Tag] = p
	}
	return out
}

func ValidateDisabledTags(tags []string) error {
	known := KnownTags()
	seen := map[string]struct{}{}
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if _, ok := known[tag]; !ok {
			return fmt.Errorf("unknown WAF package %s", tag)
		}
		seen[tag] = struct{}{}
	}
	if len(seen) >= len(known) {
		return fmt.Errorf("leave at least one package enabled")
	}
	return nil
}

func NormalizeDisabledTags(tags []string) []string {
	known := KnownTags()
	seen := map[string]struct{}{}
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if _, ok := known[tag]; !ok {
			continue
		}
		if _, dup := seen[tag]; dup {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	return out
}

func NormalizeMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "detect") {
		return "detect"
	}
	return "block"
}

func NormalizeParanoia(n int) int {
	if n < 1 {
		return 1
	}
	if n > 4 {
		return 4
	}
	return n
}

// Body inspection limit: how much of a request body the WAF reads. Bodies
// past it are forwarded uninspected (never rejected), so uploads keep
// working; raise it for form-heavy apps.
const (
	DefaultBodyLimit = 1 << 20  // 1 MiB
	MinBodyLimit     = 16 << 10 // 16 KiB
	MaxBodyLimit     = 64 << 20 // 64 MiB
)

func NormalizeBodyLimit(n int) int {
	if n <= 0 {
		return DefaultBodyLimit
	}
	if n < MinBodyLimit {
		return MinBodyLimit
	}
	if n > MaxBodyLimit {
		return MaxBodyLimit
	}
	return n
}

func NormalizeThreshold(n int) int {
	if n < 1 {
		return 5
	}
	if n > 100 {
		return 100
	}
	return n
}
