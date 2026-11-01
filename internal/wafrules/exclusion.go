package wafrules

import (
	"fmt"
	"regexp"
	"strings"
)

// An exclusion target narrows an exclusion to one input, so the rule keeps
// inspecting everything else: REQUEST_COOKIES:ph_x_posthog, ARGS:q,
// REQUEST_HEADERS:x-foo. A key in slashes is a regular expression over names
// (REQUEST_COOKIES:/^ph_.+_posthog$/).
var (
	targetCollections = map[string]bool{
		"ARGS": true, "ARGS_GET": true, "ARGS_POST": true, "ARGS_NAMES": true,
		"REQUEST_COOKIES": true, "REQUEST_COOKIES_NAMES": true,
		"REQUEST_HEADERS": true, "REQUEST_HEADERS_NAMES": true,
		"XML": true,
	}
	targetKeyRe   = regexp.MustCompile(`^[A-Za-z0-9_.\-$\[\]]{1,200}$`)
	targetRegexRe = regexp.MustCompile(`^/[A-Za-z0-9_.\-$\[\]^*+?(){}|\\]{1,200}/$`)
)

// NormalizeTarget trims a target and upper-cases its collection.
func NormalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	coll, key, found := strings.Cut(t, ":")
	coll = strings.ToUpper(strings.TrimSpace(coll))
	if !found {
		return coll
	}
	return coll + ":" + strings.TrimSpace(key)
}

// ValidateTarget accepts "", COLLECTION, COLLECTION:name or COLLECTION:/regex/.
// It is strict because the value is written into a SecLang directive.
func ValidateTarget(t string) error {
	if t == "" {
		return nil
	}
	coll, key, found := strings.Cut(t, ":")
	if !targetCollections[coll] {
		return fmt.Errorf("exclusion target %q: collection must be one of ARGS, ARGS_GET, ARGS_POST, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS, REQUEST_HEADERS_NAMES, XML", t)
	}
	if !found {
		return nil
	}
	if targetKeyRe.MatchString(key) || targetRegexRe.MatchString(key) {
		return nil
	}
	return fmt.Errorf("exclusion target %q: name may use letters, digits and _ . - $ [ ], or be a /regex/", t)
}
