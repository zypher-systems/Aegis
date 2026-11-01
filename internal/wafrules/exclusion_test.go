package wafrules

import "testing"

func TestValidateTarget(t *testing.T) {
	ok := []string{"", "ARGS", "REQUEST_COOKIES:ph_phc_abc_posthog", "ARGS:q", "REQUEST_HEADERS:x-foo", "REQUEST_COOKIES:/^ph_.+_posthog$/"}
	bad := []string{"TX:foo", "REQUEST_COOKIES:a b", `REQUEST_COOKIES:x"`, "REQUEST_COOKIES:x;y", "ARGS:x'y", "REQUEST_COOKIES:x\nSecRuleEngine Off"}
	for _, v := range ok {
		if err := ValidateTarget(NormalizeTarget(v)); err != nil {
			t.Fatalf("%q should be valid: %v", v, err)
		}
	}
	for _, v := range bad {
		if err := ValidateTarget(NormalizeTarget(v)); err == nil {
			t.Fatalf("%q must be rejected", v)
		}
	}
	if NormalizeTarget(" request_cookies:foo ") != "REQUEST_COOKIES:foo" {
		t.Fatal("collection should be upper-cased")
	}
}
