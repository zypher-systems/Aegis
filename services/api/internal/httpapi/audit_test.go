package httpapi

import "testing"

func TestSanitizeSummaryRedactsSecrets(t *testing.T) {
	out := sanitizeSummary(map[string]any{
		"email":      "a@b.c",
		"password":   "supersecretpassword",
		"token":      "cf-token",
		"api_token":  "x",
		"secret":     "y",
		"cert_pem":   "PEM",
		"key_pem":    "KEY",
		"key":        "k",
		"domains":    []string{"demo.local"},
		"configured": true,
	})
	if _, ok := out["password"]; ok {
		t.Fatal("password leaked")
	}
	if _, ok := out["token"]; ok {
		t.Fatal("token leaked")
	}
	if _, ok := out["api_token"]; ok {
		t.Fatal("api_token leaked")
	}
	if _, ok := out["secret"]; ok {
		t.Fatal("secret leaked")
	}
	if _, ok := out["cert_pem"]; ok {
		t.Fatal("cert_pem leaked")
	}
	if _, ok := out["key"]; ok {
		t.Fatal("key leaked")
	}
	if out["email"] != "a@b.c" {
		t.Fatalf("email dropped: %v", out["email"])
	}
	if out["configured"] != true {
		t.Fatal("configured dropped")
	}
}

func TestSanitizeSummaryNil(t *testing.T) {
	out := sanitizeSummary(nil)
	if out == nil || len(out) != 0 {
		t.Fatalf("want empty map, got %v", out)
	}
}
