package certsvc

import "testing"

func TestNeedsDNS01(t *testing.T) {
	if NeedsDNS01([]string{"app.example.com"}) {
		t.Fatal("explicit name should use HTTP-01")
	}
	if !NeedsDNS01([]string{"*.example.com"}) {
		t.Fatal("wildcard requires DNS-01")
	}
	if !NeedsDNS01([]string{"example.com", "*.example.com"}) {
		t.Fatal("mixed SAN with wildcard requires DNS-01")
	}
}

func TestNormalizeDomains(t *testing.T) {
	got, err := NormalizeDomains([]string{" Example.COM ", "*.example.com", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "example.com" || got[1] != "*.example.com" {
		t.Fatalf("got %v", got)
	}
	if _, err := NormalizeDomains([]string{"not a host"}); err == nil {
		t.Fatal("expected invalid domain")
	}
}

func TestCoversWildcard(t *testing.T) {
	if !covers([]string{"*.example.com"}, []string{"app.example.com"}) {
		t.Fatal("wildcard cert should cover subdomain")
	}
	if covers([]string{"*.example.com"}, []string{"example.com"}) {
		t.Fatal("*.example.com does not cover the apex")
	}
	if !covers([]string{"app.example.com"}, []string{"app.example.com"}) {
		t.Fatal("exact match")
	}
}
