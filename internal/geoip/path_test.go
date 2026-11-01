package geoip

import (
	"os"
	"testing"
)

func TestResolvePathDisable(t *testing.T) {
	for _, v := range []string{"none", "OFF", "-", " off "} {
		if got := ResolvePath(v); got != "" {
			t.Fatalf("ResolvePath(%q) = %q, want empty", v, got)
		}
	}
}

func TestResolvePathExplicit(t *testing.T) {
	got := ResolvePath(" /custom/GeoIP.mmdb ")
	if got != "/custom/GeoIP.mmdb" {
		t.Fatalf("got %q", got)
	}
}

func TestResolvePathEmptyWithoutBakedFile(t *testing.T) {
	if _, err := os.Stat(DefaultMMDB); err == nil {
		t.Skip("baked MMDB present")
	}
	if got := ResolvePath(""); got != "" {
		t.Fatalf("empty env with no baked file: got %q", got)
	}
}
