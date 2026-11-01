package httpapi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGeoIPReady(t *testing.T) {
	if geoIPReady("") {
		t.Fatal("empty path")
	}
	if geoIPReady("/no/such/geo.mmdb") {
		t.Fatal("missing file")
	}
	dir := t.TempDir()
	if geoIPReady(dir) {
		t.Fatal("directory is not ready")
	}
	p := filepath.Join(dir, "country.mmdb")
	if err := os.WriteFile(p, []byte("not a real mmdb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !geoIPReady(p) {
		t.Fatal("file should be ready")
	}
}
