package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccessLogRotatesBySizeAndKeepsN(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	l := newAccessLog(path)
	if l == nil {
		t.Fatal("open")
	}
	l.maxBytes = 2000
	l.keep = 2
	req := httptest.NewRequest(http.MethodGet, "http://x/"+strings.Repeat("p", 100), nil)
	req.RemoteAddr = "203.0.113.5:1"
	for i := 0; i < 200; i++ { // ~200 B a line → many rotations
		l.Write(req, 200, 10, nil)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 3 { // access.log, .1, .2
		t.Fatalf("files %v, want live + 2 kept", names)
	}
	for _, n := range names {
		st, _ := os.Stat(filepath.Join(dir, n))
		if st.Size() > 2200 {
			t.Fatalf("%s is %d bytes, over the cap", n, st.Size())
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Fatal("more copies kept than configured")
	}
	// Still writing to the live file after rotations.
	before, _ := os.Stat(path)
	l.Write(req, 200, 10, nil)
	after, _ := os.Stat(path)
	if after.Size() <= before.Size() {
		t.Fatal("live file not written after rotation")
	}
}
