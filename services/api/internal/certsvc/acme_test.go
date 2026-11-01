package certsvc

import "testing"

func TestOrderKeyIgnoresOrderAndCase(t *testing.T) {
	const dir = "https://acme.example/dir"
	a := orderKey([]string{"b.example.com", "A.example.com"}, dir)
	if b := orderKey([]string{"a.example.com", "b.example.com"}, dir); a != b {
		t.Fatalf("%q != %q", a, b)
	}
	if a == orderKey([]string{"a.example.com"}, dir) {
		t.Fatal("different names share a key")
	}
	if a == orderKey([]string{"a.example.com", "b.example.com"}, "https://other.example/dir") {
		t.Fatal("different directories share a key")
	}
}
