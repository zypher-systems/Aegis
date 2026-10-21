package passwd

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("phc: %s", h)
	}
	if !Verify("correct horse battery staple", h) {
		t.Fatal("verify")
	}
	if Verify("wrong password!!", h) {
		t.Fatal("wrong password")
	}
	h2, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if h == h2 {
		t.Fatal("salts should differ")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash",
		"$argon2id$v=19$m=x$salt$key",
		"$bcrypt$v=19$m=65536,t=1,p=4$YWFh$YmJi",
		"$argon2id$v=19$m=65536,t=1,p=4$@@@$YmJi",
		"$argon2id$v=19$m=65536,t=1,p=4$YWFh$@@@",
		"$argon2id$v=19$m=65536,t=1,p=4$YWFh",
	}
	for _, c := range cases {
		if Verify("pw", c) {
			t.Fatalf("accepted %q", c)
		}
	}
}
