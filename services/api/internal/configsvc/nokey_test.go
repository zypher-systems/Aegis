package configsvc

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

// The snapshot must never carry field 4 of SecurityConfig (the master key,
// removed in 1.7.2). Guards against the field being reintroduced.
func TestSecurityConfigHasNoField4(t *testing.T) {
	fields := (&aegisv1.SecurityConfig{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if protowire.Number(f.Number()) == 4 || strings.Contains(string(f.Name()), "cookie_key") {
			t.Fatalf("SecurityConfig field %d %s must stay reserved", f.Number(), f.Name())
		}
	}
}
