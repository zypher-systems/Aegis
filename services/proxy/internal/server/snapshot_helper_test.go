package server

import (
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

// snapshot is the config a test applies. WAF, CrowdSec and GeoIP run whenever
// the host turns them on.
func snapshot(t testing.TB, _ *Server, u *aegisv1.ConfigUpdate) *aegisv1.ConfigUpdate {
	t.Helper()
	return u
}
