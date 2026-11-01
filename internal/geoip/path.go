// Package geoip resolves the country MMDB path used by the API and proxy.
package geoip

import (
	"os"
	"strings"
)

// DefaultMMDB is the DB-IP Country Lite file baked into api/proxy images.
const DefaultMMDB = "/usr/share/aegis/geoip/country.mmdb"

// ResolvePath maps AEGIS_GEOIP_MMDB to a filesystem path.
//
// Empty uses DefaultMMDB when that file exists (image builds). "none",
// "off", or "-" disables GeoIP. Any other value is used as-is.
func ResolvePath(env string) string {
	v := strings.TrimSpace(env)
	switch strings.ToLower(v) {
	case "none", "off", "-":
		return ""
	case "":
		st, err := os.Stat(DefaultMMDB)
		if err != nil || st.IsDir() {
			return ""
		}
		return DefaultMMDB
	default:
		return v
	}
}
