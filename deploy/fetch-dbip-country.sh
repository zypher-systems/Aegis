#!/bin/sh
# Download DB-IP IP to Country Lite (CC BY 4.0) for baking into images.
# https://db-ip.com/db/lite.php — attribution required on pages that show results.
set -eu

dest="${1:-/out/geoip/country.mmdb}"
prefer="${2:-}"

mkdir -p "$(dirname "$dest")"

prev_month() {
	ym="$1"
	y=${ym%-*}
	m=${ym#*-}
	m=${m#0}
	if [ "$m" -eq 1 ]; then
		printf '%d-12' $((y - 1))
	else
		printf '%d-%02d' "$y" $((m - 1))
	fi
}

now=$(date -u +%Y-%m)
if [ -n "$prefer" ]; then
	candidates="$prefer $(prev_month "$prefer")"
else
	candidates="$now $(prev_month "$now")"
fi

tried=""
ok=0
for tag in $candidates; do
	case " $tried " in
	*" $tag "*) continue ;;
	esac
	tried="$tried $tag"
	url="https://download.db-ip.com/free/dbip-country-lite-${tag}.mmdb.gz"
	tmp="${dest}.tmp"
	echo "geoip: fetching $url" >&2
	if curl -fsSL --retry 3 --retry-delay 2 "$url" | gzip -dc >"$tmp"; then
		if [ ! -s "$tmp" ]; then
			rm -f "$tmp"
			continue
		fi
		if ! grep -a -q 'MaxMind.com' "$tmp"; then
			echo "geoip: $tag: not an MMDB" >&2
			rm -f "$tmp"
			continue
		fi
		mv "$tmp" "$dest"
		echo "geoip: installed $tag -> $dest ($(wc -c <"$dest") bytes)" >&2
		ok=1
		break
	fi
	rm -f "$tmp"
done

if [ "$ok" -ne 1 ]; then
	echo "geoip: failed to download DB-IP country lite" >&2
	exit 1
fi
