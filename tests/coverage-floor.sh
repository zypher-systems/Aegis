#!/bin/sh
# Fail if any trust-spine package is under 60% statement coverage.
# Run before merging. Also runs those packages with -race.
set -eu
min=60
fail=0
pkgs='
github.com/zypher-systems/aegis/services/api/internal/ca
github.com/zypher-systems/aegis/services/api/internal/crypto
github.com/zypher-systems/aegis/services/api/internal/enroll
github.com/zypher-systems/aegis/services/proxy/internal/identity
github.com/zypher-systems/aegis/internal/passwd
'
for pkg in $pkgs; do
  cov=$(mktemp)
  go test -race -count=1 -coverprofile="$cov" "$pkg"
  pct=$(go tool cover -func="$cov" | awk '/^total:/{gsub("%","",$NF); print $NF}')
  rm -f "$cov"
  echo "$pkg ${pct}%"
  awk -v p="$pct" -v m="$min" 'BEGIN { exit !(p+0 >= m+0) }' || {
    echo "FAIL: $pkg coverage ${pct}% < ${min}%"
    fail=1
  }
done
exit "$fail"
