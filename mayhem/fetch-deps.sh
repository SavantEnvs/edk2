#!/usr/bin/env bash
# Run as root in the Dockerfile: fetch each pinned dependency in mayhem/deps.txt once into
# /opt/toolchains/deps/<name>-<sha12>/src (source only, uninstrumented, no .git).
set -euo pipefail
list="${1:-$(dirname "$0")/deps.txt}"
grep -v '^[[:space:]]*#' "$list" | while read -r name sha url _; do
  [ -n "$name" ] || continue
  d=/opt/toolchains/deps/${name}-${sha:0:12}
  [ -n "$(ls -A "$d/src" 2>/dev/null)" ] && continue   # the same pin can back several paths
  mkdir -p "$d/src"
  ( cd "$d/src" && git init -q && git remote add origin "$url" \
      && git fetch -q --depth 1 origin "$sha" && git checkout -q FETCH_HEAD && rm -rf .git )
  chmod -R a+rX "$d"
done
