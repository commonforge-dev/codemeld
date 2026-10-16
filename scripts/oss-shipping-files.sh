#!/usr/bin/env bash
# Emit the OSS file list (one path per line, relative to the current directory):
# with --ship, every file the public repo receives; with no argument, the subset
# the reference check and secret scan read.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  ship=0
elif [ "$#" -eq 1 ] && [ "$1" = "--ship" ]; then
  ship=1
else
  echo "usage: oss-shipping-files.sh [--ship]" >&2
  exit 2
fi

# The include list mirrors the "Ships" set in private/release.md. Everything not
# listed here is withheld and never scanned — the prdwise apparatus (specs/,
# tasks/, archives/, adrs/, reviews/, work-done.md), private/, the root
# CLAUDE.md / AGENTS.md, private-source mise config (.mise.toml, mise.local.toml),
# and private task-apparatus scripts such as scripts/wiring-stub-check.sh. The
# public .gitignore excludes the same withheld set by whole path; this helper
# covers the content side, so the two must stay in sync (see private/release.md /
# ignore.md).
#
# The OSS gate machinery (scripts/oss-*.sh, .oss-reference-allow) ships but is
# left out of the scan list: by design these hold the very tokens and path
# patterns the scanners ban, so scanning them would self-flag.
shipping_dirs=(internal cmd scripts contributing docs schemas .github)
shipping_root_files=(
  go.mod go.sum mise.toml
  README.md ROADMAP.md LICENSE SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md
  .deadcode-allow .golangci.yml
)
gate_filter=(! -path 'scripts/oss-*.sh')
if [ "$ship" -eq 1 ]; then
  shipping_root_files+=(.oss-reference-allow)
  gate_filter=()
fi

{
  for dir in "${shipping_dirs[@]}"; do
    [ -d "$dir" ] || continue
    find "$dir" -type f \
      ! -name '*.swp' \
      ! -path 'docs/tasks/*' \
      ! -path 'docs/research/*' \
      ! -path 'scripts/wiring-stub-check.sh' \
      "${gate_filter[@]}" \
      -print
  done
  for f in "${shipping_root_files[@]}"; do
    if [ -f "$f" ]; then printf '%s\n' "$f"; fi
  done
} | LC_ALL=C sort -u
