#!/usr/bin/env bash
# Reachability gate: fail if `deadcode` reports an unreachable func not in .deadcode-allow.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allow="$repo_root/.deadcode-allow"

# Normalize "file:line:col: unreachable func: Name" -> "file Name" so allowlist
# entries stay stable as line numbers shift.
findings="$(
  deadcode -filter=codemeld.dev/codemeld codemeld.dev/codemeld/cmd/codemeld \
    | sed -nE 's#^([^:]+):[0-9]+:[0-9]+: unreachable func: (.+)$#\1 \2#p'
)"

# Allowlist with comments and blank lines stripped.
allowlist="$(grep -vE '^[[:space:]]*(#|$)' "$allow" || true)"

violations=0
while IFS= read -r finding; do
  [ -z "$finding" ] && continue
  if ! printf '%s\n' "$allowlist" | grep -qxF "$finding"; then
    if [ "$violations" -eq 0 ]; then
      echo "deadcode-check: unreachable, non-allowlisted function(s):" >&2
    fi
    echo "  $finding" >&2
    violations=1
  fi
done <<EOF
$findings
EOF

stale=0
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  if ! printf '%s\n' "$findings" | grep -qxF "$entry"; then
    if [ "$stale" -eq 0 ]; then
      echo "deadcode-check: warning — .deadcode-allow entries deadcode no longer reports:" >&2
      stale=1
    fi
    echo "  $entry" >&2
  fi
done <<EOF
$allowlist
EOF

if [ "$stale" -ne 0 ]; then
  echo "deadcode-check: a stale entry means the function is now reachable (or moved/renamed)," >&2
  echo "not that it is safe to delete. Prune the allowlist line only; deleting the function" >&2
  echo "needs tracked cleanup work — see docs/deadcode-process.md." >&2
fi

if [ "$violations" -ne 0 ]; then
  echo "deadcode-check: wire a production caller, delete the function, or (if an" >&2
  echo "intentional test-only seam) document it and add it to .deadcode-allow." >&2
  exit 1
fi
