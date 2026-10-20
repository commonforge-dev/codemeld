#!/usr/bin/env bash
# OSS secret gate: fail if a shipping file contains a credential-shaped value, a
# real ~/.codemeld session dump path, or a private developer-machine absolute path.
# This is the one exclusion .gitignore cannot perform — .gitignore drops whole
# paths and never reads file contents, so a secret pasted *inside* a shipping file
# would ship undetected. Repo-specific by design (no scanner dependency).
#
# Deliberately NOT flagged (these are not secrets): documented env-var names such as
# OPENAI_API_KEY, user-facing config paths such as ~/.codemeld/global/settings.yaml
# and ~/.codemeld/sessions/<id>.json, and the synthetic home paths (/home/u,
# /home/me) used as test fixtures.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Credential-shaped values: real provider/key/token prefixes. These forms do not
# occur in placeholder names or prose, so false positives are near zero.
CRED_RE='\bsk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9-]{20,}|sk-or-v1-[A-Za-z0-9]{20,}|\bghp_[A-Za-z0-9]{30,}|\bgho_[A-Za-z0-9]{30,}|\bghs_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{18,}|xox[baprs]-[A-Za-z0-9-]{10,}|\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----'

# A real session dump path carries the 16+ hex folder/session id; the documented
# form uses <id>/<folder-dir> placeholders and is allowed.
SESSION_RE='\.codemeld/sessions/[0-9a-f]{16,}'

# Private developer-machine absolute paths. The running user's real home is taken
# from $HOME at runtime, so this shipped script hardcodes no maintainer username and
# works for any contributor running the gate; it is flagged everywhere because the
# fixture convention is synthetic (/home/u, /home/me), never a real home. The
# project-storage root is the one repo-specific literal — it reveals layout, not an
# identity — and is allowed only in *_test.go, where a representative absolute path
# is intentional.
HOME_PATH="${HOME:-}"
STORE_RE='/data/vcs'

# Scan repo-relative file paths read on stdin (resolved against the current
# directory). Returns 1 on any finding, 0 otherwise; diagnostics go to stderr.
scan_secrets() {
  local violations=0 file is_test cat out line
  emit() { # $1=category  $2=grep "lineno:match" output
    cat="$1"; out="$2"
    [ -z "$out" ] && return 0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      if [ "$violations" -eq 0 ]; then
        echo "oss-secret-scan: possible secret or private data in shipping file(s):" >&2
      fi
      echo "  [$cat] $file:${line%%:*}" >&2
      violations=1
    done <<EOF
$out
EOF
  }

  while IFS= read -r file; do
    [ -z "$file" ] && continue
    is_test=0
    case "$file" in *_test.go) is_test=1 ;; esac

    emit credential   "$(grep -InoE  "$CRED_RE"    "$file" 2>/dev/null || true)"
    emit session-dump "$(grep -InioE "$SESSION_RE" "$file" 2>/dev/null || true)"
    if [ -n "$HOME_PATH" ] && [ "$HOME_PATH" != "/" ]; then
      emit private-home "$(grep -InoF "$HOME_PATH" "$file" 2>/dev/null || true)"
    fi
    if [ "$is_test" -eq 0 ]; then
      emit private-store "$(grep -InoE "$STORE_RE" "$file" 2>/dev/null || true)"
    fi
  done

  return "$violations"
}

run_self_test() {
  local tmp; tmp="$(mktemp -d)"
  trap "rm -rf -- '$tmp'" EXIT
  local fails=0
  cd "$tmp"
  mkdir -p docs internal

  # Negative: documented names and user-facing config paths must pass.
  {
    printf 'Set OPENAI_API_KEY or edit ~/.codemeld/global/settings.yaml\n'
    printf 'Per-session transcripts live in ~/.codemeld/sessions/<id>.json\n'
    printf 'Fixtures may use synthetic home paths like /home/u/proj and /home/me.\n'
  } > docs/ok.md
  if ! printf 'docs/ok.md\n' | scan_secrets; then
    echo "self-test FAIL: documented names / config paths must not be flagged" >&2; fails=1
  fi

  # Positive: credential value.
  printf 'key = "sk-abcdefghijklmnopqrstuvwx0123456789ABCD"\n' > docs/cred.md
  if printf 'docs/cred.md\n' | scan_secrets 2>/dev/null; then
    echo "self-test FAIL: a credential value was not caught" >&2; fails=1
  fi

  # Positive: real session dump path (hex id, not a placeholder).
  printf 'dumped to ~/.codemeld/sessions/62f8fa396e61ecc2/abc.json\n' > docs/sess.md
  if printf 'docs/sess.md\n' | scan_secrets 2>/dev/null; then
    echo "self-test FAIL: a session-dump path was not caught" >&2; fails=1
  fi

  # Positive: the running user's real home path ($HOME) is caught everywhere.
  printf 'config at %s/.codemeld\n' "$HOME_PATH" > docs/home.md
  if printf 'docs/home.md\n' | scan_secrets 2>/dev/null; then
    echo "self-test FAIL: a private home path was not caught" >&2; fails=1
  fi

  # Project-storage path: caught in non-test files, carved out for *_test.go.
  printf 'package x\nconst root = "/data/vcs/codemeld/main"\n' > internal/cfg.go
  if printf 'internal/cfg.go\n' | scan_secrets 2>/dev/null; then
    echo "self-test FAIL: a project-storage path in a non-test file must be caught" >&2; fails=1
  fi
  printf 'package x\nconst root = "/data/vcs/codemeld/main"\n' > internal/cfg_test.go
  if ! printf 'internal/cfg_test.go\n' | scan_secrets; then
    echo "self-test FAIL: a project-storage path in a *_test.go fixture must pass" >&2; fails=1
  fi

  if [ "$fails" -eq 0 ]; then
    echo "oss-secret-scan: self-test passed"
  else
    echo "oss-secret-scan: self-test FAILED" >&2
  fi
  return "$fails"
}

main() {
  if [ "${1:-}" = "--self-test" ]; then
    run_self_test
    exit $?
  fi
  cd "$repo_root"
  if "$repo_root/scripts/oss-shipping-files.sh" | scan_secrets; then
    exit 0
  fi
  echo "oss-secret-scan: remove the secret/private data from the shipping file, or move" >&2
  echo "machine-local config into the withheld mise.local.toml / private/ set." >&2
  exit 1
}

main "$@"
