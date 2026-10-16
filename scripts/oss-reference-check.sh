#!/usr/bin/env bash
# OSS reference gate: fail if a shipping file reintroduces a banned PRD / process
# reference. Public docs and code must stay self-contained for open-source readers
# who cannot resolve the withheld apparatus (a `req N` tag or a `specs/` pointer is
# a dangling reference to files that do not ship). Every prepped task cites
# requirement numbers by convention, so without this gate the shipping set drifts
# dirty again within days of a one-time scrub.
#
# Banned tokens fall in three classes:
#   Category 1 (PRD / requirement refs): req N, req-N, requirement N, PRD.
#     Carve-out: an .oss-reference-allow list of the audited req-named
#     identifiers/strings intentionally left in Go sources and test diagnostics.
#     An entry matches its repo-relative path exactly and case-sensitively, and
#     its token case-insensitively: it permits that token in that one file
#     (a public doc included) and never in another file.
#   Category 2 (process apparatus / withheld paths): prdwise, specs/, adrs/,
#     tasks/, archives/, reviews/, documentation.md, work-done.md, CLAUDE.md,
#     scripts/wiring-stub-check.sh, and a repo-relative private/ reference. No
#     carve-out — these have no legitimate place in a shipping file. The private/
#     guard skips OS paths like /private/var that are not the apparatus folder.
#   Category 3 (task / ADR ids): whole tokens adr-NNN and [gfimt]NNN[N], any
#     letter case. Only comment text is checked in .go files (Go strings, rune
#     literals and identifiers are not); every other file is checked in full.
#     Carve-out: the same .oss-reference-allow lookup as category 1, for audited
#     false positives such as the architecture name i386 or a hash fragment.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allow_default="$repo_root/.oss-reference-allow"
id_pattern='\b(adr-[0-9]{3}|[gfimt][0-9]{3,4})\b'

# Print each line of a Go source with everything but its comment text blanked, so
# grep -n over the output reports original line numbers. Raw strings and block
# comments carry state across lines; interpreted strings and rune literals cannot.
go_comments_awk='
{
  s = $0; n = length(s); out = ""; i = 1
  while (i <= n) {
    if (st == 1) {
      j = index(substr(s, i), "*/")
      if (j == 0) { out = out substr(s, i); break }
      out = out substr(s, i, j + 1); i += j + 1; st = 0; continue
    }
    if (st == 2) {
      j = index(substr(s, i), "`")
      if (j == 0) break
      i += j; st = 0; out = out " "; continue
    }
    if (!match(substr(s, i), /[\/"'"'"'`]/)) break
    i += RSTART - 1; out = out " "
    c = substr(s, i, 1); c2 = substr(s, i + 1, 1)
    if (c == "/" && c2 == "/") { out = out substr(s, i); break }
    if (c == "/" && c2 == "*") { out = out "/*"; i += 2; st = 1; continue }
    i++
    if (c == "`") { st = 2; continue }
    if (c == "/") continue
    while (i <= n) {
      d = substr(s, i, 1); i++
      if (d == "\\") i++
      else if (d == c) break
    }
  }
  print out
}'

# Scan the repo-relative file paths read on stdin (resolved against the current
# directory). $1 is the allowlist file (may be empty/absent). Returns 1 on any
# violation, 0 otherwise; diagnostics go to stderr.
scan_reference() {
  local allow="${1:-}"
  local allowlist=""
  [ -n "$allow" ] && [ -f "$allow" ] && allowlist="$(grep -vE '^[[:space:]]*(#|$)' "$allow" | awk -F'\t' 'NF>1 {print $1 "\t" tolower($2); next} {print}' || true)"

  local violations=0 file line lno match match_lower key
  while IFS= read -r file; do
    [ -z "$file" ] && continue

    # --- Categories 1 and 3: requirement references and task/ADR ids ---
    local c1 c3
    c1="$( { grep -InioE 'req[ -]?[0-9]+|requirement [0-9]+' "$file" 2>/dev/null || true; \
             grep -InoE  '\bPRD\b'                            "$file" 2>/dev/null || true; } )"
    c3="$(grep -InioE "$id_pattern" "$file" 2>/dev/null || true)"
    if [ -n "$c3" ] && [[ "$file" == *.go ]]; then
      c3="$(awk "$go_comments_awk" "$file" | grep -nioE "$id_pattern" || true)"
    fi
    c1+=$'\n'"$c3"
    if [ -n "$c1" ]; then
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        lno="${line%%:*}"
        match="${line#*:}"
        # Audited carve-out: the path must match exactly, the token case-insensitively.
        match_lower="$(printf '%s\n' "$match" | awk '{print tolower($0)}')"
        key="$(printf '%s\t%s' "$file" "$match_lower")"
        if printf '%s\n' "$allowlist" | grep -qxF "$key"; then
          continue
        fi
        if [ "$violations" -eq 0 ]; then
          echo "oss-reference-check: banned PRD/process reference in shipping file(s):" >&2
        fi
        echo "  $file:$lno -> '$match'" >&2
        violations=1
      done <<EOF
$c1
EOF
    fi

    # --- Category 2: process apparatus / withheld-path references ---
    local c2
    c2="$(grep -InioE 'prdwise|specs/|adrs/|tasks/|archives/|reviews/|documentation\.md|work-done\.md|\bCLAUDE\.md\b|scripts/wiring-stub-check\.sh|(^|[^/])private/' "$file" 2>/dev/null || true)"
    if [ -n "$c2" ]; then
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        lno="${line%%:*}"
        match="${line#*:}"
        if [ "$violations" -eq 0 ]; then
          echo "oss-reference-check: banned PRD/process reference in shipping file(s):" >&2
        fi
        echo "  $file:$lno -> '$match'" >&2
        violations=1
      done <<EOF
$c2
EOF
    fi
  done

  return "$violations"
}

run_self_test() {
  local tmp; tmp="$(mktemp -d)"
  trap "rm -rf -- '$tmp'" EXIT
  local fails=0
  local helper="$repo_root/scripts/oss-shipping-files.sh"
  cd "$tmp"
  mkdir -p docs/research private specs internal scripts
  echo 'module x' > go.mod

  # (1) Excluded paths are never emitted, and banned text confined to them passes.
  printf 'clean public doc, no banned tokens here.\n'        > docs/ok.md
  printf 'leak: req 5, PRD, prdwise, specs/9-prd.md, tasks/index.md\n' > private/leak.md
  printf 'see private/release.md and requirement 7\n'        > specs/leak.md
  printf 'research notes citing req 3\n'                     > docs/research/leak.md
  printf 'see tasks/index.md\n' > scripts/oss-gate.sh
  printf 'internal/x.go\treq1\n' > .oss-reference-allow
  local list; list="$("$helper")"
  local ship; ship="$("$helper" --ship)"
  if printf '%s\n%s\n' "$list" "$ship" | grep -qE 'private/leak.md|specs/leak.md|docs/research/'; then
    echo "self-test FAIL: a withheld path leaked into the shipping list" >&2; fails=1
  fi
  if ! printf '%s\n' "$list" | scan_reference ""; then
    echo "self-test FAIL: clean shipping tree was flagged" >&2; fails=1
  fi
  if printf '%s\n' "$list" | grep -qxE 'scripts/oss-gate\.sh|\.oss-reference-allow'; then
    echo "self-test FAIL: a gate file leaked into the scan list" >&2; fails=1
  fi
  if ! printf '%s\n' "$ship" | grep -qxF 'scripts/oss-gate.sh' \
    || ! printf '%s\n' "$ship" | grep -qxF '.oss-reference-allow'; then
    echo "self-test FAIL: --ship omitted a gate file" >&2; fails=1
  fi

  # (2) Banned reference inside a shipping file fails.
  printf 'oops, req 9 leaked into a public doc\n' > docs/bad.md
  if printf 'docs/bad.md\n' | scan_reference "" 2>/dev/null; then
    echo "self-test FAIL: banned reference in a shipping doc was not caught" >&2; fails=1
  fi
  rm -f docs/bad.md

  # (2b) Withheld paths named inside a shipping file fail.
  printf 'oops, see tasks/index.md for the owner\n' > docs/path.md
  if printf 'docs/path.md\n' | scan_reference "" 2>/dev/null; then
    echo "self-test FAIL: withheld task path in a shipping doc was not caught" >&2; fails=1
  fi
  rm -f docs/path.md

  # (3) Audited carve-out: req identifiers in tests and non-test Go fail unless
  #     allowlisted; an entry for a Go file never permits the token in a doc.
  printf 'package x\nfunc TestReq135Literal() {}\n' > internal/foo_test.go
  if printf 'internal/foo_test.go\n' | scan_reference "" 2>/dev/null; then
    echo "self-test FAIL: unaudited req in *_test.go must fail" >&2; fails=1
  fi
  printf 'internal/foo_test.go\tReq135\n' > allow-test
  if ! printf 'internal/foo_test.go\n' | scan_reference "$tmp/allow-test"; then
    echo "self-test FAIL: an allowlisted test req must pass" >&2; fails=1
  fi
  printf 'package x\nvar req135 = 1\n' > internal/foo.go
  if printf 'internal/foo.go\n' | scan_reference "" 2>/dev/null; then
    echo "self-test FAIL: req135 in non-test go must fail without an allowlist entry" >&2; fails=1
  fi
  printf 'internal/foo.go\treq135\n' > allow
  if ! printf 'internal/foo.go\n' | scan_reference "$tmp/allow"; then
    echo "self-test FAIL: an allowlisted non-test req must pass" >&2; fails=1
  fi
  printf 'a req135 reference in prose\n' > docs/req.md
  if printf 'docs/req.md\n' | scan_reference "$tmp/allow" 2>/dev/null; then
    echo "self-test FAIL: the allowlist must not permit the same token in a doc" >&2; fails=1
  fi

  # (4) Case folding is token-only: the path stays exact and case-sensitive, so an
  #     entry for another file — or for one differing only in letter case — still fails.
  printf 'package x\nfunc TestReq600Case() {}\n' > internal/case_test.go
  printf 'internal/case_test.go\treq600\n' > allow-case
  if ! printf 'internal/case_test.go\n' | scan_reference "$tmp/allow-case"; then
    echo "self-test FAIL: a lower-case entry must permit its capitalized token" >&2; fails=1
  fi
  printf 'internal/other_test.go\treq600\n' > allow-other-file
  if printf 'internal/case_test.go\n' | scan_reference "$tmp/allow-other-file" 2>/dev/null; then
    echo "self-test FAIL: an entry for a different file must not permit the token" >&2; fails=1
  fi
  printf 'internal/Case_test.go\treq600\n' > allow-other-case
  if printf 'internal/case_test.go\n' | scan_reference "$tmp/allow-other-case" 2>/dev/null; then
    echo "self-test FAIL: an entry whose path differs only in letter case must not match" >&2; fails=1
  fi

  # (5) Task/ADR ids: comment text in Go, full text elsewhere.
  check_case() {
    local want="$1" msg="$2" path="$3" allow="${4:-}" got=pass
    printf '%s\n' "$path" | scan_reference "$allow" 2>/dev/null || got=fail
    if [ "$got" != "$want" ]; then
      echo "self-test FAIL: $msg" >&2; fails=1
    fi
  }
  printf 'package x\n// see g815\n' > internal/line.go
  check_case fail "a task id in a standalone Go line comment" internal/line.go
  printf 'package x\nvar a = 1 // t480\n' > internal/trail.go
  check_case fail "a task id in a trailing Go line comment" internal/trail.go
  printf 'package x\n/* first\n   about m805\n*/\nvar a = 1\n' > internal/block.go
  check_case fail "a task id in a multiline Go block comment" internal/block.go
  printf 'package x\n// G4480 owns this\n' > internal/upper.go
  check_case fail "an uppercase task id in a Go comment" internal/upper.go
  printf 'package x\nvar s = "http://x g815" // see i1150\n' > internal/after.go
  check_case fail "an id in the comment after a string containing //" internal/after.go
  printf 'decided in adr-014\n' > docs/adr.md
  check_case fail "an ADR id in a doc" docs/adr.md
  printf 'decided in ADR-014\n' > docs/adr-upper.md
  check_case fail "an uppercase ADR id in a doc" docs/adr-upper.md

  cat > internal/strings.go <<'EOF'
package x

var a = "see g815 // not a comment m805"
var b = `raw g815
// t480 still raw
adr-014`
var c = "esc \" // g815"
var d = '\''
var e = '"' // plain comment
var g815 = 1
var h = "f123" // no id here
func TestG4480() {}
EOF
  check_case pass "ids in Go strings, rune literals and identifiers must pass" internal/strings.go

  cat > internal/leak.go <<'EOF'
package x

var c = "esc \" // g815"
var d = '\''
var e = '"'
var b = `raw // m805
still raw`
var f = "x" // see t480
/* don't */ var q = 1 // f123
EOF
  local leak_err
  leak_err="$(printf 'internal/leak.go\n' | scan_reference "" 2>&1 >/dev/null || true)"
  if [ "$(printf '%s\n' "$leak_err" | grep -c '^  ')" -ne 2 ] \
    || ! printf '%s\n' "$leak_err" | grep -qxF "  internal/leak.go:8 -> 't480'" \
    || ! printf '%s\n' "$leak_err" | grep -qxF "  internal/leak.go:9 -> 'f123'"; then
    echo "self-test FAIL: string/rune/raw lexical state leaked into comment detection:" >&2
    printf '%s\n' "$leak_err" >&2; fails=1
  fi

  printf 'package x\n\n// see g815\n' > internal/known.go
  local known_err known_rc=0
  known_err="$(printf 'internal/known.go\n' | scan_reference "" 2>&1 >/dev/null)" || known_rc=$?
  if [ "$known_rc" -eq 0 ] || ! printf '%s\n' "$known_err" | grep -qxF "  internal/known.go:3 -> 'g815'"; then
    echo "self-test FAIL: an id comment must fail naming path, source line and token" >&2; fails=1
  fi

  printf 'runs on i386 and I386 hosts\n' > docs/arch.md
  cp docs/arch.md docs/other.md
  printf 'docs/arch.md\ti386\n' > allow-arch
  printf 'docs/Arch.md\ti386\n' > allow-arch-case
  check_case fail "an unallowlisted i386 in a doc" docs/arch.md
  check_case pass "an exact doc-path entry must permit i386 in any case" docs/arch.md "$tmp/allow-arch"
  check_case fail "a doc entry must not permit the token in another file" docs/other.md "$tmp/allow-arch"
  check_case fail "a doc entry whose path differs only in case must not match" docs/arch.md "$tmp/allow-arch-case"

  printf 'see tasks/index.md\n' > docs/path.md
  printf 'docs/path.md\ttasks/\n' > allow-path
  check_case fail "a withheld path must fail even with an allowlist entry" docs/path.md "$tmp/allow-path"

  if [ "$fails" -eq 0 ]; then
    echo "oss-reference-check: self-test passed"
  else
    echo "oss-reference-check: self-test FAILED" >&2
  fi
  return "$fails"
}

main() {
  if [ "${1:-}" = "--self-test" ]; then
    run_self_test
    exit $?
  fi
  cd "$repo_root"
  if "$repo_root/scripts/oss-shipping-files.sh" | scan_reference "$allow_default"; then
    exit 0
  fi
  echo "oss-reference-check: remove the reference, or (if an audited requirement-named Go" >&2
  echo "identifier or test diagnostic, or an id-shaped token that is not a task or ADR id," >&2
  echo "such as i386) add a 'path<TAB>match' line to .oss-reference-allow: the path is" >&2
  echo "matched exactly, the token case-insensitively. Withheld paths cannot be allowlisted." >&2
  exit 1
}

main "$@"
