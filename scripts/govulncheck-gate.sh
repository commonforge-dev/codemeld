#!/usr/bin/env bash
# Release vulnerability gate: govulncheck plus the expiring exceptions file named by
# CODEMELD_VULN_EXCEPTIONS (unset or missing: no exceptions).
set -euo pipefail

die() { echo "govulncheck-gate: $*" >&2; exit 1; }

json=""
if [ "$#" -eq 2 ] && [ "$1" = --json ]; then
  json="$2"
elif [ "$#" -ne 0 ]; then
  echo "usage: govulncheck-gate.sh [--json <govulncheck-json-file>]" >&2
  exit 2
fi

command -v jq >/dev/null || die "jq is required"

today="$(date +%F)"

exc_file="${CODEMELD_VULN_EXCEPTIONS:-}"
exc=""
if [ -n "$exc_file" ] && [ -e "$exc_file" ]; then
  exc="$(cat -- "$exc_file")" || die "cannot read exceptions file $exc_file"
fi

expiry_of() {
  jq -nr --arg d "$1" '
    def ymd: strftime("%Y-%m-%d");
    try ($d | strptime("%Y-%m-%d") | mktime) catch null
    | if . == null or ymd != $d then empty else . + 7 * 86400 | ymd end'
}

declare -A exc_date=() exc_expiry=() exc_reason=() exc_line=()
exc_ids=()
errors=0
n=0
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
  if ! [[ "$line" =~ ^(GO-[0-9]{4}-[0-9]{4,})[[:space:]]+([0-9]{4}-[0-9]{2}-[0-9]{2})[[:space:]]+(.*[^[:space:]].*)$ ]]; then
    echo "$exc_file:$n: malformed exception line (want: GO-YYYY-NNNN YYYY-MM-DD reason)" >&2
    errors=1
    continue
  fi
  id="${BASH_REMATCH[1]}" d="${BASH_REMATCH[2]}" reason="${BASH_REMATCH[3]}"
  if [ -n "${exc_line[$id]:-}" ]; then
    echo "$exc_file:$n: exception $id repeats line ${exc_line[$id]}" >&2
    errors=1
    continue
  fi
  exc_line[$id]=$n
  expiry="$(expiry_of "$d")"
  if [ -z "$expiry" ]; then
    echo "$exc_file:$n: $d is not a calendar date" >&2
    errors=1
    continue
  fi
  if [[ "$d" > "$today" ]]; then
    echo "$exc_file:$n: exception $id is dated $d, after today $today" >&2
    errors=1
    continue
  fi
  exc_ids+=("$id")
  exc_date[$id]="$d" exc_expiry[$id]="$expiry" exc_reason[$id]="$reason"
done <<<"$exc"
[ "$errors" -eq 0 ] || die "invalid exceptions file $exc_file"

input="$json"
if [ -z "$json" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf -- "$tmp"' EXIT
  input="$tmp/scan.json"
  rc=0
  govulncheck -format json ./... >"$input" || rc=$?
  [ "$rc" -eq 0 ] || die "govulncheck exited $rc"
fi

# shellcheck disable=SC2016
prog='
def need(c; m): if c then . else error(m) end;
def nestr: type == "string" and length > 0;
def optstr(k): (has(k) | not) or (.[k] | type == "string");
[inputs]
| need(length > 0; "empty govulncheck stream")
| need(.[0] | type == "object" and (.config | type) == "object"; "govulncheck stream does not start with a config message")
| .[0].config as $c
| need($c.protocol_version == "v1.0.0"; "unsupported protocol_version \($c.protocol_version | tojson)")
| need($c.scan_mode == "source"; "unsupported scan_mode \($c.scan_mode | tojson)")
| need($c.scan_level == "symbol"; "unsupported scan_level \($c.scan_level | tojson)")
| [.[]
   | need(type == "object"; "govulncheck message is not an object")
   | select(has("finding")) | .finding
   | need(type == "object"; "finding is not an object")
   | need(.osv | nestr; "finding without an osv ID")
   | .osv as $id
   | need((.trace | type) == "array" and (.trace | length) > 0; "finding \($id) has no trace")
   | need(all(.trace[]; type == "object" and (.module | nestr) and optstr("package") and optstr("function"));
       "finding \($id) has an invalid trace frame")
   | select(any(.trace[]; (.function // "") != "")) | $id]
| unique[]'

ids="$(jq -nr "$prog" <"$input")" || die "cannot read or parse govulncheck JSON${json:+ from $json}"

failed=0
declare -A found=()
while IFS= read -r id; do
  [ -n "$id" ] || continue
  found[$id]=1
  if [ -z "${exc_date[$id]:-}" ]; then
    echo "vulnerability $id is reachable: https://pkg.go.dev/vuln/$id"
    failed=1
  elif [[ "$today" > "${exc_expiry[$id]}" ]]; then
    echo "exception $id expired ${exc_expiry[$id]}. Allowed on ${exc_date[$id]} because: ${exc_reason[$id]}. Review it, then re-date the line or remove it."
    failed=1
  else
    echo "$id allowed by exception (added ${exc_date[$id]}, expires ${exc_expiry[$id]}): ${exc_reason[$id]}"
  fi
done <<<"$ids"

for id in "${exc_ids[@]}"; do
  [ -n "${found[$id]:-}" ] || echo "unused exception $id: remove it"
done

[ "$failed" -eq 0 ] || die "reachable vulnerabilities without an active exception"
[ -n "$ids" ] || echo "govulncheck: no reachable vulnerabilities"
