#!/usr/bin/env bash
# Authentic Simvader demo: drives the REAL binary + a vulnerable mock server over HTTP and narrates
# the result of each call. Every block below is produced by Simvader, not scripted output.
#
# Prereqs (build once):
#   cargo build --release
#   cargo build --release --example mock_mcp_server
# Then run:  ./scripts/demo.sh        (or record it: vhs demo.tape)
set -euo pipefail

# ---- locate binaries (repo target, or the WSL split-target used during development) ----
find_bin() {
  for p in "target/release/$1" "$HOME/simvader-target/release/$1"; do
    [ -x "$p" ] && { echo "$p"; return; }
  done
  echo ""; return 1
}
BIN="$(find_bin simvader)"
MOCK="$(find_bin examples/mock_mcp_server)"
if [ -z "$BIN" ] || [ -z "$MOCK" ]; then
  echo "build first:  cargo build --release && cargo build --release --example mock_mcp_server" >&2
  exit 1
fi

# ---- colors (respect NO_COLOR) ----
if [ -n "${NO_COLOR:-}" ]; then
  G= R= Y= B= D= X=
else
  G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; B=$'\033[1m'; D=$'\033[2m'; X=$'\033[0m'
fi

PORT=8791
URL="http://127.0.0.1:${PORT}/mcp"
AUDIT="$(mktemp)"

# ---- start the gateway in front of the vulnerable mock server ----
"$BIN" run --http "127.0.0.1:${PORT}" --audit-log "$AUDIT" -- "$MOCK" >/dev/null 2>&1 &
SV=$!
trap 'kill $SV 2>/dev/null; rm -f "$AUDIT"' EXIT
sleep 0.8

post() { curl -s -H content-type:application/json -X POST "$URL" -d "$1"; }
render() {  # $1 = the JSON-RPC response; prints a one-line verdict
  python3 - "$G" "$R" "$B" "$D" "$X" "$1" <<'PY'
import sys, json
g, r, b, d, x = sys.argv[1:6]
resp = json.loads(sys.argv[6] or "{}")
res = resp.get("result", {})
content = res.get("content") or [{}]
text = content[0].get("text", "")
if res.get("isError"):
    why = text.split("potential ", 1)[-1].split(" via parameter", 1)[0]
    print(f"      {r}{b}BLOCKED{x}  {r}{why}{x}")
else:
    print(f"      {g}allowed{x}  {d}-> {text}{x}")
PY
}
call() {  # $1 human label   $2 json body   $3 optional note
  printf "   %s>%s %s" "$D" "$X" "$1"
  [ -n "${3:-}" ] && printf "   %s<- %s%s" "$Y" "$3" "$X"
  printf "\n"
  sleep 0.5
  render "$(post "$2")"
  sleep 0.8
}

# ---- session ----
printf "\n  %ssimvader%s  virtual patching for MCP\n\n" "$B" "$X"
post '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}' >/dev/null
NTOOLS=$(post '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | grep -o '"name"' | wc -l)
printf "  %s* client connected -> %s tools behind the gateway%s\n\n" "$D" "$NTOOLS" "$X"

call "fetch(url=https://news.google.com)" \
     '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mock_mcp_server__fetch","arguments":{"url":"https://news.google.com"}}}'

call "fetch(url=http://169.254.169.254/latest/meta-data/)" \
     '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mock_mcp_server__fetch","arguments":{"url":"http://169.254.169.254/latest/meta-data/"}}}' \
     "prompt-injected SSRF"

call "run_command(cmd=ls; cat /etc/passwd)" \
     '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mock_mcp_server__run_command","arguments":{"command":"ls; cat /etc/passwd"}}}' \
     "command injection"

call "run_command(cmd=ls -la)" \
     '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"mock_mcp_server__run_command","arguments":{"command":"ls -la"}}}'

printf "\n  %saudit log%s (one JSON line per call, ship it anywhere):\n" "$B" "$X"
sleep 0.4
grep '"blocked"' "$AUDIT" | while IFS= read -r line; do printf "   %s%s%s\n" "$D" "$line" "$X"; done
sleep 1.0
printf "\n  %sBlocked at the gateway. No server patch required.%s\n\n" "$G" "$X"
sleep 0.6
