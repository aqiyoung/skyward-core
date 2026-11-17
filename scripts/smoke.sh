#!/usr/bin/env bash
# End-to-end smoke test: drive a real connection through both inbounds and
# verify the REST controller. Usage: scripts/smoke.sh ./target/release/skyward-core
set -euo pipefail

BIN="${1:?usage: smoke.sh <path-to-skyward-core>}"
if [[ ! -x "$BIN" ]]; then
  echo "binary not found or not executable: $BIN" >&2
  exit 1
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$ROOT/tests/smoke/config.yaml"
TARGET_PORT=18081

TMP="$(mktemp -d)"
CORE_PID=""
HTTP_PID=""
cleanup() {
  [[ -n "$CORE_PID" ]] && kill "$CORE_PID" 2>/dev/null || true
  [[ -n "$HTTP_PID" ]] && kill "$HTTP_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "SKYWARD_SMOKE_OK" > "$TMP/index.html"
(
  cd "$TMP"
  python3 -m http.server "$TARGET_PORT" --bind 127.0.0.1 > "$TMP/server.log" 2>&1
) &
HTTP_PID=$!

"$BIN" -c "$CONFIG" > "$TMP/core.log" 2>&1 &
CORE_PID=$!

# Wait for the target HTTP server first: the proxy resolves connections as
# soon as the controller is up, so a slow target would cause connection resets.
target_ready=0
for _ in $(seq 1 40); do
  if curl -s --noproxy '*' --max-time 1 "http://127.0.0.1:${TARGET_PORT}/index.html" >/dev/null 2>&1; then
    target_ready=1
    break
  fi
  sleep 0.25
done
if [[ "$target_ready" != 1 ]]; then
  echo "target http server did not become ready" >&2
  cat "$TMP/server.log" >&2 || true
  exit 1
fi

# Wait for the controller to come up.
ready=0
for _ in $(seq 1 40); do
  if curl -s --noproxy '*' --max-time 1 http://127.0.0.1:19090/version >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.25
done
if [[ "$ready" != 1 ]]; then
  echo "core did not become ready" >&2
  cat "$TMP/core.log" >&2
  exit 1
fi

fail() {
  echo "FAIL $1" >&2
  echo "--- core.log ---" >&2
  cat "$TMP/core.log" >&2 || true
  echo "--- server.log ---" >&2
  cat "$TMP/server.log" >&2 || true
  exit 1
}

expect() {
  local label="$1" got="$2"
  if [[ "$got" != "SKYWARD_SMOKE_OK" ]]; then
    echo "FAIL $label: got '$got'" >&2
    echo "--- core.log ---" >&2
    cat "$TMP/core.log" >&2 || true
    echo "--- server.log ---" >&2
    cat "$TMP/server.log" >&2 || true
    exit 1
  fi
  echo "PASS $label"
}

# no_proxy may be set in the environment; clear it so curl actually uses the
# explicitly supplied proxy. Use a hostname in the URL to exercise domain rules.
unset no_proxy NO_PROXY http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy || true

got="$(curl -s --max-time 5 --socks5-hostname 127.0.0.1:17891 \
  "http://localhost:${TARGET_PORT}/index.html")" || fail "socks5 curl exited $?"
expect "socks5 inbound" "$got"

got="$(curl -s --max-time 5 -x "http://127.0.0.1:17890" \
  "http://localhost:${TARGET_PORT}/index.html")" || fail "http curl exited $?"
expect "http inbound" "$got"

curl -s --max-time 5 http://127.0.0.1:19090/traffic | grep -q '"up"' \
  && echo "PASS /traffic" || { echo "FAIL /traffic" >&2; exit 1; }
curl -s --max-time 5 http://127.0.0.1:19090/proxies | grep -q 'DIRECT' \
  && echo "PASS /proxies" || { echo "FAIL /proxies" >&2; exit 1; }
curl -s --max-time 5 http://127.0.0.1:19090/connections | grep -q 'connections' \
  && echo "PASS /connections" || { echo "FAIL /connections" >&2; exit 1; }

echo "ALL SMOKE CHECKS PASSED"
