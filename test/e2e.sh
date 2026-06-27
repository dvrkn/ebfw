#!/usr/bin/env bash
#
# End-to-end test for the ebfw binary. Runs the agent on the host, generates
# real traffic with curl, and asserts what it captured. Covers:
#   - domain monitoring   (DNS)
#   - ssl monitoring      (TLS SNI)
#   - path inspection     (HTTP plaintext path + HTTPS path via SSL_write uprobe)
#   - header inspection   (EBFW_INSPECT_HEADERS)
#   - internal filtering  (an excluded domain must NOT appear)
#
# Requires: Linux, root (eBPF), curl with OpenSSL, outbound network.
# Usage: sudo ./test/e2e.sh [path-to-ebfw-binary]    (default ./out/ebfw)

set -uo pipefail

BIN="${BIN:-${1:-./out/ebfw}}"
SHOWN="${SHOWN:-example.com}"     # external domain that must be reported
HIDDEN="${HIDDEN:-example.org}"   # external domain excluded by config (must NOT appear)
HDR="X-Ebfw-Test: e2e-$$"

log="$(mktemp)"
cfg="$(mktemp)"
cleanup() { kill "${AGENT:-}" 2>/dev/null; wait "${AGENT:-}" 2>/dev/null; rm -f "$log" "$cfg"; }
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "ERROR: must run as root (eBPF)"; exit 1; }
[ -x "$BIN" ] || { echo "ERROR: binary not found/executable: $BIN"; exit 1; }
command -v curl >/dev/null || { echo "ERROR: curl required"; exit 1; }

cat > "$cfg" <<YAML
cgroup: /sys/fs/cgroup
exclude:
  cidrs: [127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16]
  domainSuffixes: [cluster.local, svc, local, in-addr.arpa, ip6.arpa, ${HIDDEN}]
YAML

echo "# starting agent: $BIN"
EBFW_CONFIG="$cfg" EBFW_INSPECT_PATHS=true EBFW_INSPECT_HEADERS=true \
  "$BIN" > "$log" 2>&1 &
AGENT=$!
sleep 3   # allow cgroup attach + libssl uprobe discovery

echo "# generating traffic"
curl --http1.1 -s -o /dev/null --max-time 10 -H "$HDR" "http://${SHOWN}/e2e/http-path"   || true
curl --http1.1 -s -o /dev/null --max-time 10 -H "$HDR" "https://${SHOWN}/e2e/https-path" || true
curl          -s -o /dev/null --max-time 10 -H "$HDR" "https://${SHOWN}/e2e/h2-path"    || true  # HTTP/2 (curl default)
curl --http1.1 -s -o /dev/null --max-time 10           "https://${HIDDEN}/e2e/should-be-filtered" || true
sleep 2

kill "$AGENT" 2>/dev/null; wait "$AGENT" 2>/dev/null; AGENT=""

echo "# ---- captured output ----"
cat "$log"
echo "# -------------------------"

fail=0
present() { if grep -qE "$2" "$log"; then echo "PASS  $1"; else echo "FAIL  $1   [missing: $2]"; fail=1; fi; }
absent()  { if grep -qE "$2" "$log"; then echo "FAIL  $1   [unexpected: $2]"; fail=1; else echo "PASS  $1"; fi; }

present "domain (DNS)"              "DNS .* ${SHOWN} "
present "ssl (TLS SNI)"             "TLS .* ${SHOWN} "
present "http path (plaintext)"     "HTTP .* GET ${SHOWN}/e2e/http-path"
present "path inspection (HTTPS/1.1)" "HTTPS .* GET ${SHOWN}/e2e/https-path"
present "path inspection (HTTP/2)"    "HTTPS .* GET ${SHOWN}/e2e/h2-path"
present "header inspection"           "${HDR}"
absent  "internal filter (${HIDDEN})" "${HIDDEN}"

echo "# -------------------------"
if [ "$fail" -eq 0 ]; then echo "RESULT: ALL PASS"; else echo "RESULT: FAILURES"; fi
exit "$fail"
