#!/usr/bin/env bash
#
# End-to-end test for the ebfw binary. Runs the agent on the host, generates
# real traffic with curl, and asserts what it captured. Covers:
#   - domain monitoring   (DNS)
#   - ssl monitoring      (TLS SNI)
#   - path inspection     (HTTP plaintext path + HTTPS path via SSL_write uprobe)
#   - header inspection   (EBFW_INSPECT_HEADERS)
#   - internal filtering  (an excluded domain must NOT appear)
#   - enforcement         (a denied CIDR's connection is dropped; log mode annotates)
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
metrics="$(mktemp)"
jlog="$(mktemp)"
cleanup() {
  kill "${AGENT:-}" "${JAGENT:-}" "${GAGENT:-}" "${EAGENT:-}" "${DAGENT:-}" "${LAGENT:-}" 2>/dev/null
  wait "${AGENT:-}" "${JAGENT:-}" "${GAGENT:-}" "${EAGENT:-}" "${DAGENT:-}" "${LAGENT:-}" 2>/dev/null
  rm -f "$log" "$cfg" "$metrics" "$jlog" "${glog:-}" \
        "${epol:-}" "${elog:-}" "${emetrics:-}" "${dpol:-}" "${dlog:-}" "${dmetrics:-}" \
        "${lpol:-}" "${llog:-}"
  rm -rf "${gotmp:-}"
}
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
# The packet monitor parses both IPv4 and IPv6. We exercise each explicitly with
# curl -4 / -6 so the assertions are deterministic on dual-stack hosts.
curl -4 --http1.1 -s -o /dev/null --max-time 10 -H "$HDR" "http://${SHOWN}/e2e/http-path"   || true
curl -4 --http1.1 -s -o /dev/null --max-time 10 -H "$HDR" "https://${SHOWN}/e2e/https-path" || true
curl -4          -s -o /dev/null --max-time 10 -H "$HDR" "https://${SHOWN}/e2e/h2-path"    || true  # HTTP/2 (curl default)
curl -4 --http1.1 -s -o /dev/null --max-time 10           "https://${HIDDEN}/e2e/should-be-filtered" || true

# IPv6 packet path. GitHub-hosted runners have no IPv6 egress, so gate on a real
# v6 reachability probe and skip the v6 assertions when it fails. Plaintext HTTP
# is captured ONLY by the eBPF packet parser (the SSL_write uprobe is HTTPS-only),
# so a curl -6 plaintext path showing up is decisive proof the v6 parser works.
HAVE_V6=0
if curl -6 -s -o /dev/null --max-time 6 "https://${SHOWN}/" 2>/dev/null; then
  HAVE_V6=1
  echo "# IPv6 egress available — exercising the v6 packet path"
  curl -6 --http1.1 -s -o /dev/null --max-time 10 -H "$HDR" "http://${SHOWN}/e2e/http6-path"   || true
  curl -6 --http1.1 -s -o /dev/null --max-time 10 -H "$HDR" "https://${SHOWN}/e2e/https6-path" || true
else
  echo "# IPv6 egress unavailable — skipping v6 packet-path checks"
fi
sleep 2

echo "# scraping metrics (:9090)"
curl -s --max-time 5 "http://127.0.0.1:9090/metrics" > "$metrics" || true

kill "$AGENT" 2>/dev/null; wait "$AGENT" 2>/dev/null; AGENT=""

echo "# ---- captured output ----"
cat "$log"
echo "# -------------------------"

fail=0
present()    { if grep -qE "$2" "$log"; then echo "PASS  $1"; else echo "FAIL  $1   [missing: $2]"; fail=1; fi; }
absent()     { if grep -qE "$2" "$log"; then echo "FAIL  $1   [unexpected: $2]"; fail=1; else echo "PASS  $1"; fi; }
present_in() { if grep -qE "$3" "$1"; then echo "PASS  $2"; else echo "FAIL  $2   [missing: $3 in $1]"; fail=1; fi; }
skip()       { echo "SKIP  $1"; }

present "domain (DNS)"              "DNS .* ${SHOWN} "
present "ssl (TLS SNI)"             "TLS .* ${SHOWN} "
present "http path (plaintext)"     "HTTP .* GET ${SHOWN}/e2e/http-path"
present "path inspection (HTTPS/1.1)" "HTTPS .* GET ${SHOWN}/e2e/https-path"
present "path inspection (HTTP/2)"    "HTTPS .* GET ${SHOWN}/e2e/h2-path"
present "header inspection"           "${HDR}"
absent  "internal filter (${HIDDEN})" "${HIDDEN}"
present_in "$metrics" "metrics endpoint (ebfw_events_total)" "ebfw_events_total"

# IPv6 packet-path assertions (only when v6 egress was available).
if [ "$HAVE_V6" -eq 1 ]; then
  # Decisive: plaintext HTTP is packet-parser-only, and we sent it over v6 only.
  present "http path over IPv6 (plaintext, packet-path)" "HTTP .* GET ${SHOWN}/e2e/http6-path"
  # A v6 source address (colon-separated) in any event line proves v6 decoding.
  present "IPv6 address decoded in events" "^[A-Z]+ +[0-9a-fA-F]*:[0-9a-fA-F:]+:"
else
  skip "http path over IPv6 (plaintext, packet-path) — no IPv6 egress"
  skip "IPv6 address decoded in events — no IPv6 egress"
fi

# ---- JSON output smoke (separate pass; bare host has no pod, so we only assert
#      structure, not attribution) ----
echo "# ---- JSON output smoke ----"
EBFW_CONFIG="$cfg" EBFW_INSPECT_PATHS=true EBFW_OUTPUT=json EBFW_METRICS_ADDR= \
  "$BIN" > "$jlog" 2>&1 &
JAGENT=$!
sleep 3
curl -4 --http1.1 -s -o /dev/null --max-time 10 "https://${SHOWN}/e2e/json-path" || true
sleep 2
kill "$JAGENT" 2>/dev/null; wait "$JAGENT" 2>/dev/null; JAGENT=""

present_in "$jlog" "json output (https path)" '"kind":"https".*"path":"/e2e/json-path"'
if command -v python3 >/dev/null 2>&1; then
  if grep '^{' "$jlog" | python3 -c 'import sys,json;[json.loads(l) for l in sys.stdin]' 2>/dev/null; then
    echo "PASS  json output (lines parse as JSON)"
  else
    echo "FAIL  json output (lines parse as JSON)"; fail=1
  fi
fi

# ---- Go native crypto/tls capture (statically-linked TLS) ----
# curl links OpenSSL's libssl, which the SSL_write uprobe hooks directly. A Go
# net/http client instead links crypto/tls *statically* into the binary and
# never calls SSL_write, so its request is invisible to the OpenSSL uprobe — it
# is captured ONLY via the crypto/tls.(*Conn).Write uprobe. A Go request showing
# up with its host, path, and header is therefore decisive proof that we recover
# L7 detail from a statically-linked-TLS binary before encryption.
#
# The client lives in test/fixtures/gotls-client and is compiled via its own
# Dockerfile, so the test never assumes a host Go toolchain — only Docker, which
# CI and the dev box already have. The resulting static binary runs on the host
# under the agent. With no Docker (or a build failure) the checks self-skip.
echo "# ---- Go crypto/tls capture ----"
GOTLS_PATH="/e2e/go-tls-path"
GOTLS_HDR_NAME="X-Ebfw-Gotls"
GOTLS_HDR_VAL="e2e-$$"
GOTLS_DIR="$(dirname "$0")/fixtures/gotls-client"
gobin=""
gotmp=""
if command -v docker >/dev/null 2>&1; then
  gotmp="$(mktemp -d)"
  echo "# building Go client from $GOTLS_DIR"
  if docker build --target bin --output "type=local,dest=$gotmp" "$GOTLS_DIR" >/dev/null 2>&1 \
     && [ -x "$gotmp/gotls-client" ]; then
    gobin="$gotmp/gotls-client"
  else
    echo "# Go client build failed (image pull or compile); go-tls checks will skip"
  fi
fi

if [ -n "$gobin" ] && [ -x "$gobin" ]; then
  glog="$(mktemp)"
  EBFW_CONFIG="$cfg" EBFW_INSPECT_PATHS=true EBFW_INSPECT_HEADERS=true EBFW_METRICS_ADDR= \
    "$BIN" > "$glog" 2>&1 &
  GAGENT=$!
  sleep 3   # allow cgroup attach
  # The client waits internally (> the ~1s discovery interval) so the uprobe
  # attaches to it before it sends, then issues a single request and exits.
  "$gobin" "https://${SHOWN}${GOTLS_PATH}" "$GOTLS_HDR_NAME" "$GOTLS_HDR_VAL" || true
  sleep 2   # let the captured event drain
  kill "$GAGENT" 2>/dev/null; wait "$GAGENT" 2>/dev/null; GAGENT=""
  echo "# ---- go-tls output ----"; cat "$glog"; echo "# -------------------------"
  present_in "$glog" "go crypto/tls: uprobe attached"        "attached crypto/tls.*Write uprobe"
  present_in "$glog" "go crypto/tls: host+path pre-encrypt"  "HTTPS .* GET ${SHOWN}${GOTLS_PATH}"
  present_in "$glog" "go crypto/tls: header pre-encrypt"     "${GOTLS_HDR_NAME}: ${GOTLS_HDR_VAL}"
else
  skip "go crypto/tls: uprobe attached — no Docker"
  skip "go crypto/tls: host+path pre-encrypt — no Docker"
  skip "go crypto/tls: header pre-encrypt — no Docker"
fi

# ---- enforcement: deny a CIDR; the connection must be dropped ----
# Cloudflare's 1.1.1.0/24 is reliably reachable, so a timeout is meaningful, and
# we additionally assert the agent logged the deny + bumped the drop metric (so
# the test proves the datapath decision even if the target were unreachable).
echo "# ---- enforcement (deny CIDR) ----"
DENY_IP="${DENY_IP:-1.1.1.1}"
DENY_CIDR="${DENY_CIDR:-1.1.1.0/24}"
epol="$(mktemp)"; elog="$(mktemp)"; emetrics="$(mktemp)"
cat > "$epol" <<YAML
defaultAction: Allow
rules:
  - name: e2e-block
    action: Deny
    match:
      cidrs: ["${DENY_CIDR}"]
YAML
EBFW_CONFIG="$cfg" EBFW_INSPECT_PATHS=false EBFW_ENFORCE_MODE=enforce \
  EBFW_POLICY="$epol" EBFW_METRICS_ADDR=:9091 \
  "$BIN" > "$elog" 2>&1 &
EAGENT=$!
sleep 3   # allow cgroup attach + map programming

allowed_ok=0
curl -4 -s -o /dev/null --max-time 8 "https://${SHOWN}/" && allowed_ok=1   # baseline: egress still works
denied_rc=0
curl -4 -s -o /dev/null --max-time 5 "https://${DENY_IP}/" || denied_rc=$?  # SYN dropped -> nonzero
curl -s --max-time 5 "http://127.0.0.1:9091/metrics" > "$emetrics" || true
sleep 1
kill "$EAGENT" 2>/dev/null; wait "$EAGENT" 2>/dev/null; EAGENT=""

echo "# ---- enforcement output ----"; cat "$elog"; echo "# -------------------------"
if [ "$allowed_ok" -eq 1 ]; then echo "PASS  enforce: allowed egress still works"; else echo "FAIL  enforce: allowed egress was blocked"; fail=1; fi
if [ "$denied_rc" -ne 0 ]; then echo "PASS  enforce: denied connection failed (rc=$denied_rc)"; else echo "FAIL  enforce: denied connection succeeded"; fail=1; fi
present_in "$elog"     "enforce: deny logged"  "${DENY_IP}:443.*action=Deny"
present_in "$emetrics" "enforce: drops metric" "ebfw_enforcement_drops_total"

# ---- enforcement: block a DOMAIN via DNS→IP learning ----
# Deny a domain; the agent learns its A records from the DNS answer and programs
# the resolved IPs, so the next connection is dropped. The first request primes
# the learner (its connect races the map write); the retry must be blocked.
echo "# ---- enforcement (deny domain) ----"
DOMAIN_DENY="${DOMAIN_DENY:-example.net}"
dpol="$(mktemp)"; dlog="$(mktemp)"; dmetrics="$(mktemp)"
cat > "$dpol" <<YAML
defaultAction: Allow
rules:
  - name: e2e-block-domain
    action: Deny
    match:
      domains: ["${DOMAIN_DENY}"]
YAML
EBFW_CONFIG="$cfg" EBFW_INSPECT_PATHS=false EBFW_ENFORCE_MODE=enforce \
  EBFW_POLICY="$dpol" EBFW_METRICS_ADDR=:9092 \
  "$BIN" > "$dlog" 2>&1 &
DAGENT=$!
sleep 3

curl -4 -s -o /dev/null --max-time 6 "https://${DOMAIN_DENY}/" || true   # prime: learn the A records
sleep 2
denied_dom_rc=0
curl -4 -s -o /dev/null --max-time 6 "https://${DOMAIN_DENY}/" || denied_dom_rc=$?  # now blocked
allowed_dom_ok=0
curl -4 -s -o /dev/null --max-time 8 "https://${SHOWN}/" && allowed_dom_ok=1        # unrelated domain still works
curl -s --max-time 5 "http://127.0.0.1:9092/metrics" > "$dmetrics" || true
sleep 1
kill "$DAGENT" 2>/dev/null; wait "$DAGENT" 2>/dev/null; DAGENT=""

echo "# ---- domain-enforcement output ----"; cat "$dlog"; echo "# -------------------------"
if [ "$allowed_dom_ok" -eq 1 ]; then echo "PASS  enforce: unrelated domain still works"; else echo "FAIL  enforce: unrelated domain blocked"; fail=1; fi
if [ "$denied_dom_rc" -ne 0 ]; then echo "PASS  enforce: denied domain failed (rc=$denied_dom_rc)"; else echo "FAIL  enforce: denied domain succeeded (DNS learning)"; fail=1; fi
# A domain-blocked flow only produces a CONNECT (the SYN is dropped, so no TLS
# event with the SNI), so the kernel verdict — not a rule name — is what's known.
present_in "$dlog"     "enforce: domain deny logged" "CONNECT.*action=Deny"
present_in "$dmetrics" "enforce: dns-learned metric" "ebfw_dns_learned_ips [1-9]"

# ---- log mode: annotate the verdict but DO NOT drop ----
# Same deny rule as the enforce test, but EBFW_ENFORCE_MODE=log. The connection
# must SUCCEED (no datapath) yet be annotated action=Deny. -k so a reachable
# endpoint returns rc=0 (we're testing reachability, not the cert).
echo "# ---- log mode (annotate, no drop) ----"
lpol="$(mktemp)"; llog="$(mktemp)"
cat > "$lpol" <<YAML
defaultAction: Allow
rules:
  - name: e2e-log-block
    action: Deny
    match:
      cidrs: ["${DENY_CIDR}"]
YAML
EBFW_CONFIG="$cfg" EBFW_INSPECT_PATHS=false EBFW_ENFORCE_MODE=log \
  EBFW_POLICY="$lpol" EBFW_METRICS_ADDR=:9093 \
  "$BIN" > "$llog" 2>&1 &
LAGENT=$!
sleep 3
log_rc=0
curl -4 -sS -k -o /dev/null --max-time 6 "https://${DENY_IP}/" || log_rc=$?  # must NOT be dropped
sleep 1
kill "$LAGENT" 2>/dev/null; wait "$LAGENT" 2>/dev/null; LAGENT=""

if [ "$log_rc" -eq 0 ]; then echo "PASS  log mode: denied flow NOT dropped (connection succeeded)"; else echo "FAIL  log mode: connection was dropped (rc=$log_rc)"; fail=1; fi
present_in "$llog" "log mode: verdict annotated" "${DENY_IP}:443.*action=Deny rule=e2e-log-block"

echo "# -------------------------"
if [ "$fail" -eq 0 ]; then echo "RESULT: ALL PASS"; else echo "RESULT: FAILURES"; fi
exit "$fail"
