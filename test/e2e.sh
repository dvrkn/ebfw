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
  kill "${AGENT:-}" "${JAGENT:-}" "${EAGENT:-}" "${DAGENT:-}" "${LAGENT:-}" 2>/dev/null
  wait "${AGENT:-}" "${JAGENT:-}" "${EAGENT:-}" "${DAGENT:-}" "${LAGENT:-}" 2>/dev/null
  rm -f "$log" "$cfg" "$metrics" "$jlog" \
        "${epol:-}" "${elog:-}" "${emetrics:-}" "${dpol:-}" "${dlog:-}" "${dmetrics:-}" \
        "${lpol:-}" "${llog:-}"
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
# Force IPv4 (-4): the packet monitor is IPv4-only, so on dual-stack hosts the
# TLS/HTTP/CONNECT checks need IPv4 egress (the uprobe is IP-agnostic regardless).
curl -4 --http1.1 -s -o /dev/null --max-time 10 -H "$HDR" "http://${SHOWN}/e2e/http-path"   || true
curl -4 --http1.1 -s -o /dev/null --max-time 10 -H "$HDR" "https://${SHOWN}/e2e/https-path" || true
curl -4          -s -o /dev/null --max-time 10 -H "$HDR" "https://${SHOWN}/e2e/h2-path"    || true  # HTTP/2 (curl default)
curl -4 --http1.1 -s -o /dev/null --max-time 10           "https://${HIDDEN}/e2e/should-be-filtered" || true
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

present "domain (DNS)"              "DNS .* ${SHOWN} "
present "ssl (TLS SNI)"             "TLS .* ${SHOWN} "
present "http path (plaintext)"     "HTTP .* GET ${SHOWN}/e2e/http-path"
present "path inspection (HTTPS/1.1)" "HTTPS .* GET ${SHOWN}/e2e/https-path"
present "path inspection (HTTP/2)"    "HTTPS .* GET ${SHOWN}/e2e/h2-path"
present "header inspection"           "${HDR}"
absent  "internal filter (${HIDDEN})" "${HIDDEN}"
present_in "$metrics" "metrics endpoint (ebfw_events_total)" "ebfw_events_total"

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
