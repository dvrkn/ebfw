#!/usr/bin/env bash
#
# Kubernetes end-to-end test: deploy ebfw to a throwaway k3d cluster (JSON output)
# and assert it attributes real pod egress (DNS / TLS / HTTP / HTTPS) to the
# originating pod and serves Prometheus metrics. Event fields are checked with jq.
#
# This covers the whole Stage-1 path the bare-host e2e (test/e2e.sh) cannot:
# cgroup-id -> pod resolution and Kubernetes API enrichment (namespace/name).
#
# Builds the image itself via the repo Dockerfile (no local Go/clang needed).
# Requires: Linux, docker, k3d, kubectl, curl, jq.
#   ./test/k8s.sh          # create cluster, test, tear down
#   KEEP=1 ./test/k8s.sh   # leave the cluster up afterwards (debugging)

set -uo pipefail

CLUSTER="${CLUSTER:-ebfw-e2e}"
IMAGE="${IMAGE:-ebfw:e2e}"
SHOWN="${SHOWN:-example.com}"
NS="${NS:-ebfw}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fail=0
note() { echo "# $*"; }

cleanup() {
  if [ "$fail" -ne 0 ]; then
    echo "# ---- debug: ebfw pods + recent log ----"
    kubectl -n "$NS" get pods -o wide 2>&1 | tail -5
    kubectl -n "$NS" logs ds/ebfw --tail=40 2>&1 | tail -40
  fi
  if [ "${KEEP:-}" != "1" ]; then
    note "tearing down cluster $CLUSTER"
    k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
  else
    note "KEEP=1 — leaving cluster $CLUSTER up"
  fi
}
trap cleanup EXIT

for bin in docker k3d kubectl curl jq; do
  command -v "$bin" >/dev/null || { echo "ERROR: $bin required"; exit 1; }
done

# ── build image + cluster ───────────────────────────────────────────────────
note "building image $IMAGE (BPF + Go compiled inside)"
docker build -t "$IMAGE" "$ROOT" || { echo "ERROR: image build failed"; exit 1; }

note "creating k3d cluster $CLUSTER"
k3d cluster create "$CLUSTER" --wait || { echo "ERROR: cluster create failed"; exit 1; }

note "importing image into cluster"
k3d image import "$IMAGE" -c "$CLUSTER" || { echo "ERROR: image import failed"; exit 1; }

# ── deploy (point at our image; JSON output for jq assertions) ──────────────
manifest="$(mktemp)"
sed -e "s#image: ebfw:dev#image: ${IMAGE}#" \
    -e 's#output: "text"#output: "json"#' \
    "$ROOT/deploy/ebfw.yaml" > "$manifest"
note "deploying ebfw (JSON output)"
kubectl apply -f "$manifest" || { echo "ERROR: apply failed"; exit 1; }
rm -f "$manifest"
kubectl -n "$NS" rollout status ds/ebfw --timeout=120s || { echo "ERROR: ds not ready"; exit 1; }

# Wait for the pod informer to sync so events carry namespace/name.
note "waiting for pod informer to sync"
for _ in $(seq 1 30); do
  kubectl -n "$NS" logs ds/ebfw 2>/dev/null | grep -q "pod informer synced" && break
  sleep 1
done

note "starting probe pod"
kubectl run probe --image=nicolaka/netshoot --restart=Never --command -- sleep infinity || exit 1
kubectl wait --for=condition=Ready pod/probe --timeout=120s || { echo "ERROR: probe not ready"; exit 1; }

# Let the uprobe discovery loop (1s cadence) attach to the probe's libssl before
# we send HTTPS; otherwise the first request's SSL_write is missed.
note "waiting for SSL_write uprobe to attach to probe libssl"
sleep 6

# curl -4: the packet monitor is IPv4-only (the uprobe is IP-agnostic regardless).
note "generating traffic"
kubectl exec probe -- sh -c "
  curl -4 -s -o /dev/null --max-time 15 --http1.1 http://${SHOWN}/k8s/http-path   || true
  curl -4 -s -o /dev/null --max-time 15 --http1.1 https://${SHOWN}/k8s/https-path || true
  curl -4 -s -o /dev/null --max-time 15           https://${SHOWN}/k8s/h2-path     || true
" >/dev/null 2>&1 || true
sleep 4

# ── collect JSON events and assert fields with jq ───────────────────────────
events="$(mktemp)"
kubectl -n "$NS" logs ds/ebfw --tail=800 2>&1 | grep '^{' > "$events" || true

echo "# ---- attributed events (kind / target / pod) ----"
jq -rc 'select(.pod.name=="probe") | [.kind, (.domain // .path), "\(.pod.namespace)/\(.pod.name)"] | @tsv' \
  "$events" | sort -u | head -12
echo "# --------------------------------------------------"

# assert: at least one JSON event matches the jq boolean filter.
assert() { # <label> <jq-filter>
  if [ -n "$(jq -c "select($2)" "$events" 2>/dev/null | head -1)" ]; then
    echo "PASS  $1"
  else
    echo "FAIL  $1   [no event matching: $2]"; fail=1
  fi
}
pod='.pod.namespace=="default" and .pod.name=="probe"'
assert "DNS attributed to pod"   ".kind==\"dns\"   and .domain==\"${SHOWN}\"      and ${pod}"
assert "TLS attributed to pod"   ".kind==\"tls\"   and .domain==\"${SHOWN}\"      and ${pod}"
assert "HTTP attributed to pod"  ".kind==\"http\"  and .path==\"/k8s/http-path\"  and ${pod}"
assert "HTTPS attributed to pod" ".kind==\"https\" and .path==\"/k8s/https-path\" and ${pod}"
assert "pod metadata complete"   '.kind=="https" and .pod.uid!="" and .pod.container!="" and .pod.qos!="" and .pod.node!=""'

# ── metrics (hostNetwork -> reachable on the node IP) ───────────────────────
node_ip="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
metrics="$(mktemp)"
kubectl exec probe -- curl -s --max-time 10 "http://${node_ip}:9090/metrics" > "$metrics" 2>/dev/null || true
echo "# ---- ebfw metrics ----"
grep -E '^ebfw_' "$metrics" | grep -vE 'go_|process_' | head -12
echo "# ----------------------"
if grep -q 'ebfw_events_total' "$metrics" && grep -Eq 'ebfw_attribution_total.*hit' "$metrics"; then
  echo "PASS  metrics endpoint (events + attribution)"
else
  echo "FAIL  metrics endpoint"; fail=1
fi

echo "# ============================="
if [ "$fail" -eq 0 ]; then echo "RESULT: ALL PASS"; else echo "RESULT: FAILURES"; fi
exit "$fail"
