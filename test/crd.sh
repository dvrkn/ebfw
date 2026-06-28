#!/usr/bin/env bash
#
# Kubernetes end-to-end: install the full stack via the Helm chart (CRDs +
# operator + agent with EBFW_POLICY_SOURCE=crd, enforce mode) on a throwaway k3d
# cluster, then assert the full CRD-driven path:
#   - pod attribution (DNS/TLS/HTTP/HTTPS events attributed to the originating pod)
#   - the operator validates resources and stamps status.conditions[Accepted]
#   - an EgressPolicy deny is programmed by the agent and attributed to the pod
#   - a namespaced defaultAction:Deny default-denies ONLY that namespace's pods,
#     while node-global egress stays Allow (the load-bearing semantic)
#   - a ClusterEgressPolicy deny applies node-wide
#
# Builds both images via the repo Dockerfiles (no local Go/clang needed).
# Requires: Linux, docker, k3d, kubectl, curl, jq, helm.
#   ./test/crd.sh          # create cluster, test, tear down
#   KEEP=1 ./test/crd.sh   # leave the cluster up afterwards (debugging)

set -uo pipefail

CLUSTER="${CLUSTER:-ebfw-crd}"
AGENT_IMAGE="${AGENT_IMAGE:-ebfw:crd}"
OPERATOR_IMAGE="${OPERATOR_IMAGE:-ebfw-operator:crd}"
NS="${NS:-ebfw}"
BLOCKED="${BLOCKED:-1.1.1.0/24}"        # blocked by the namespaced EgressPolicy (probe)
BLOCKED_IP="${BLOCKED_IP:-1.1.1.1}"
OPEN_IP="${OPEN_IP:-1.0.0.1}"           # not blocked until the ClusterEgressPolicy
CLUSTER_BLOCK="${CLUSTER_BLOCK:-1.0.0.0/24}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fail=0
note() { echo "# $*"; }

cleanup() {
  if [ "$fail" -ne 0 ]; then
    echo "# ---- debug: pods + recent agent log ----"
    kubectl -n "$NS" get pods -o wide 2>&1 | tail -8
    kubectl -n "$NS" logs -l app.kubernetes.io/component=agent --tail=40 2>&1 | tail -40
    kubectl -n "$NS" logs -l app.kubernetes.io/component=operator --tail=20 2>&1 | tail -20
    kubectl get egp,cegp -A 2>&1 | tail -10
  fi
  if [ "${KEEP:-}" != "1" ]; then
    note "tearing down cluster $CLUSTER"
    k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
  else
    note "KEEP=1 — leaving cluster $CLUSTER up"
  fi
}
trap cleanup EXIT

for bin in docker k3d kubectl curl jq helm; do
  command -v "$bin" >/dev/null || { echo "ERROR: $bin required"; exit 1; }
done

# ── build images + cluster ───────────────────────────────────────────────────
note "building agent image $AGENT_IMAGE"
docker build -t "$AGENT_IMAGE" "$ROOT" || { echo "ERROR: agent image build failed"; exit 1; }
note "building operator image $OPERATOR_IMAGE"
docker build -f "$ROOT/Dockerfile.operator" -t "$OPERATOR_IMAGE" "$ROOT" || { echo "ERROR: operator image build failed"; exit 1; }

note "creating k3d cluster $CLUSTER"
k3d cluster create "$CLUSTER" --wait || { echo "ERROR: cluster create failed"; exit 1; }
note "importing images"
k3d image import "$AGENT_IMAGE" "$OPERATOR_IMAGE" -c "$CLUSTER" || { echo "ERROR: image import failed"; exit 1; }

# ── install the full stack via the Helm chart ───────────────────────────────
note "helm install ebfw (CRDs + operator + agent: enforce + crd source, JSON output)"
helm install ebfw "$ROOT/helm/ebfw" \
  --namespace "$NS" --create-namespace \
  --set operator.image.repository="${OPERATOR_IMAGE%:*}" --set operator.image.tag="${OPERATOR_IMAGE##*:}" \
  --set agent.image.repository="${AGENT_IMAGE%:*}"       --set agent.image.tag="${AGENT_IMAGE##*:}" \
  --set agent.enforceMode=enforce --set agent.policySource=crd --set agent.output=json \
  || { echo "ERROR: helm install failed"; exit 1; }

kubectl -n "$NS" rollout status deploy/ebfw-operator --timeout=120s || { echo "ERROR: operator not ready"; fail=1; }
kubectl -n "$NS" rollout status ds/ebfw-agent --timeout=120s        || { echo "ERROR: agent not ready"; fail=1; }

note "waiting for agent pod informer + CRD watch to sync"
for _ in $(seq 1 40); do
  kubectl -n "$NS" logs -l app.kubernetes.io/component=agent 2>/dev/null | grep -q "watching EgressPolicy" && break
  sleep 1
done

# assert: at least one JSON event matches the jq filter, scanning recent agent logs.
agent_events() { kubectl -n "$NS" logs -l app.kubernetes.io/component=agent --tail=600 2>&1 | grep '^{'; }
assert_event() { # <label> <jq-filter>
  local ev; ev="$(agent_events)"
  if [ -n "$(jq -c "select($2)" <<<"$ev" 2>/dev/null | head -1)" ]; then echo "PASS  $1"; else echo "FAIL  $1   [no event: $2]"; fail=1; fi
}
# fetch a CR status condition status (True/False/"") for type Accepted.
accepted() { kubectl get "$1" "$2" ${3:+-n "$3"} -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null; }

# retry_ok <attempts> <cmd...> — succeeds if any attempt exits 0. Domain-allow
# rules depend on DNS→IP learning, which races the first connect; retry smooths it.
retry_ok() { local n="$1"; shift; local i; for i in $(seq 1 "$n"); do "$@" && return 0; sleep 3; done; return 1; }

# ── probe pods ───────────────────────────────────────────────────────────────
note "starting probe pods (default/probe, walled/probe2)"
kubectl create namespace walled >/dev/null 2>&1 || true
kubectl run probe  --image=nicolaka/netshoot --restart=Never --command -- sleep infinity >/dev/null
kubectl -n walled run probe2 --image=nicolaka/netshoot --restart=Never --command -- sleep infinity >/dev/null
kubectl wait --for=condition=Ready pod/probe --timeout=120s >/dev/null || { echo "ERROR: probe not ready"; exit 1; }
kubectl -n walled wait --for=condition=Ready pod/probe2 --timeout=120s >/dev/null || { echo "ERROR: probe2 not ready"; exit 1; }

# ── Test 1+2: operator status (valid + invalid) ─────────────────────────────
note "Test 1/2: operator validation status"
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: valid-pol, namespace: default }
spec:
  podSelector: {}
  defaultAction: Allow
  rules:
    - name: allow-dns
      action: Allow
      match: { ports: [53] }
YAML
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: invalid-pol, namespace: default }
spec:
  podSelector: {}
  rules:
    - name: bad-cidr
      action: Deny
      match: { cidrs: ["not-a-cidr"] }
YAML
ok=""; for _ in $(seq 1 20); do [ "$(accepted egresspolicy valid-pol default)" = "True" ] && { ok=1; break; }; sleep 1; done
[ -n "$ok" ] && echo "PASS  operator marks valid policy Accepted=True" || { echo "FAIL  operator did not Accept valid policy"; fail=1; }
bad=""; for _ in $(seq 1 20); do [ "$(accepted egresspolicy invalid-pol default)" = "False" ] && { bad=1; break; }; sleep 1; done
[ -n "$bad" ] && echo "PASS  operator marks invalid policy Accepted=False" || { echo "FAIL  operator did not reject invalid policy"; fail=1; }
kubectl delete egresspolicy invalid-pol -n default >/dev/null 2>&1 || true

# ── Test 3: namespaced EgressPolicy deny, attributed to the pod ──────────────
note "Test 3: EgressPolicy(default) deny ${BLOCKED} for pod probe"
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: block-probe, namespace: default }
spec:
  podSelector: {}            # govern the whole namespace; the rule narrows by pod name
  defaultAction: Allow
  rules:
    - name: block-cidr
      action: Deny
      match:
        pod: { name: probe }
        cidrs: ["${BLOCKED}"]
YAML
sleep 12  # agent re-walk ticker maps the pod cgroup + programs the verdict
denied_rc=0; kubectl exec probe -- curl -4 -s -o /dev/null --max-time 6 "https://${BLOCKED_IP}/" || denied_rc=$?
open_rc=1;   kubectl exec probe -- curl -4 -s -o /dev/null --max-time 8 "https://${OPEN_IP}/" && open_rc=0
[ "$denied_rc" -ne 0 ] && echo "PASS  probe denied to ${BLOCKED_IP} (rc=$denied_rc)" || { echo "FAIL  probe reached ${BLOCKED_IP}"; fail=1; }
[ "$open_rc" -eq 0 ]   && echo "PASS  probe still reaches ${OPEN_IP} (blocklist)"    || { echo "FAIL  probe blocked from ${OPEN_IP}"; fail=1; }
assert_event "deny attributed to default/probe" ".kind==\"connect\" and (.action|ascii_downcase)==\"deny\" and .pod.name==\"probe\" and (.dst|startswith(\"1.1.1\"))"

# ── Test 4: namespaced default-deny scopes to its namespace; node stays Allow ─
note "Test 4: EgressPolicy(walled) defaultAction:Deny — only walled is walled off"
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: walled-deny, namespace: walled }
spec:
  podSelector: {}            # default-deny the entire walled namespace
  defaultAction: Deny
  rules:
    - name: allow-dns
      action: Allow
      match: { ports: [53] }
    - name: allow-example
      action: Allow
      match: { domains: ["example.com", "*.example.com"], ports: [443] }
YAML
sleep 12
# walled/probe2: denied to an unlisted dest, but DNS + example.com allowed.
w_denied=0; kubectl -n walled exec probe2 -- curl -4 -s -o /dev/null --max-time 6 "https://${OPEN_IP}/" || w_denied=$?
w_dns=1;    kubectl -n walled exec probe2 -- sh -c "nslookup example.com >/dev/null 2>&1" && w_dns=0
w_allow=1;  retry_ok 4 kubectl -n walled exec probe2 -- curl -4 -s -o /dev/null --max-time 10 "https://example.com/" && w_allow=0
# default/probe: still reaches OPEN_IP -> node-global default stayed Allow.
d_open=1;   kubectl exec probe -- curl -4 -s -o /dev/null --max-time 8 "https://${OPEN_IP}/" && d_open=0
[ "$w_denied" -ne 0 ] && echo "PASS  walled/probe2 default-denied to ${OPEN_IP} (rc=$w_denied)" || { echo "FAIL  walled/probe2 reached unlisted dest"; fail=1; }
[ "$w_dns" -eq 0 ]    && echo "PASS  walled/probe2 DNS still resolves"                          || { echo "FAIL  walled/probe2 DNS broke under default-deny"; fail=1; }
[ "$w_allow" -eq 0 ]  && echo "PASS  walled/probe2 reaches allowed example.com"                 || { echo "FAIL  walled/probe2 blocked from allowed example.com"; fail=1; }
[ "$d_open" -eq 0 ]   && echo "PASS  default/probe still reaches ${OPEN_IP} (node-global Allow)" || { echo "FAIL  namespaced deny leaked node-wide"; fail=1; }

# ── Test 5: ClusterEgressPolicy applies node-wide ────────────────────────────
note "Test 5: ClusterEgressPolicy deny ${CLUSTER_BLOCK} node-wide"
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: ClusterEgressPolicy
metadata: { name: node-block }
spec:
  podSelector: {}            # node-wide
  defaultAction: Allow
  rules:
    - name: block-open-cidr
      action: Deny
      match: { cidrs: ["${CLUSTER_BLOCK}"] }
YAML
sleep 12
c_denied=0; kubectl exec probe -- curl -4 -s -o /dev/null --max-time 6 "https://${OPEN_IP}/" || c_denied=$?
[ "$c_denied" -ne 0 ] && echo "PASS  ClusterEgressPolicy blocks ${OPEN_IP} node-wide (rc=$c_denied)" || { echo "FAIL  ClusterEgressPolicy deny not enforced"; fail=1; }
co_ok=""; for _ in $(seq 1 20); do [ "$(accepted clusteregresspolicy node-block)" = "True" ] && { co_ok=1; break; }; sleep 1; done
[ -n "$co_ok" ] && echo "PASS  operator Accepted the ClusterEgressPolicy" || { echo "FAIL  ClusterEgressPolicy not Accepted"; fail=1; }

# ── Test 6: podSelector scopes a policy to a labeled subset of pods ───────────
# Two pods in one namespace; an EgressPolicy with podSelector + defaultAction:Deny
# governs ONLY the labeled pod, leaving its neighbour fully open. 1.1.1.1 is
# reachable here (the Test-3 block is scoped to default/probe; the Test-5 cluster
# block is 1.0.0.0/24), so it is a clean "is egress allowed?" probe.
note "Test 6: EgressPolicy(tenants) podSelector app=locked default-denies only the selected pod"
kubectl create namespace tenants >/dev/null 2>&1 || true
kubectl -n tenants run sel   --image=nicolaka/netshoot --labels=app=locked --restart=Never --command -- sleep infinity >/dev/null
kubectl -n tenants run unsel --image=nicolaka/netshoot --labels=app=open   --restart=Never --command -- sleep infinity >/dev/null
kubectl -n tenants wait --for=condition=Ready pod/sel   --timeout=120s >/dev/null || { echo "ERROR: sel not ready"; fail=1; }
kubectl -n tenants wait --for=condition=Ready pod/unsel --timeout=120s >/dev/null || { echo "ERROR: unsel not ready"; fail=1; }
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: tenant-lock, namespace: tenants }
spec:
  podSelector:
    matchLabels: { app: locked }
  defaultAction: Deny
  rules:
    - name: allow-dns
      action: Allow
      match: { ports: [53] }
YAML
sleep 12  # re-walk maps the labeled pod's cgroup + programs its per-pod default-deny
sel_denied=0; kubectl -n tenants exec sel   -- curl -4 -s -o /dev/null --max-time 6 "https://${BLOCKED_IP}/" || sel_denied=$?
uns_open=1;   kubectl -n tenants exec unsel -- curl -4 -s -o /dev/null --max-time 8 "https://${BLOCKED_IP}/" && uns_open=0
[ "$sel_denied" -ne 0 ] && echo "PASS  tenants/sel (app=locked) default-denied (rc=$sel_denied)"          || { echo "FAIL  podSelector did not govern the labeled pod"; fail=1; }
[ "$uns_open" -eq 0 ]   && echo "PASS  tenants/unsel (app=open) unaffected by the podSelector policy"      || { echo "FAIL  podSelector leaked to an unselected pod"; fail=1; }

echo "# ============================="
if [ "$fail" -eq 0 ]; then echo "RESULT: ALL PASS"; else echo "RESULT: FAILURES"; fi
exit "$fail"
