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
#   - a podSelector scopes a policy to a labeled subset of pods
#   - CR lifecycle: editing a CR applies the new rule live (hot-reload), deleting a
#     CR lifts its enforcement, and an invalid CR is dropped while valid CRs keep
#     enforcing (both at the operator status and the agent datapath)
#   - policy merge: multiple policies over ONE pod merge by union of their denies,
#     cluster + namespaced policies stack on the same pod, and a longer-prefix
#     Allow overrides a broader Deny (most-specific match)
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

# reach <ns> <pod> <ip> — exit 0 if the pod can open a TLS connection to the IP
# (egress allowed), nonzero if it is dropped/EPERM'd. A fresh connection each call,
# so it reflects the CURRENT map state — what the lifecycle tests below toggle. -k:
# we measure datapath reachability, not cert trust (a dropped SYN/EPERM fails before
# the handshake regardless), so any per-IP cert quirk can't masquerade as "blocked".
reach() { kubectl -n "$1" exec "$2" -- curl -4 -sk -o /dev/null --max-time 8 "https://$3/"; }

# ── probe pods ───────────────────────────────────────────────────────────────
note "starting probe pods (default/probe, walled/probe2)"
kubectl create namespace walled >/dev/null 2>&1 || true
kubectl run probe  --image=nicolaka/netshoot --labels=app=probe --restart=Never --command -- sleep infinity >/dev/null
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
  podSelector:
    matchLabels: { app: probe }   # scope this policy to the probe pod (by label)
  defaultAction: Allow
  rules:
    - name: block-cidr
      action: Deny
      match:
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

# ── CR lifecycle (Tests 7-9): a dedicated namespace/pod, isolated from the state
# above. The earlier tests only block 1.0.0.0/24 node-wide (Test 5) and 1.1.1.0/24
# for default/probe (Test 3), so in the `life` namespace BOTH 1.1.1.1 and 8.8.8.8
# start reachable — clean toggle targets. Lifecycle tests use CIDR rules (programmed
# directly into the LPM map, no DNS-learning race), so map changes are deterministic
# after the re-walk window. ──
LIFE_A_CIDR="${LIFE_A_CIDR:-1.1.1.0/24}"; LIFE_A_IP="${LIFE_A_IP:-1.1.1.1}"
LIFE_B_CIDR="${LIFE_B_CIDR:-8.8.8.0/24}"; LIFE_B_IP="${LIFE_B_IP:-8.8.8.8}"
note "creating lifecycle namespace/pod (life/lp)"
kubectl create namespace life >/dev/null 2>&1 || true
kubectl -n life run lp --image=nicolaka/netshoot --restart=Never --command -- sleep infinity >/dev/null
kubectl -n life wait --for=condition=Ready pod/lp --timeout=120s >/dev/null || { echo "ERROR: lp not ready"; fail=1; }

# life_pol <cidr-to-deny> — (re)apply the single lifecycle EgressPolicy. kubectl
# apply REPLACES the existing object, so calling it twice with different CIDRs is
# exactly the hot-reload edit Test 7 exercises.
life_pol() {
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: life-pol, namespace: life }
spec:
  podSelector: {}
  defaultAction: Allow
  rules:
    - name: block
      action: Deny
      match: { cidrs: ["$1"] }
YAML
}

# ── Test 7: hot-reload — editing a CR applies the new rule live (no restart) ──
# Deny CIDR-A, confirm it bites and CIDR-B is open; then edit the SAME CR to deny
# CIDR-B instead. The agent's CRD informer rebuilds and the Programmer reconciles
# the maps live: CIDR-A must reopen (old rule lifted) AND CIDR-B must close (new
# rule applied) — all without any pod or agent restart.
note "Test 7: hot-reload an edited EgressPolicy applies live (deny ${LIFE_A_CIDR} -> ${LIFE_B_CIDR})"
life_pol "$LIFE_A_CIDR"
sleep 12  # re-walk maps lp's cgroup + programs the CIDR verdict
a_denied=0; reach life lp "$LIFE_A_IP" || a_denied=$?
b_open=1;   reach life lp "$LIFE_B_IP" && b_open=0
[ "$a_denied" -ne 0 ] && echo "PASS  life/lp denied to ${LIFE_A_IP} (initial rule, rc=$a_denied)"      || { echo "FAIL  initial deny rule not enforced"; fail=1; }
[ "$b_open" -eq 0 ]   && echo "PASS  life/lp reaches ${LIFE_B_IP} (not yet blocked)"                   || { echo "FAIL  ${LIFE_B_IP} unexpectedly blocked before edit"; fail=1; }
life_pol "$LIFE_B_CIDR"   # the edit
sleep 12
a_open=1;   reach life lp "$LIFE_A_IP" && a_open=0
b_denied=0; reach life lp "$LIFE_B_IP" || b_denied=$?
[ "$a_open" -eq 0 ]   && echo "PASS  hot-reload: ${LIFE_A_IP} reachable after edit (old rule lifted live)"        || { echo "FAIL  edited-away rule still enforced (no live reconcile)"; fail=1; }
[ "$b_denied" -ne 0 ] && echo "PASS  hot-reload: ${LIFE_B_IP} blocked after edit (new rule applied live, rc=$b_denied)" || { echo "FAIL  edited-in rule not enforced live"; fail=1; }

# ── Test 8: deleting a CR lifts its enforcement ──
# Pre-state from Test 7: life-pol denies ${LIFE_B_CIDR}, so ${LIFE_B_IP} is blocked.
# Deleting the CR must remove the map entry and reopen egress.
note "Test 8: deleting the EgressPolicy lifts enforcement"
pre_denied=0; reach life lp "$LIFE_B_IP" || pre_denied=$?
kubectl delete egresspolicy life-pol -n life >/dev/null 2>&1 || true
sleep 12
post_open=1; reach life lp "$LIFE_B_IP" && post_open=0
[ "$pre_denied" -ne 0 ] && echo "PASS  life/lp denied to ${LIFE_B_IP} before delete (rc=$pre_denied)" || { echo "FAIL  pre-delete deny not in effect"; fail=1; }
[ "$post_open" -eq 0 ]  && echo "PASS  deletion lifts enforcement: ${LIFE_B_IP} reachable again"      || { echo "FAIL  enforcement persisted after CR deletion"; fail=1; }

# ── Test 9: an invalid CR is dropped while valid CRs keep enforcing ──
# Apply a valid deny and confirm it enforces, THEN add an invalid CR alongside it.
# The operator must mark only the invalid one Accepted=False (valid stays True), and
# — the load-bearing bit — the AGENT must keep enforcing the valid policy: crdsource
# drops just the invalid CR from the aggregate, it never fails the whole node.
note "Test 9: invalid CR is dropped; valid CRs keep enforcing"
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: keep-pol, namespace: life }
spec:
  podSelector: {}
  defaultAction: Allow
  rules:
    - name: block
      action: Deny
      match: { cidrs: ["${LIFE_A_CIDR}"] }
YAML
sleep 12
keep_denied=0; reach life lp "$LIFE_A_IP" || keep_denied=$?
[ "$keep_denied" -ne 0 ] && echo "PASS  keep-pol enforcing: ${LIFE_A_IP} denied (rc=$keep_denied)" || { echo "FAIL  valid policy not enforcing before invalid CR added"; fail=1; }
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: bad-pol, namespace: life }
spec:
  podSelector: {}
  defaultAction: Allow
  rules:
    - name: bad-cidr
      action: Deny
      match: { cidrs: ["not-a-cidr"] }
YAML
bad=""; for _ in $(seq 1 20); do [ "$(accepted egresspolicy bad-pol life)" = "False" ] && { bad=1; break; }; sleep 1; done
[ -n "$bad" ] && echo "PASS  operator marks bad-pol Accepted=False"                              || { echo "FAIL  operator did not reject bad-pol"; fail=1; }
[ "$(accepted egresspolicy keep-pol life)" = "True" ] && echo "PASS  keep-pol stays Accepted=True alongside the invalid CR" || { echo "FAIL  valid policy lost acceptance when an invalid CR was added"; fail=1; }
sleep 12  # let the agent rebuild after the invalid apply
still_denied=0; reach life lp "$LIFE_A_IP" || still_denied=$?
[ "$still_denied" -ne 0 ] && echo "PASS  agent keeps enforcing the valid policy despite the invalid CR (rc=$still_denied)" || { echo "FAIL  an invalid CR broke enforcement of the valid policy"; fail=1; }
kubectl delete egresspolicy bad-pol keep-pol -n life >/dev/null 2>&1 || true

# ── Policy merge (Tests 10-12): multiple policies governing ONE pod, in a fresh
# `merge` namespace + pod `mp`. The Test-5 ClusterEgressPolicy (deny 1.0.0.0/24
# node-wide) is still active, so it ALSO governs mp — Test 11 uses that to show
# cluster + namespaced rules stacking. All merge tests use CIDR rules (the
# deterministic LPM datapath). NOTE on what we assert: in verdict_for a per-pod
# (namespaced) map entry is consulted before the node-global (cluster) one, so we
# only assert merges the datapath honors faithfully — union of denies, cross-scope
# stacking on different dests, and a longer-prefix Allow beating a broader Deny —
# never an overlapping cluster-vs-namespace Allow/Deny on the SAME CIDR (engine
# first-match-wins and kernel most-specific-wins disagree there by design). ──
MERGE_A_CIDR="${MERGE_A_CIDR:-1.1.1.0/24}"; MERGE_A_IP="${MERGE_A_IP:-1.1.1.1}"; MERGE_A_IP2="${MERGE_A_IP2:-1.1.1.3}"
MERGE_B_CIDR="${MERGE_B_CIDR:-8.8.8.0/24}"; MERGE_B_IP="${MERGE_B_IP:-8.8.8.8}"
MERGE_CTL_IP="${MERGE_CTL_IP:-9.9.9.9}"     # control: blocked by none of the merge policies
note "creating merge namespace/pod (merge/mp)"
kubectl create namespace merge >/dev/null 2>&1 || true
kubectl -n merge run mp --image=nicolaka/netshoot --restart=Never --command -- sleep infinity >/dev/null
kubectl -n merge wait --for=condition=Ready pod/mp --timeout=120s >/dev/null || { echo "ERROR: mp not ready"; fail=1; }

# ── Test 10: two EgressPolicies in one namespace, both selecting mp, merge by the
# UNION of their deny rules — each policy's deny is independently enforced. ──
note "Test 10: two EgressPolicies on one pod merge (union of denies)"
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: m-deny-a, namespace: merge }
spec:
  podSelector: {}
  defaultAction: Allow
  rules:
    - name: deny-a
      action: Deny
      match: { cidrs: ["${MERGE_A_CIDR}"] }
YAML
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: m-deny-b, namespace: merge }
spec:
  podSelector: {}
  defaultAction: Allow
  rules:
    - name: deny-b
      action: Deny
      match: { cidrs: ["${MERGE_B_CIDR}"] }
YAML
sleep 12
m_a=0;   reach merge mp "$MERGE_A_IP"   || m_a=$?
m_b=0;   reach merge mp "$MERGE_B_IP"   || m_b=$?
m_ctl=1; reach merge mp "$MERGE_CTL_IP" && m_ctl=0
[ "$m_a" -ne 0 ]   && echo "PASS  merge/mp denied to ${MERGE_A_IP} (policy m-deny-a, rc=$m_a)"          || { echo "FAIL  m-deny-a not enforced in the merge"; fail=1; }
[ "$m_b" -ne 0 ]   && echo "PASS  merge/mp denied to ${MERGE_B_IP} (policy m-deny-b, rc=$m_b)"          || { echo "FAIL  m-deny-b not enforced in the merge"; fail=1; }
[ "$m_ctl" -eq 0 ] && echo "PASS  merge/mp still reaches ${MERGE_CTL_IP} (union, not a blanket deny)"   || { echo "FAIL  merge over-blocked an unlisted dest"; fail=1; }

# ── Test 11: a ClusterEgressPolicy and a namespaced EgressPolicy both govern mp;
# their rules stack. The Test-5 cluster deny (1.0.0.0/24, node-wide) reaches mp,
# and mp's own namespace policy (m-deny-a) denies 1.1.1.0/24 — so mp is denied to
# a cluster-scoped AND a namespace-scoped dest at once. ──
note "Test 11: cluster + namespaced policy stack on the same pod"
m_cl=0; reach merge mp "$OPEN_IP"     || m_cl=$?   # 1.0.0.1: blocked node-wide by the Test-5 ClusterEgressPolicy
m_ns=0; reach merge mp "$MERGE_A_IP"  || m_ns=$?   # 1.1.1.1: blocked by the namespaced m-deny-a
[ "$m_cl" -ne 0 ] && echo "PASS  merge/mp denied to ${OPEN_IP} (ClusterEgressPolicy, node-wide, rc=$m_cl)" || { echo "FAIL  cluster rule did not reach mp"; fail=1; }
[ "$m_ns" -ne 0 ] && echo "PASS  merge/mp denied to ${MERGE_A_IP} (namespaced EgressPolicy, rc=$m_ns)"     || { echo "FAIL  namespaced rule not enforced alongside the cluster rule"; fail=1; }

# ── Test 12: when policies overlap, the longer-prefix match wins — a /32 Allow
# beats the enclosing /24 Deny (most-specific). Add a policy allowing
# ${MERGE_A_IP}/32 while m-deny-a still denies ${MERGE_A_CIDR}: the /32 host
# becomes reachable (the hole) while the rest of the /24 stays denied. The Allow CR
# name sorts before the Deny CR (m-allow-host < m-deny-a), so the engine's
# first-match and the kernel's longest-prefix agree. ──
note "Test 12: longer-prefix Allow overrides a broader Deny across two policies"
kubectl apply -f - >/dev/null <<YAML
apiVersion: ebfw.dvrkn.com/v1
kind: EgressPolicy
metadata: { name: m-allow-host, namespace: merge }
spec:
  podSelector: {}
  defaultAction: Allow
  rules:
    - name: allow-host
      action: Allow
      match: { cidrs: ["${MERGE_A_IP}/32"] }
YAML
sleep 12
m_hole=1; reach merge mp "$MERGE_A_IP"  && m_hole=0   # 1.1.1.1/32 Allow carves a hole
m_rest=0; reach merge mp "$MERGE_A_IP2" || m_rest=$?  # 1.1.1.3 still inside the denied /24
[ "$m_hole" -eq 0 ] && echo "PASS  merge/mp reaches ${MERGE_A_IP} (/32 Allow overrides the /24 Deny)"          || { echo "FAIL  longer-prefix Allow did not win over the broader Deny"; fail=1; }
[ "$m_rest" -ne 0 ] && echo "PASS  merge/mp still denied to ${MERGE_A_IP2} (rest of ${MERGE_A_CIDR}, rc=$m_rest)" || { echo "FAIL  the /32 Allow leaked to the rest of the /24"; fail=1; }
kubectl delete egresspolicy m-deny-a m-deny-b m-allow-host -n merge >/dev/null 2>&1 || true

echo "# ============================="
if [ "$fail" -eq 0 ]; then echo "RESULT: ALL PASS"; else echo "RESULT: FAILURES"; fi
exit "$fail"
