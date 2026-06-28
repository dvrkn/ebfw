# ebfw Stage 2 — k3d enforcement demo

A self-contained walkthrough of observe + enforce (allow/deny by domain, IP/CIDR)
with per-pod attribution, on a single-node k3d cluster. Run it on a Linux host
with Docker + k3d + kubectl (e.g. the project's test box).

> Enforcement attaches at the **node root cgroup**, so it is node-wide. This demo
> uses a *blocklist* (`defaultAction: Allow`) that only denies destinations the
> node/cluster doesn't need. Never use `defaultAction: Deny` with a node-root
> attach, or you'll cut the node off (kube-dns, API server, image pulls).

## 1. Build, deploy, enable the demo policy

```bash
cd ~/ebfw
k3d cluster create ebfw                 # once
docker build -t ebfw:dev .
k3d image import ebfw:dev -c ebfw

kubectl apply -f deploy/ebfw.yaml        # ships observe-only (enforce-mode: off)

# Flip to enforce mode with the demo blocklist (deny example.com/.net + 1.1.1.0/24):
kubectl -n ebfw patch configmap ebfw-config --type merge \
  --patch-file deploy/demo-enforce.patch.yaml
kubectl -n ebfw rollout restart ds/ebfw
kubectl -n ebfw rollout status  ds/ebfw
```

Confirm the agent came up enforcing:

```bash
kubectl -n ebfw logs ds/ebfw | grep -E "enforcement|datapath|learning|connect4|informer"
# ebfw: enforcement enforce — 2 rules, default Allow, policy="/etc/ebfw/policy.yaml"
# ebfw enforce: cgroup datapath active (dry_run=false)
# ebfw enforce: DNS→IP learning active (domain rules)
# ebfw enforce: connect4 fast-fail (EPERM) active
# ebfw attr: pod informer synced (node="k3d-ebfw-server-0")
```

## 2. A workload to generate egress

```bash
kubectl run playground --image=nicolaka/netshoot --restart=Never --command -- sleep infinity
kubectl wait --for=condition=Ready pod/playground
```

## 3. Watch the agent, then drive traffic

In one terminal:

```bash
kubectl -n ebfw logs -f ds/ebfw
```

In another:

```bash
# ALLOWED — succeeds (http 200)
kubectl exec playground -- curl -4 -sS -m8 -o /dev/null -w "github: %{http_code}\n" https://github.com

# DENIED by CIDR rule (1.1.1.0/24) — fails immediately with EPERM
kubectl exec playground -- curl -4 -sS -m6 https://1.1.1.1

# DENIED by domain rule (example.com) via DNS→IP learning — fails with EPERM
kubectl exec playground -- curl -4 -sS -m6 https://example.com
```

### What you'll see in the agent log

```
DNS      10.42.0.9 ? github.com (TypeA)                       pod=default/playground
TLS      10.42.0.9 -> github.com  (20.217.135.5:443)          pod=default/playground  action=Allow
HTTPS  [pid=… curl] GET github.com/                           pod=default/playground  action=Allow
CONNECT  0.0.0.0 -> 1.1.1.1:443                               pod=default/playground  action=Deny rule=demo-deny-1.1.1.0/24
CONNECT  0.0.0.0 -> 172.66.147.243:443                        pod=default/playground  action=Deny
```

- Allowed flows are reported with `action=Allow`; denied ones with `action=Deny`
  (and the rule name when known).
- Domain denials show as a `CONNECT` to the *resolved IP* with `src 0.0.0.0`: the
  `connect()` is failed with `EPERM` before any packet leaves, so there's no SNI
  to print — the agent learned the IP from the DNS answer.
- Every line is attributed to `pod=default/playground`.

### Metrics

```bash
kubectl -n ebfw exec ds/ebfw -- wget -qO- http://localhost:9090/metrics \
  | grep -E "ebfw_(enforcement|policy|dns)"
# ebfw_enforcement_decisions_total{action="Allow",mode="enforce"} …
# ebfw_enforcement_decisions_total{action="Deny",mode="enforce"} …
# ebfw_enforcement_drops_total{kind="connect"} …
# ebfw_policy_rules 2
# ebfw_dns_learned_ips …
```

## 4. Try your own policy

Edit `policy.yaml` inside the ConfigMap, then restart:

```bash
kubectl -n ebfw edit configmap ebfw-config      # change the policy.yaml block
kubectl -n ebfw rollout restart ds/ebfw
```

Or dry-run a policy against sample flows with no kernel at all:

```bash
./out/ebfw policy test --policy deploy/policy.example.yaml \
  --flow 'pod=default/playground domain=example.com port=443' \
  --flow 'domain=github.com port=443'
```

Tips:
- Start with `enforce-mode: log` (annotates events `action=…` without dropping)
  to validate a policy against live traffic safely, then switch to `enforce`.
- Scope a rule to a workload with `match.pod.{namespace,name}` so only that pod
  is affected (the rest of the node is untouched).

## 5. Tear down

```bash
kubectl delete pod playground
k3d cluster delete ebfw
```
