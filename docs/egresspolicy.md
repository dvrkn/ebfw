# EgressPolicy & ClusterEgressPolicy (Stage 3)

ebfw exposes its egress policy as two Kubernetes CRDs in the group
`ebfw.dvrkn.com/v1`:

| Kind | Scope | Use it for |
|------|-------|------------|
| `EgressPolicy` (`egp`) | Namespaced | egress rules for the pods in **one namespace** |
| `ClusterEgressPolicy` (`cegp`) | Cluster | **node/cluster-wide** rules and the node-global default posture |

Both share the same `spec` shape (it mirrors the internal policy model 1:1).
The per-node agent watches both kinds cluster-wide, aggregates them into one
node policy, and programs the eBPF datapath. A thin control-plane operator
validates each resource and records its status — it does not program anything.

## How the two kinds combine

The agent aggregates every policy on the node, first-match-wins, in this order:

1. **ClusterEgressPolicy rules** (sorted by name) — applied node-wide as written.
2. **EgressPolicy rules** (sorted by namespace, then name) — each automatically
   scoped to its own namespace (a namespaced policy can only affect its own pods;
   any `match.pod.namespace` you set is overridden with the CR's namespace).
3. **Per-namespace default-deny** — for each `EgressPolicy` with
   `defaultAction: Deny`, a trailing catch-all `Deny` scoped to that namespace.

The **node-global default** is `Deny` only if some `ClusterEgressPolicy` sets
`defaultAction: Deny`; otherwise it is `Allow`. This is what makes namespaced and
node-wide policy coexist safely:

- A namespaced `EgressPolicy` with `defaultAction: Deny` default-denies **only
  that namespace's pods** (realized as per-cgroup defaults). It never cuts off
  the node.
- A `ClusterEgressPolicy` with `defaultAction: Deny` sets the **node-global**
  default-deny — the cluster-admin opt-in. **Use it carefully:** enforcement is
  physically node-wide (the program attaches at the root cgroup), so a node-wide
  default-deny stops the API server, image pulls, and everything else unless you
  explicitly allow them. DNS (udp:53) is always permitted in-kernel.

> One bad CR never breaks the node: a policy that fails validation is dropped
> (and marked `Accepted=False`); the rest keep enforcing.

## Spec reference

```yaml
spec:
  defaultAction: Allow | Deny          # default when no rule matches (default Allow)
  rules:                               # evaluated in order; first match wins
    - name: <string>                   # label for logs/metrics
      action: Allow | Deny | Modify    # required
      match:                           # AND across dimensions; empty = match-any
        pod:                           # source pod selector
          namespace: <string>          # (ignored for EgressPolicy — forced to the CR's ns)
          name: <string>
          uid: <string>
          labels: { k: v }             # evaluated for log/metrics; not yet a drop dimension
        domains: ["example.com", "*.example.com"]  # DNS qname / TLS SNI / HTTP Host suffix globs
        cidrs: ["203.0.113.0/24"]      # destination IP ranges (IPv4 enforced; IPv6 logged)
        ports: [443]                   # destination ports (1..65535)
        methods: ["GET"]               # L7 (log/metrics + future proxy only)
        pathPrefix: "/api"             # L7 (log/metrics + future proxy only)
      mutations:                       # required iff action: Modify (data only for now)
        - type: SetHeader | AddHeader | RemoveHeader | RewritePath
          header: <string>
          value: <string>
          pathReplace: <string>
```

### What is enforced vs logged

Enforced by the kernel datapath (Stage 2 capabilities, unchanged): domain rules
(via DNS→IP learning), IPv4 CIDR rules, IP+port pairs, and the default posture.
Evaluated for log/metrics but **not dropped yet**: port-only rules (no IP), IPv6
CIDRs, CIDR+port combinations, L7 (`methods`/`pathPrefix`), `Modify`, and pod
`labels` selectors.

## Status

The operator stamps each resource:

```yaml
status:
  observedGeneration: 3
  ruleCount: 2
  conditions:
    - type: Accepted
      status: "True"          # "False" with reason ValidationFailed on a bad spec
      reason: Validated
      message: policy spec is valid
```

```sh
kubectl get egp,cegp -A          # Default / Rules / Accepted columns
kubectl describe egp allow-github
```

## RBAC

- **Operator** (control plane): get/list/watch + status update on both kinds.
- **Agent** (DaemonSet): get/list/watch on both kinds cluster-wide (it aggregates
  across namespaces), plus the existing `pods` read for attribution.

Set the agent to watch the CRDs with `EBFW_POLICY_SOURCE=crd` (the Helm chart's
default). Off-cluster or when the CRDs are absent, the agent falls back to the
`EBFW_POLICY` file source.

## Examples

See `config/samples/ebfw_v1_egresspolicy.yaml` (namespaced allowlist) and
`config/samples/ebfw_v1_clusteregresspolicy.yaml` (node-wide blocklist).
