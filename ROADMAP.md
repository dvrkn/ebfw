# ebfw roadmap

Development stages, what's shipped, and what's deferred. User-facing usage lives
in [`README.md`](README.md); this file is the staged plan and the running list of
deferred / in-progress work.

| Stage | Theme | Status |
|---|---|---|
| 0 | Visibility | ✅ done |
| 1 | Attribution & output | ✅ done |
| 2 | Enforcement | ✅ done |
| 3 | Operator (CRDs + Helm) | ✅ done |
| 3.1 | Operator hardening | 🔜 next |
| 4 | Hardening | 📋 planned |

## Stage 0 — visibility (done)

Domains (DNS + TLS SNI), HTTP/HTTPS paths, headers, connections; node-wide;
internal traffic filtered. Observe only.

## Stage 1 — attribution & output (done)

Map cgroup id → pod (cgroup path → pod UID/container/QoS, enriched to
namespace/name via a node-scoped Pods informer), structured JSON output,
Prometheus metrics.

_Remaining and deferred to Stage 4: TLS/HTTP multi-segment reassembly and TLS 1.3
ECH handling._

## Stage 2 — enforcement (done)

Allow/deny egress per pod by domain / IP / CIDR / port. A pure `internal/policy`
engine (the future CRD spec) drives three modes — `off`, `log` (annotate the
verdict, no drop), and `enforce` — programming `LRU_HASH` + `LPM_TRIE` verdict
maps from the policy. Denials drop at the `cgroup_skb/egress` hook and fail IPv4
TCP `connect()` fast with `EPERM` (`cgroup/connect4`); domain rules are enforced
by learning DNS→IP from a `cgroup_skb/ingress` hook (LRU + TTL). Testable as a
plain binary via `ebfw policy test`; host + k3d e2e coverage.

_Deferred: `connect6` / IPv6 enforcement, an in-kernel TLS-SNI/HTTP-Host drop
backstop (limited by ECH), pinned maps for the Stage-3 controller, and request
**modify** (header injection / path rewrite — needs a terminating L7 proxy + TLS
MITM; modeled in the policy now but not enforced)._

## Stage 3 — operator (done)

`EgressPolicy` (namespaced) + `ClusterEgressPolicy` (cluster-scoped) CRDs in
`ebfw.dvrkn.com/v1`, whose spec mirrors `policy.Policy`. Each agent watches both
kinds cluster-wide via a new in-process informer `PolicySource`
(`EBFW_POLICY_SOURCE=crd`), aggregates them (cluster rules first, then
per-namespace rules + default-deny catch-alls; a namespaced Deny never cuts off
the node), and feeds the unchanged Stage-2 enforce stack. A thin
controller-runtime operator validates each resource and records its `Accepted`
status. Shipped as a Helm chart (CRDs + operator + agent) with multi-arch images
pushed to ghcr.io by CI. Scaffolded with kubebuilder; controllers covered by
envtest.

_Deferred: pinned maps + an external map-programming controller (the per-node
agent programs its own maps for now)._

## Stage 3.1 — operator hardening (next)

Broaden coverage and smooth the rough edges now that the happy path is proven.

- **e2e coverage:** lifecycle (hot-reload an edited CR → new rule applies live; CR
  deletion lifts enforcement; an invalid CR is dropped while the rest keep
  enforcing); aggregation interactions (cluster `defaultAction: Deny` allowlist
  that keeps DNS/API up, multiple `EgressPolicy` across namespaces,
  cluster+namespace precedence); more dimensions (domain **deny** via CRD, `log`
  mode via CRD, and negative checks that deferred dims — port-only / IPv6 /
  label-selector — are logged-not-dropped).
- **crdsource + agent:** coalesce/debounce informer rebuilds, watch-error
  resilience, optional node-scoped watch (only namespaces with local pods), and
  surface the deferred-dimension count (rules that couldn't be programmed) as a
  metric/log.
- **operator UX:** emit Kubernetes Events on validation failure, operator metrics
  (policy / validation-failure counts), and evaluate a validating admission
  webhook for synchronous rejection instead of post-hoc `Accepted=False`.
- **CRD / chart polish:** CEL field validations (`Modify` ⇒ mutations, action
  required), an Age print column, and Helm values for operator probes/resources;
  note the agent binary now links controller-runtime (size bump).

## Stage 4 — hardening

TLS/HTTP multi-segment reassembly, TLS 1.3 ECH, IPv6 extension-header parsing +
enforcement, cgroup-v1 fallback, request-body inspection, uprobe coverage beyond
OpenSSL-dynamic, multi-kernel CI, HA, scale tests.
