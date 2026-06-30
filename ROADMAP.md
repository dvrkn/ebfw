# ebfw roadmap

What ebfw does today and what's planned next. User-facing usage lives in
[`README.md`](README.md); this file tracks capabilities and the running list of
deferred / in-progress work.

## Today

ebfw is a single-binary per-node agent plus a thin control-plane operator,
shipped as a Helm chart with multi-arch images on ghcr.io.

- **Visibility.** Outgoing domains (DNS + TLS SNI), HTTP/HTTPS request paths and
  headers, and new TCP connections — node-wide, internal traffic filtered, observe
  only by default.
- **Attribution.** Every event is mapped to the originating pod: cgroup id → pod
  UID/container/QoS via the cgroup path, enriched to `namespace/name` through a
  node-scoped Pods informer. Structured text/JSON output and Prometheus metrics.
- **Enforcement.** Allow/deny egress per pod by domain / IP / CIDR / port. A pure
  `internal/policy` engine drives three modes — `off`, `log` (annotate the verdict,
  no drop), and `enforce` — programming `LRU_HASH` + `LPM_TRIE` verdict maps.
  Denials drop at the `cgroup_skb/egress` hook and fail IPv4 TCP `connect()` fast
  with `EPERM` (`cgroup/connect4`); domain rules are enforced by learning DNS→IP
  from a `cgroup_skb/ingress` hook (LRU + TTL). Testable as a plain binary via
  `ebfw policy test`; host + k3d e2e coverage.
- **Policy as CRDs.** `EgressPolicy` (namespaced) + `ClusterEgressPolicy`
  (cluster-scoped) in `ebfw.dvrkn.com/v1`, whose spec mirrors `policy.Policy`. Each
  agent watches both kinds cluster-wide via an in-process informer `PolicySource`
  (`EBFW_POLICY_SOURCE=crd`) and aggregates them (cluster rules first, then
  per-namespace rules + default-deny catch-alls; a namespaced Deny never cuts off
  the node). A thin controller-runtime operator validates each resource and records
  its `Accepted` status; it never programs maps. Controllers covered by envtest.

## Planned

### Operator hardening

Broaden coverage and smooth the rough edges now that the happy path is proven.

- **e2e coverage:** CR lifecycle is now covered (`test/crd.sh` Tests 7-9:
  hot-reload an edited CR applies the new rule live, CR deletion lifts enforcement,
  and an invalid CR is dropped while valid CRs keep enforcing — asserted at both the
  operator status and the agent datapath). Policy merge is now covered too
  (`test/crd.sh` Tests 10-12: multiple `EgressPolicy` over one pod merge by union
  of their denies, a `ClusterEgressPolicy` and a namespaced `EgressPolicy` stack on
  the same pod, and a longer-prefix Allow overrides a broader Deny — most-specific
  match). Still to add: a node-wide cluster `defaultAction: Deny` allowlist that
  keeps DNS/API up, and explicit cross-namespace isolation (multiple `EgressPolicy`
  in different namespaces not leaking into each other); more dimensions (domain
  **deny** via CRD, `log` mode via CRD, and negative checks that deferred dims —
  port-only / IPv6 / label-selector — are logged-not-dropped).
- **crdsource + agent:** coalesce/debounce informer rebuilds, watch-error
  resilience, optional node-scoped watch (only namespaces with local pods), and
  surface the deferred-dimension count (rules that couldn't be programmed) as a
  metric/log.
- **operator UX:** emit Kubernetes Events on validation failure, operator metrics
  (policy / validation-failure counts), and evaluate a validating admission
  webhook for synchronous rejection instead of post-hoc `Accepted=False`.
- **CRD / chart polish:** CEL field validations (`Modify` ⇒ mutations, action
  required), an Age print column, and Helm values for operator probes/resources.

### Datapath & hardening

- `connect6` / IPv6 enforcement and IPv6 extension-header parsing.
- **L7 (method / path) policy enforcement.** The `methods` and `pathPrefix` rule
  dimensions are accepted and evaluated for `log`/metrics today, but not yet
  dropped. Enforce them via two paths: an in-kernel TLS-SNI / HTTP-Host drop
  backstop for connection-level domain denies (limited by ECH), and a terminating
  L7 proxy + TLS MITM for full method / path / header semantics.
- Request **modify** (header injection / path rewrite — modeled in the policy now;
  shares the terminating L7 proxy above).
- Pinned maps + an external map-programming controller (the per-node agent programs
  its own maps for now).
- TLS/HTTP multi-segment reassembly, TLS 1.3 ECH, cgroup-v1 fallback,
  request-body inspection, uprobe coverage beyond OpenSSL-dynamic, multi-kernel CI,
  HA, and scale tests.
