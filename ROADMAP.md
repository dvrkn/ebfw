# ebfw roadmap

The running list of planned and deferred work — forward-looking only. What ebfw
does **today** is documented in [`README.md`](README.md) and [`docs/`](docs/); the
current automated-test coverage lives in [`docs/tests.md`](docs/tests.md).

## Operator hardening

Smooth the rough edges now that the happy path and the full e2e matrix are proven
(lifecycle, aggregation/merge, cross-namespace isolation, CRD domain-deny, node-wide
lockdown, log mode, and deferred-dimension negative checks — see
[`docs/tests.md`](docs/tests.md)).

- **crdsource + agent:** coalesce/debounce informer rebuilds, watch-error
  resilience, optional node-scoped watch (only namespaces with local pods), and
  surface the deferred-dimension count (rules that couldn't be programmed) as a
  metric/log.
- **operator UX:** emit Kubernetes Events on validation failure, operator metrics
  (policy / validation-failure counts), and evaluate a validating admission
  webhook for synchronous rejection instead of post-hoc `Accepted=False`.
- **CRD / chart polish:** CEL field validations (`Modify` ⇒ mutations, action
  required), an Age print column, and Helm values for operator probes/resources.

## Datapath & hardening

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
