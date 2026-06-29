# Configuration

The agent is configured in two layers: a YAML **filter** file (what internal
traffic to suppress) and a set of **environment variables** (inspection depth,
output, metrics, enforcement). With the Helm chart these are set via
[`helm/ebfw/values.yaml`](https://github.com/dvrkn/ebfw/blob/main/helm/ebfw/values.yaml).

## Filtering

From a YAML file (`-config` / `EBFW_CONFIG`, e.g. a mounted ConfigMap). Lists left
unset fall back to built-in defaults.

```yaml
cgroup: /sys/fs/cgroup
exclude:
  cidrs:            # suppress these destination IPs (cluster/private/loopback)
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 127.0.0.0/8
  domainSuffixes:   # suppress DNS/SNI/HTTP for these suffixes
    - cluster.local
    - svc
    - in-addr.arpa
```

## Environment variables

| Env var | Default | Effect |
|---|---|---|
| `EBFW_INSPECT_PATHS` | `true` | capture HTTPS paths via the `SSL_write` uprobe |
| `EBFW_INSPECT_HEADERS` | `false` | also report HTTP request headers |
| `EBFW_INSPECT_BODY` | `false` | **stub** — request-body capture is not implemented |
| `EBFW_OUTPUT` | `text` | event format: `text` or `json` (one object per line) |
| `EBFW_METRICS_ADDR` | `:9090` | Prometheus `/metrics` listen address (empty disables) |
| `EBFW_NODE_NAME` | _(unset)_ | this node's name (set via the downward API); scopes the pod informer |
| `EBFW_ENFORCE_MODE` | `off` | egress enforcement: `off` / `log` / `enforce` (see below) |
| `EBFW_POLICY_SOURCE` | `file` | where policy comes from: `file` (the `EBFW_POLICY` YAML) or `crd` (watch the `EgressPolicy` + `ClusterEgressPolicy` CRDs) |
| `EBFW_POLICY` | _(unset)_ | path to the egress policy YAML (used when `EBFW_POLICY_SOURCE=file`) |
| `EBFW_ENFORCE_DRY_RUN` | `false` | in `enforce` mode, program the datapath but suppress drops (canary) |

## Enforcement

The agent evaluates an egress **policy** (allow/deny per pod by
domain/IP/CIDR/port) — either a YAML file (`EBFW_POLICY`, see
[`examples/policy.yaml`](https://github.com/dvrkn/ebfw/blob/main/examples/policy.yaml)) or the
[EgressPolicy CRDs](egresspolicy.md). `EBFW_ENFORCE_MODE` selects the behavior:

- **`off`** (default) — observe-only; policy ignored.
- **`log`** — evaluate each connection-level event and annotate it with the
  verdict (`action=deny rule=…` in text, `"action"`/`"rule"` in JSON) **without
  dropping** anything. A safe dry-run to validate a policy against live traffic.
- **`enforce`** — drop denied egress. Denied IPv4 TCP `connect()` fails fast with
  `EPERM` (the `cgroup/connect4` hook); anything else denied is dropped at the
  `cgroup_skb/egress` hook (the SYN is dropped → connection times out).
  `EBFW_ENFORCE_DRY_RUN=true` programs the datapath and stamps verdicts but
  suppresses the drop, as a canary.

What `enforce` drops today: per-pod (or node-global) **IP/CIDR** and **CIDR+port**
rules + default posture, and **domain** rules — a `cgroup_skb/ingress` hook
captures DNS answers and the agent programs the resolved IPs into the verdict map,
so a domain-blocked connection's SYN is dropped. (A domain-blocked flow shows only
a `CONNECT` with `action=deny`; the SYN never completes, so there's no TLS event
carrying the SNI/rule name.) **Port-only / L7 (method,path) / IPv6** rules are
evaluated for `log`/metrics but not yet dropped — the agent logs how many
dimensions it couldn't program.

Policy is hot-reloaded on file change (a bad reload is logged and ignored, keeping
the last good policy). Evaluate a policy offline, no kernel needed:

```bash
ebfw policy test --policy examples/policy.yaml \
  --flow 'pod=payments/web dst=203.0.113.5 port=443 domain=api.example.com' \
  --flow 'domain=evil.com port=443'
```

`Modify` rules (header injection / path rewrite) are accepted and shown by
`policy test`, but are not enforced — that datapath (a terminating proxy + TLS
MITM) is a deferred, opt-in feature; the cgroup/connect datapath treats `Modify`
as `Allow`.

## Pod attribution

When the agent runs in-cluster it watches Pods on its own node (a `spec.nodeName`
field selector) to map pod UID → `namespace/name`, so it needs RBAC to
`get/list/watch` pods (granted by the chart) and `EBFW_NODE_NAME` from the
downward API. This enrichment is **best-effort**: with no in-cluster config, or
before the informer has synced, events still carry the node-local identity (pod
UID, container id, QoS) — only the human-readable `namespace/name` is absent.

## Metrics

`/metrics` (default `:9090`, on `hostNetwork` so reachable on the node) exposes:
`ebfw_events_total{kind}`, `ebfw_filtered_total{kind}`,
`ebfw_attribution_total{result}` (hit/miss), `ebfw_uprobe_attached`, and — when
enforcement is enabled — `ebfw_enforcement_decisions_total{action,mode}` and
`ebfw_policy_rules`. Labels are deliberately low-cardinality — pod identity lives
in the event lines, not in metric labels.

## Limitations

- **IPv6 extension headers are not parsed.** The packet monitor handles both IPv4
  and IPv6, but an IPv6 packet whose next-header is not TCP/UDP directly (a
  hop-by-hop, routing, fragment, or destination-options header) is skipped rather
  than walked. These are rare on normal egress.
- **HTTPS paths need OpenSSL-dynamic.** Statically-linked TLS has no `libssl.so`
  to hook — notably Go (`crypto/tls`, often stripped), Java, rustls.
- **Single segment** — DNS/TLS/HTTP are parsed from the first packet/segment only;
  larger ClientHellos/requests are truncated. Reassembly is future work.
- **Request bodies are a stub** (`EBFW_INSPECT_BODY` does nothing yet).
- **TLS 1.3 ECH** encrypts the SNI; such connections show only the dst IP.
- De-dup of connections is in-memory and unbounded — fine for a node agent, not
  tuned for very long runs.
