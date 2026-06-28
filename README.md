# ebfw — eBPF egress visibility agent → egress-control operator

`ebfw` is a single node-level agent that reports what each pod on a Kubernetes
node talks to: the **domains** it resolves and connects to, the **HTTP/HTTPS
request paths** (and optionally headers) it sends, and the **destination
IPs/ports** of new connections — each **attributed to the originating pod**
(`namespace/name`), with internal/cluster traffic filtered out. Output is
human-readable text or structured JSON, and the agent exposes Prometheus metrics.

This is the observability stage. The long-term goal is a Kubernetes **operator
that allows/blocks egress** per pod by domain/IP; the eBPF hooks used here are the
same ones that will later enforce policy.

## How it works

One binary, one agent, two eBPF data sources running in the same process:

- **Egress monitor** — a `cgroup_skb/egress` program attached at the node's root
  cgroup v2 (`/sys/fs/cgroup`). Because cgroup BPF is hierarchical, that single
  attach point sees egress from **every pod on the node**: DNS queries, TLS
  ClientHello SNI, plaintext HTTP requests, and new TCP connections.
- **Path inspection** (optional, on by default) — an `SSL_write` **uprobe**
  attached to each container's libssl. It reads HTTPS request plaintext **before**
  encryption, recovering paths the packet layer can't see (they're encrypted on
  the wire). It auto-discovers each container's libssl via `/proc` and attaches
  per library; capture is **live** (every `SSL_write`, no sampling).

The eBPF programs only bounds-check and ship bytes via ring buffers; all
DNS/TLS/HTTP parsing happens in Go. Internal traffic is dropped per config before
anything is printed.

- **Pod attribution** — both eBPF programs capture the originating cgroup v2 id
  in-kernel (`bpf_skb_cgroup_id` in the packet path, `bpf_get_current_cgroup_id`
  in the uprobe). Go resolves that id to a cgroup path (the directory inode equals
  the cgroup id on kernel ≥ 5.5), parses out the pod UID + container id + QoS, and
  — when running in-cluster — enriches it to `namespace/name` via a node-scoped
  Kubernetes Pods informer. Off-cluster it degrades to the node-local identity.

```
                       ┌─ cgroup_skb/egress ─ DNS / TLS-SNI / HTTP / CONNECT ─┐
[ pods on node ] ──────┤                          (+ cgroup id)                ├─► ebfw (Go) ─► attribute ─► text|json
                       └─ SSL_write uprobe ── HTTPS path (+headers, cgroup id)─┘        │
                                                                              k8s Pods informer (namespace/name)
```

Example output (text):

```
DNS      10.42.0.9 ? example.com (TypeA)  pod=default/probe
TLS      10.42.0.9 -> example.com  (104.20.23.154:443)  pod=default/probe
HTTP     10.42.0.9 -> GET example.com/foo/bar  pod=default/probe
HTTPS  [pid=2550689 curl] GET example.com/secret/path?token=abc123  pod=default/probe
CONNECT  10.42.0.9 -> 104.20.23.154:443  pod=default/probe
```

Example output (`EBFW_OUTPUT=json`, one object per line):

```json
{"ts":"2026-06-28T09:14:01Z","kind":"https","domain":"example.com","method":"GET","path":"/secret/path","pid":2550689,"comm":"curl","pod":{"namespace":"default","name":"probe","uid":"be31e934-…","container":"ad68e835…","qos":"besteffort","node":"k3d-ebfw-server-0"}}
```

## Layout

```
main.go                    agent entrypoint (config + signals; runs both data sources)
internal/config/           YAML config + env toggles (inspection/output/metrics) + Filter
internal/egress/           cgroup_skb/egress program + loader (gen.go -> bpf2go)
internal/sslsnoop/         SSL_write uprobe + libssl auto-discovery (gen.go -> bpf2go)
internal/attr/             pod attribution: cgroup-path parser, id->path index, k8s informer
internal/output/           Event model + text/json sinks (single emit chokepoint)
internal/metrics/          Prometheus collectors + /metrics server
internal/l7/               shared HTTP request parser (headers; body is a stub)
internal/tlsparse/         TLS ClientHello -> SNI extractor (+ unit test)
internal/policy/           pure policy model + engine + file source + CRD aggregation
internal/crdsource/        PolicySource backed by the EgressPolicy CRDs (in-process informer)
internal/controller/       thin status-only reconcilers for the two CRDs
api/v1/                    EgressPolicy + ClusterEgressPolicy types (CRD spec + ToPolicy)
cmd/operator/              the control-plane operator (manager) entrypoint
config/                    kubebuilder kustomize tree (generated CRDs, RBAC, manager)
helm/ebfw/                 Helm chart: CRDs + operator + agent DaemonSet
bpf/egress.bpf.c           the cgroup_skb/egress program
bpf/sslsnoop.bpf.c         the SSL_write uprobe program
deploy/ebfw.yaml           Namespace + ServiceAccount + RBAC + ConfigMap + DaemonSet (agent-only quickstart)
test/e2e.sh                host e2e (domain / ssl / paths / headers / filter / metrics / enforcement)
test/k8s.sh                k3d e2e (pod attribution + CRD-driven enforcement)
Dockerfile                 agent image: multi-stage (BPF + Go), or `--target bin` host binary
Dockerfile.operator        operator image (pure Go, no eBPF)
```

## Configuration

Two layers:

- **Filtering** comes from a YAML file (`-config` / `EBFW_CONFIG`, e.g. a mounted
  ConfigMap). Lists left unset fall back to built-in defaults.

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

- **Inspection depth, output, and metrics** come from environment variables (set
  via the ConfigMap):

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

### Enforcement (Stage 2)

The agent can evaluate an egress **policy** (allow/deny per pod by
domain/IP/CIDR/port) loaded from a YAML file (`EBFW_POLICY`) — the same schema
that will back the Stage-3 `EgressPolicy` CRD. See
[`deploy/policy.example.yaml`](deploy/policy.example.yaml).

`EBFW_ENFORCE_MODE` selects the behavior:

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
rules + default posture (Stage 2b), and **domain** rules (Stage 2c) — a
`cgroup_skb/ingress` hook captures DNS answers and the agent programs the
resolved IPs into the verdict map, so a domain-blocked connection's SYN is
dropped. (A domain-blocked flow shows only a `CONNECT` with `action=deny`; the
SYN never completes, so there's no TLS event carrying the SNI/rule name.)
**Port-only / L7 (method,path) / IPv6** rules are evaluated for `log`/metrics but
not yet dropped — the agent logs how many dimensions it couldn't program.

Policy is hot-reloaded on file change (a bad reload is logged and ignored,
keeping the last good policy). Evaluate a policy offline, no kernel needed:

```bash
ebfw policy test --policy deploy/policy.example.yaml \
  --flow 'pod=payments/web dst=203.0.113.5 port=443 domain=api.example.com' \
  --flow 'domain=evil.com port=443'
```

`Modify` rules (header injection / path rewrite) are accepted and shown by
`policy test`, but Stage 2 does not enforce them — that datapath (a terminating
proxy + TLS MITM) is a deferred, opt-in sub-stage; the cgroup/connect datapath
treats `Modify` as `Allow`.

For a full k3d walkthrough (deploy, enable a demo blocklist, watch allow/deny
events attributed per pod), see [`deploy/DEMO.md`](deploy/DEMO.md).

### Egress policy CRDs (Stage 3)

Instead of a YAML file, the policy can be declared as Kubernetes resources. Set
`EBFW_POLICY_SOURCE=crd` (the Helm chart's default) and each agent watches two
CRDs in `ebfw.dvrkn.com/v1`, cluster-wide:

- **`EgressPolicy`** (namespaced) — rules for the pods in **one namespace**. Its
  `defaultAction: Deny` default-denies only that namespace's pods.
- **`ClusterEgressPolicy`** (cluster-scoped) — **node-wide** rules and the only
  place that can set a node-global default-deny.

Either kind has a required top-level **`spec.podSelector`** (a NetworkPolicy-style
label selector; `{}` means "all pods in scope") that scopes the whole policy —
rules **and** `defaultAction` — to a labeled subset of pods, so a
`defaultAction: Deny` can lock down just `app=frontend` and leave the rest of the
namespace/node alone.

The agent aggregates every policy on the node (cluster rules first, then
per-namespace rules, then default-deny catch-alls), folding each policy's
`podSelector` into its rules, into the same engine + datapath used by the file
source — so enforcement behaviour is identical, only the source differs. A thin control-plane **operator** validates
each resource and records `status.conditions[Accepted]`; it does not program the
datapath (the per-node agents do). An invalid resource is dropped (and marked
`Accepted=False`) without affecting the others.

Full field reference, aggregation semantics, and the node-wide default-deny
caveat are in [`docs/egresspolicy.md`](docs/egresspolicy.md).

### Pod attribution

When the agent runs in-cluster it watches Pods on its own node (a `spec.nodeName`
field selector) to map pod UID → `namespace/name`, so it needs RBAC to
`get/list/watch` pods (included in `deploy/ebfw.yaml`) and `EBFW_NODE_NAME` from
the downward API. This enrichment is **best-effort**: with no in-cluster config,
or before the informer has synced, events still carry the node-local identity
(pod UID, container id, QoS) — only the human-readable `namespace/name` is absent.

### Metrics

`/metrics` (default `:9090`, on `hostNetwork` so reachable on the node) exposes:
`ebfw_events_total{kind}`, `ebfw_filtered_total{kind}`,
`ebfw_attribution_total{result}` (hit/miss), `ebfw_uprobe_attached`, and — when
enforcement is enabled — `ebfw_enforcement_decisions_total{action,mode}` and
`ebfw_policy_rules`. Labels are deliberately low-cardinality — pod identity
lives in the event lines, not in metric labels.

## Requirements

- **Runtime:** Linux kernel **≥ 5.8** (ring buffer), cgroup **v2** unified
  hierarchy. Verified on Ubuntu 24.04 / kernel 6.17 via k3d.
- **Build:** done in Docker by default (no local clang needed). The build image is
  `golang:1.26-trixie` (clang ~19, **libbpf 1.5** → modern `BPF_UPROBE`).

## Build

```bash
make docker            # build the container image (BPF + Go compiled inside)
make build             # native: bin/ebfw  (needs clang, libbpf-dev; Linux)
make test              # unit tests (TLS SNI parser); runs anywhere, no eBPF
```

## Deploy

```bash
make docker
k3d image import ebfw:dev -c <cluster>     # or: kind load / push to a registry
kubectl apply -f deploy/ebfw.yaml
kubectl -n ebfw logs -f ds/ebfw

# generate egress from any pod, then watch the agent on that node:
kubectl run probe --rm -it --image=nicolaka/netshoot --restart=Never -- \
  curl -4 --http1.1 https://example.com/foo/bar
```

The DaemonSet runs `privileged` + `hostNetwork` + `hostPID` (the last is needed
to find each container's libssl via `/proc`). To turn off path inspection, set
`inspect-paths: "false"` in the ConfigMap. Fine-grained capabilities instead of
`privileged` (kernel-dependent): `CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN, CAP_SYS_ADMIN`.

`deploy/ebfw.yaml` is the agent-only quickstart (no CRDs, file-based policy). To
install the full Stage-3 stack — the CRDs, the operator, and the agent wired to
watch them (`EBFW_POLICY_SOURCE=crd`) — use the Helm chart:

```bash
helm install ebfw ./helm/ebfw --namespace ebfw --create-namespace \
  --set agent.enforceMode=log        # observe verdicts first; flip to enforce when ready

kubectl apply -f config/samples/ebfw_v1_egresspolicy.yaml
kubectl get egp,cegp -A
```

Published images: `ghcr.io/dvrkn/ebfw` (agent) and `ghcr.io/dvrkn/ebfw-operator`
(operator), built multi-arch by CI on `main`/tags after the test jobs pass.

## End-to-end test

`test/e2e.sh` runs the binary on a Linux host, generates real traffic with curl,
and asserts what it captured — domain (DNS), ssl (TLS SNI), HTTP + HTTPS paths,
headers, and that an excluded domain is filtered out.

```bash
docker build --target bin --output type=local,dest=out .   # -> out/ebfw
sudo ./test/e2e.sh out/ebfw
```

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

## Roadmap

- **Stage 0 — visibility (done):** domains (DNS + TLS SNI), HTTP/HTTPS paths,
  headers, connections; node-wide; internal traffic filtered. Observe only.
- **Stage 1 — attribution & output (done):** map cgroup id → pod (cgroup path →
  pod UID/container/QoS, enriched to namespace/name via a node-scoped Pods
  informer), structured JSON output, Prometheus metrics. _Remaining and deferred
  to Stage 4: TLS/HTTP multi-segment reassembly and TLS 1.3 ECH handling._
- **Stage 2 — enforcement (done):** allow/deny egress per pod by
  domain / IP / CIDR / port. A pure `internal/policy` engine (the future CRD
  spec) drives three modes — `off`, `log` (annotate the verdict, no drop), and
  `enforce` — programming `LRU_HASH` + `LPM_TRIE` verdict maps from the policy.
  Denials drop at the `cgroup_skb/egress` hook and fail IPv4 TCP `connect()` fast
  with `EPERM` (`cgroup/connect4`); domain rules are enforced by learning DNS→IP
  from a `cgroup_skb/ingress` hook (LRU + TTL). Testable as a plain binary via
  `ebfw policy test`; host + k3d e2e coverage. _Deferred: `connect6` / IPv6
  enforcement, an in-kernel TLS-SNI/HTTP-Host drop backstop (limited by ECH),
  pinned maps for the Stage-3 controller, and request **modify** (header
  injection / path rewrite — needs a terminating L7 proxy + TLS MITM; modeled in
  the policy now but not enforced)._
- **Stage 3 — operator (done):** `EgressPolicy` (namespaced) + `ClusterEgressPolicy`
  (cluster-scoped) CRDs in `ebfw.dvrkn.com/v1`, whose spec mirrors `policy.Policy`.
  Each agent watches both kinds cluster-wide via a new in-process informer
  `PolicySource` (`EBFW_POLICY_SOURCE=crd`), aggregates them (cluster rules first,
  then per-namespace rules + default-deny catch-alls; a namespaced Deny never cuts
  off the node), and feeds the unchanged Stage-2 enforce stack. A thin
  controller-runtime operator validates each resource and records its `Accepted`
  status. Shipped as a Helm chart (CRDs + operator + agent) with multi-arch images
  pushed to ghcr.io by CI. Scaffolded with kubebuilder; controllers covered by
  envtest. _Deferred: pinned maps + an external map-programming controller (the
  per-node agent programs its own maps for now)._
- **Stage 3.1 — operator hardening (next):** broaden coverage and smooth the
  rough edges now that the happy path is proven.
  - _e2e coverage:_ lifecycle (hot-reload an edited CR → new rule applies live;
    CR deletion lifts enforcement; an invalid CR is dropped while the rest keep
    enforcing); aggregation interactions (cluster `defaultAction: Deny` allowlist
    that keeps DNS/API up, multiple `EgressPolicy` across namespaces,
    cluster+namespace precedence); more dimensions (domain **deny** via CRD,
    `log` mode via CRD, and negative checks that deferred dims —
    port-only / IPv6 / label-selector — are logged-not-dropped).
  - _crdsource + agent:_ coalesce/debounce informer rebuilds, watch-error
    resilience, optional node-scoped watch (only namespaces with local pods), and
    surface the deferred-dimension count (rules that couldn't be programmed) as a
    metric/log.
  - _operator UX:_ emit Kubernetes Events on validation failure, operator metrics
    (policy / validation-failure counts), and evaluate a validating admission
    webhook for synchronous rejection instead of post-hoc `Accepted=False`.
  - _CRD / chart polish:_ CEL field validations (`Modify` ⇒ mutations, action
    required), an Age print column, and Helm values for operator probes/resources;
    note the agent binary now links controller-runtime (size bump).
- **Stage 4 — hardening:** TLS/HTTP multi-segment reassembly, TLS 1.3 ECH, IPv6
  extension-header parsing + enforcement, cgroup-v1 fallback, request-body
  inspection, uprobe coverage beyond OpenSSL-dynamic, multi-kernel CI, HA, scale
  tests.

---

Built with the [eBPF skill](https://github.com/h0x0er/ebpf-skill) for
hook/map/verifier guidance and [`cilium/ebpf`](https://github.com/cilium/ebpf)
(ebpf-go) for the loader.
```
