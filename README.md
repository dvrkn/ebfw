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
bpf/egress.bpf.c           the cgroup_skb/egress program
bpf/sslsnoop.bpf.c         the SSL_write uprobe program
deploy/ebfw.yaml           Namespace + ServiceAccount + RBAC + ConfigMap + DaemonSet
test/e2e.sh                end-to-end test (domain / ssl / paths / headers / filter / metrics / json)
Dockerfile                 multi-stage: image (default) or `--target bin` host binary
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
`ebfw_attribution_total{result}` (hit/miss), and `ebfw_uprobe_attached`. Labels
are deliberately low-cardinality — pod identity lives in the event lines, not in
metric labels.

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
- **Stage 2 — enforcement (next):** allow/block egress by domain/IP. Learn DNS→IP
  into an `LPM_TRIE`/`HASH` and drop disallowed egress at the cgroup hook
  (`return 0`) or a `cgroup/connect4` hook; pin maps so policy updates need no reload.
- **Stage 3 — operator:** an `EgressPolicy` CRD + controller that programs each
  node agent's maps.
- **Stage 4 — hardening:** TLS/HTTP multi-segment reassembly, TLS 1.3 ECH, IPv6
  extension-header parsing, cgroup-v1 fallback, request-body inspection, uprobe
  coverage beyond OpenSSL-dynamic, multi-kernel CI, HA, scale tests.

---

Built with the [eBPF skill](https://github.com/h0x0er/ebpf-skill) for
hook/map/verifier guidance and [`cilium/ebpf`](https://github.com/cilium/ebpf)
(ebpf-go) for the loader.
```
