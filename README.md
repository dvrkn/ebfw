# ebfw — eBPF egress visibility agent → egress-control operator

`ebfw` is a single node-level agent that reports what each pod on a Kubernetes
node talks to: the **domains** it resolves and connects to, the **HTTP/HTTPS
request paths** (and optionally headers) it sends, and the **destination
IPs/ports** of new connections — with internal/cluster traffic filtered out.

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

```
                       ┌─ cgroup_skb/egress ─ DNS / TLS-SNI / HTTP / CONNECT ─┐
[ pods on node ] ──────┤                                                       ├─► ebfw (Go) ─► filtered output
                       └─ SSL_write uprobe ── HTTPS request path (+headers) ───┘
```

Example output:

```
DNS      10.42.0.2 ? example.com (TypeA)
TLS      10.42.0.2 -> example.com  (104.20.23.154:443)
HTTP     10.42.0.2 -> GET example.com/foo/bar
HTTPS  [pid=2550689 curl] GET example.com/secret/path?token=abc123
CONNECT  10.42.0.2 -> 104.20.23.154:443
```

## Layout

```
main.go                    agent entrypoint (config + signals; runs both data sources)
internal/config/           YAML config + env inspection toggles + traffic Filter
internal/egress/           cgroup_skb/egress program + loader (gen.go -> bpf2go)
internal/sslsnoop/         SSL_write uprobe + libssl auto-discovery (gen.go -> bpf2go)
internal/l7/               shared HTTP request parser (headers; body is a stub)
internal/tlsparse/         TLS ClientHello -> SNI extractor (+ unit test)
bpf/egress.bpf.c           the cgroup_skb/egress program
bpf/sslsnoop.bpf.c         the SSL_write uprobe program
deploy/ebfw.yaml           Namespace + ServiceAccount + ConfigMap + DaemonSet
test/e2e.sh                end-to-end test (domain / ssl / paths / headers / filter)
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

- **Inspection depth** comes from environment variables (set via the ConfigMap):

  | Env var | Default | Effect |
  |---|---|---|
  | `EBFW_INSPECT_PATHS` | `true` | capture HTTPS paths via the `SSL_write` uprobe |
  | `EBFW_INSPECT_HEADERS` | `false` | also print HTTP request headers |
  | `EBFW_INSPECT_BODY` | `false` | **stub** — request-body capture is not implemented |

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

- **IPv4 only** in the packet monitor (IPv6 is stubbed). The `SSL_write` uprobe is
  IP-agnostic, so HTTPS paths are captured over IPv6 even though the packet-level
  DNS/TLS/CONNECT are not. Force IPv4 (`curl -4`) to exercise the packet path.
- **HTTPS paths need OpenSSL-dynamic.** Statically-linked TLS has no `libssl.so`
  to hook — notably Go (`crypto/tls`, often stripped), Java, rustls.
- **Single segment** — DNS/TLS/HTTP are parsed from the first packet/segment only;
  larger ClientHellos/requests are truncated. Reassembly is future work.
- **Request bodies are a stub** (`EBFW_INSPECT_BODY` does nothing yet).
- **TLS 1.3 ECH** encrypts the SNI; such connections show only the dst IP.
- De-dup of connections is in-memory and unbounded — fine for a node agent, not
  tuned for very long runs.

## Roadmap

- **Stage 0 — visibility (this):** domains (DNS + TLS SNI), HTTP/HTTPS paths,
  headers, connections; node-wide; internal traffic filtered. Observe only.
- **Stage 1 — attribution & output:** map cgroup id → pod (cgroup path / CRI),
  structured JSON logs + Prometheus metrics, TLS/HTTP reassembly, ECH handling.
- **Stage 2 — enforcement:** allow/block egress by domain/IP. Learn DNS→IP into an
  `LPM_TRIE`/`HASH` and drop disallowed egress at the cgroup hook (`return 0`) or a
  `cgroup/connect4` hook; pin maps so policy updates need no reload.
- **Stage 3 — operator:** an `EgressPolicy` CRD + controller that programs each
  node agent's maps.
- **Stage 4 — hardening:** IPv6, cgroup-v1 fallback, request-body inspection,
  uprobe coverage beyond OpenSSL-dynamic, multi-kernel CI, HA, scale tests.

---

Built with the [eBPF skill](https://github.com/h0x0er/ebpf-skill) for
hook/map/verifier guidance and [`cilium/ebpf`](https://github.com/cilium/ebpf)
(ebpf-go) for the loader.
```
