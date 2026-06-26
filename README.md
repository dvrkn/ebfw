# ebfw — eBPF egress monitor → egress-control operator

`ebfw` watches **outgoing** network traffic on a Kubernetes node and prints what
each pod is talking to: the **domains** it resolves and connects to, the **HTTP
request paths** it sends, and the **destination IPs/ports** of new connections.

This is **Stage 0**: observe and print. The long-term goal is a Kubernetes
**operator that allows/blocks egress** per pod by domain/IP — and the eBPF hook
used here (`cgroup_skb/egress`) is the same one that will later enforce policy,
so the PoC is on the direct path to that goal.

## How it works

A single eBPF program of type `cgroup_skb/egress` is attached at the node's
**root cgroup v2** (`/sys/fs/cgroup`). Because cgroup BPF is hierarchical, that
one attach point sees egress packets from **every pod on the node**. The program
does no protocol parsing — it bounds-checks each packet, classifies it, and ships
the relevant bytes to userspace through a ring buffer. All DNS/TLS/HTTP parsing
happens in Go.

```
[ pods on node ] --egress--> cgroup_skb/egress (eBPF)  ──ringbuf──>  ebfw (Go)
                                  - UDP dst :53            -> DNS payload   -> domain
                                  - TLS ClientHello (0x16) -> TLS bytes     -> SNI domain
                                  - TCP payload "GET …"    -> HTTP bytes    -> METHOD host+path
                                  - TCP SYN & !ACK         -> {dst ip,port} -> connection
```

Example output:

```
DNS      10.244.1.7 ? example.com (A)
TLS      10.244.1.7 -> example.com  (93.184.216.34:443)
HTTP     10.244.1.7 -> GET example.com/foo/bar
CONNECT  10.244.1.7 -> 93.184.216.34:80
```

## Layout

```
gen.go                  bpf2go directive (compiles bpf/egress.bpf.c)
main.go                 loader, cgroup attach, ringbuf loop, event printing
bpf/egress.bpf.c        the cgroup_skb/egress program
internal/tlsparse/      TLS ClientHello -> SNI extractor (+ unit test)
Dockerfile              multi-stage build (compiles BPF + Go in-image)
Makefile                generate / build / test / docker / kind-load
deploy/ebfw.yaml        DaemonSet + privileges + cgroup mount
```

## Requirements

- **Runtime:** Linux kernel **≥ 5.8** (ring buffer), cgroup **v2** unified hierarchy.
- **Build (native):** Go 1.26, `clang`, `llvm`, `libbpf-dev`, `linux-libc-dev`.
  You don't need any of these locally if you build with Docker — the image
  compiles the BPF object and the Go binary itself.

## Build

```bash
make docker            # build the container image (BPF + Go compiled inside)
# or, on a Linux box with the build deps:
make build             # -> bin/ebfw
make test              # unit tests (TLS SNI parser); runs anywhere, no eBPF
```

## Verify

### 1. Local smoke test (no Kubernetes)

On a Linux host with cgroup v2:

```bash
sudo ./bin/ebfw                       # attaches at /sys/fs/cgroup
# in another shell:
curl http://example.com/foo/bar       # -> DNS + "GET example.com/foo/bar" + CONNECT :80
curl https://example.com/foo/bar      # -> DNS + TLS SNI example.com + CONNECT :443
```

Ctrl-C detaches cleanly.

To smoke-test the container image directly:

```bash
docker run --rm -it --privileged --network=host --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro ebfw:dev
```

### 2. Kubernetes

```bash
# Make the image available to the cluster:
make docker                           # build ebfw:dev
kind load docker-image ebfw:dev       # kind
#   or:  k3d image import ebfw:dev -c <cluster>     # k3d
#   or:  push ebfw:dev to a registry and edit deploy/ebfw.yaml

kubectl apply -f deploy/ebfw.yaml
kubectl -n ebfw rollout status ds/ebfw

# Generate some egress from any pod, then watch the agent on that node:
kubectl run probe --rm -it --image=curlimages/curl --restart=Never -- \
  sh -c 'curl -s https://example.com/foo/bar >/dev/null; nslookup github.com'
kubectl -n ebfw logs -l app=ebfw --prefix --tail=50
```

**Single node only?** The DaemonSet is the idiomatic "one pod per node" form. For
a literal single Pod, pin it with `nodeName: <node>` (or a `nodeSelector`) in the
template spec.

## Privileges

The PoC uses `securityContext.privileged: true` for simplicity. The fine-grained
alternative (kernel-dependent) is to drop `privileged` and grant only:

```yaml
securityContext:
  capabilities:
    add: ["BPF", "PERFMON", "NET_ADMIN", "SYS_ADMIN"]
```

`SYS_ADMIN` is needed to attach a program to the cgroup on many kernels; on newer
kernels `CAP_BPF` + `CAP_PERFMON` cover load/observe.

## Limitations (Stage 0)

- **IPv4 only** (IPv6 parsing is stubbed for a later stage).
- **HTTPS paths are encrypted** — we surface the domain via TLS SNI, not the path.
- **Single TCP segment** — DNS/TLS/HTTP are parsed from the first packet only;
  a ClientHello or request split across segments (or beyond ~512 captured bytes)
  is skipped. Reassembly is Stage 1.
- **TLS 1.3 ECH** encrypts the SNI; such connections show only the dst IP.
- **cgroup reachability** depends on the runtime/CNI exposing the host cgroup v2
  root to the agent. If a given setup breaks this, the fallback is a TC clsact
  egress program per pod veth (more attach plumbing).
- Connection de-dup is in-memory and unbounded — fine for a PoC, not for long runs.

## Roadmap

- **Stage 0 — PoC (this):** node agent prints egress domains (DNS + TLS SNI),
  HTTP paths, and dst IPs. Observe only.
- **Stage 1 — Attribution & output:** map cgroup id → pod (cgroup path / CRI),
  structured JSON logs + Prometheus metrics, reassemble TLS/HTTP across TCP
  segments, handle TLS 1.3 ECH gracefully.
- **Stage 2 — Enforcement primitive:** allow/block egress. Learn DNS→IP mappings
  into an `LPM_TRIE`/`HASH` (FQDN model), then drop disallowed egress — either
  `return 0` in `cgroup_skb/egress` or a `cgroup/connect4` hook. Pin maps to
  bpffs so policy updates need no reload.
- **Stage 3 — Operator:** an `EgressPolicy` CRD + controller (controller-runtime)
  that watches policies and programs each node agent's eBPF maps.
- **Stage 4 — Hardening:** IPv6, cgroup-v1 fallback, multi-kernel CI, HA, audit
  logging, scale tests.

---

Built with the [eBPF skill](https://github.com/h0x0er/ebpf-skill) for
hook/map/verifier guidance and [`cilium/ebpf`](https://github.com/cilium/ebpf)
(ebpf-go) for the loader.
