<div align="center">

<img src="logo.png" alt="ebfw" width="180" />

# ebfw

### eBPF egress firewall for Kubernetes

*See exactly what every pod talks to — domains, paths, IPs — then allow or deny it.<br/>Attributed per pod. Enforced in the kernel.*

[![Website](https://img.shields.io/badge/docs-dvrkn.github.io%2Febfw-F2A93B?logo=githubpages&logoColor=white)](https://dvrkn.github.io/ebfw/)
[![e2e](https://github.com/dvrkn/ebfw/actions/workflows/e2e.yml/badge.svg)](https://github.com/dvrkn/ebfw/actions/workflows/e2e.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/dvrkn/ebfw)](https://goreportcard.com/report/github.com/dvrkn/ebfw)
[![Go](https://img.shields.io/github/go-mod/go-version/dvrkn/ebfw?logo=go&logoColor=white&color=00ADD8)](go.mod)
[![ghcr.io](https://img.shields.io/badge/ghcr.io-ebfw%20%C2%B7%20ebfw--operator-2496ED?logo=docker&logoColor=white)](https://github.com/dvrkn/ebfw/pkgs/container/ebfw)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-operator-326CE5?logo=kubernetes&logoColor=white)](docs/egresspolicy.md)
[![Linux kernel ≥ 5.8](https://img.shields.io/badge/kernel-%E2%89%A5%205.8-FCC624?logo=linux&logoColor=black)](docs/install.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[**Install**](docs/install.md) · [**Configuration**](docs/configuration.md) · [**Egress policies**](docs/egresspolicy.md) · [**Roadmap**](ROADMAP.md) · [**Images**](https://github.com/dvrkn/ebfw/pkgs/container/ebfw)

</div>

---

`ebfw` is a single, node-level eBPF agent that shows — and enforces — what every
pod on a Kubernetes node is allowed to reach. One `cgroup_skb` program at the
node's root cgroup sees every pod's outbound DNS, TLS SNI, HTTP, and new TCP
connections; an `SSL_write` uprobe recovers HTTPS request paths before
encryption. Every event is attributed to the originating pod (`namespace/name`).
The same in-kernel hooks then **allow or deny egress** per pod by
domain / IP / CIDR / port, driven by Kubernetes-native `EgressPolicy` CRDs.

## How it works

- **One `cgroup_skb/egress` program** at the node's root cgroup v2 sees egress
  from **every pod on the node** — DNS, TLS ClientHello SNI, plaintext HTTP, and
  new TCP connections — no per-pod sidecar.
- **An `SSL_write` uprobe** reads HTTPS request plaintext **before** encryption,
  recovering paths the packet layer can't see. Auto-discovered per container's
  libssl, live (no sampling).
- **Attributed per pod** in-kernel via the originating cgroup id, enriched to
  `namespace/name` by a node-scoped Pods informer. The same maps carry policy
  verdicts back to the kernel for enforcement.

```
                       ┌─ cgroup_skb/egress ─ DNS / TLS-SNI / HTTP / CONNECT ─┐
[ pods on node ] ──────┤                          (+ cgroup id)                ├─► ebfw (Go) ─► attribute ─► text|json
                       └─ SSL_write uprobe ── HTTPS path (+headers, cgroup id)─┘        │
                                                                              k8s Pods informer (namespace/name)
```

## See it

```
DNS      10.42.0.9 ? example.com (TypeA)  pod=default/probe
TLS      10.42.0.9 -> example.com  (104.20.23.154:443)  pod=default/probe
HTTP     10.42.0.9 -> GET example.com/foo/bar  pod=default/probe
HTTPS  [pid=2550689 curl] GET example.com/secret/path?token=abc123  pod=default/probe
CONNECT  10.42.0.9 -> 104.20.23.154:443  pod=default/probe
```

Or structured JSON (`EBFW_OUTPUT=json`, one object per line):

```json
{"ts":"2026-06-28T09:14:01Z","kind":"https","domain":"example.com","method":"GET","path":"/secret/path","pid":2550689,"comm":"curl","pod":{"namespace":"default","name":"probe","uid":"be31e934-…","container":"ad68e835…","qos":"besteffort","node":"k3d-ebfw-server-0"}}
```

## Control it

Declare egress as Kubernetes resources — `EgressPolicy` (namespaced) and
`ClusterEgressPolicy` (cluster-wide) — and the agent enforces them in three modes:
`off` (observe), `log` (annotate verdicts, no drops), or `enforce` (drop denied
egress). A `defaultAction: Deny` plus a `podSelector` locks a labeled set of pods
to an allowlist. See [docs/egresspolicy.md](docs/egresspolicy.md).

## Quickstart

```bash
helm install ebfw ./helm/ebfw -n ebfw --create-namespace \
  --set agent.enforceMode=log        # observe verdicts first; flip to enforce when ready

kubectl apply -f config/samples/ebfw_v1_egresspolicy.yaml
```

Full guide → [**docs/install.md**](docs/install.md).

## License

[MIT](LICENSE) © dvrkn.

---

Built with the [eBPF skill](https://github.com/h0x0er/ebpf-skill) for
hook/map/verifier guidance and [`cilium/ebpf`](https://github.com/cilium/ebpf)
(ebpf-go, MIT) for the loader.
