# ebfw vs Cilium

A common question: *"why not just use Cilium?"* This page is the honest, long-form
answer. Short version lives in the [README](https://github.com/dvrkn/ebfw#how-is-this-different-from-cilium).

## They aren't the same category

**Cilium is a CNI** — it wants to *be* your cluster's network dataplane: pod-to-pod
connectivity, IPAM, kube-proxy replacement, encryption, load balancing, and full
L3/L4/L7 policy in both directions. **ebfw is not a CNI.** It's a single node-level
agent that attaches at the **root cgroup** and rides *alongside* whatever CNI you
already run (Calico, flannel, Cilium itself, k3d's default — it doesn't matter). It
does one job: see and control **egress**, attributed per pod.

So the fair comparison isn't "ebfw vs Cilium the platform" — it's "ebfw vs the
egress-firewall slice of Cilium" (`toFQDNs`, L7 HTTP policy, Hubble flow visibility).

## At a glance

| | **ebfw** | **Cilium** |
|---|---|---|
| **What it is** | Add-on egress agent (1 DaemonSet + thin operator) | Full CNI / networking platform |
| **Install footprint** | One ~40 MB binary, no dataplane takeover | Replaces / owns cluster networking |
| **HTTPS L7 visibility** | `SSL_write` **uprobe** reads plaintext *before* encryption — no proxy, no MITM, no cert injection | Terminating **Envoy + TLS** (you provide certs; Envoy MITMs the flow) |
| **L7 enforcement** | Evaluated for log/metrics; **drop is on the roadmap** | Drops on HTTP method/path/header, Kafka, gRPC **today** |
| **Domain policy** | DNS→IP learning at a `cgroup_skb/ingress` hook (LRU + TTL) | DNS proxy intercepts queries (`toFQDNs`) |
| **Scope** | Egress only | Full L3/L4/L7, ingress + egress, east-west |
| **Outside Kubernetes** | Yes — same agent on a plain Docker/containerd host with a YAML file | Kubernetes-centric |
| **Policy model** | 2 CRDs over a pure, unit-testable engine | Rich CNP/CCNP + identity model |
| **Maturity** | Early (single project, focused scope) | CNCF-graduated, production-hardened, scale-tested |

## Where ebfw wins

1. **No proxy in the data path for L7 visibility.** This is the big one. To see HTTP
   method / path / headers on **HTTPS**, Cilium has to terminate TLS through Envoy —
   a man-in-the-middle with injected certs sitting in every flow. ebfw recovers the
   same plaintext request line by hooking `SSL_write` *before* encryption: no latency
   tax, no cert management, no proxy to operate.
   *Caveat:* the uprobe is OpenSSL-dynamic only — it misses statically-linked TLS
   (Go `crypto/tls`, Java, rustls). Envoy termination catches all of those.

2. **Additive, not a commitment.** Adopting Cilium means adopting (or CNI-chaining
   into) a network dataplane — a cluster-wide, hard-to-reverse decision. ebfw is a
   DaemonSet you drop on, observe in `log` mode, and remove with zero effect on
   connectivity, because it never touches how packets are routed.

3. **Runs without Kubernetes.** The same binary watches and enforces egress for every
   container on a bare Docker / containerd host, driven by a YAML policy file — no
   API server, no operator. Cilium's value is bound to a cluster.

4. **Radically simpler operationally.** One pure policy engine, two CRDs, a
   status-only operator, and an `off → log → enforce` rollout. No Envoy, no DNS proxy,
   no identity-allocation subsystem to reason about or debug.

5. **Per-pod attribution done in-kernel via cgroup id.** Even short-lived clients
   (a `curl` that exits before the event is processed) are attributed correctly — no
   racy userspace `/proc/<pid>/cgroup` reads.

## Where Cilium wins

Stated plainly, because the honest comparison matters:

- **L7 *enforcement*.** Cilium *drops* on HTTP method / path / header (and Kafka /
  gRPC) today. ebfw evaluates those dimensions for log + metrics but **does not yet
  drop on them** — that needs the terminating proxy + TLS MITM we've deliberately
  avoided. It's on the [roadmap](https://github.com/dvrkn/ebfw/blob/main/ROADMAP.md).
- **Universal TLS coverage.** Envoy termination sees every TLS library; our uprobe
  sees OpenSSL-dynamic only.
- **Breadth & maturity.** Ingress policy, encryption, load balancing, multi-cluster,
  identity-based scaling, HA, multi-kernel CI, scale tests, CNCF-graduated. ebfw is
  early: IPv6 enforcement is incomplete, there's no map pinning yet, and it's
  single-kernel-tested.

## Bottom line

Reach for **ebfw** when you want *"what is each pod talking to, and lock it down"* —
without adopting a CNI or putting a TLS-terminating proxy in front of every
connection. Reach for **Cilium** when you want a full networking platform and need
hard L7 enforcement now. They also compose: ebfw runs perfectly well on a
Cilium-CNI cluster, adding pre-encryption HTTPS visibility Cilium can't get without
Envoy.
