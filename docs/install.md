# Install & run

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

`ebfw` is installed with the Helm chart in [`helm/ebfw`](https://github.com/dvrkn/ebfw/tree/main/helm/ebfw) — CRDs, the
operator, and the per-node agent DaemonSet.

```bash
helm install ebfw ./helm/ebfw --namespace ebfw --create-namespace \
  --set agent.enforceMode=log        # observe verdicts first; flip to enforce when ready

kubectl apply -f config/samples/ebfw_v1_egresspolicy.yaml
kubectl get egp,cegp -A

# watch the agent on a node:
kubectl -n ebfw logs -f ds/ebfw
```

Generate egress from any pod, then watch it attributed:

```bash
kubectl run probe --rm -it --image=nicolaka/netshoot --restart=Never -- \
  curl -4 --http1.1 https://example.com/foo/bar
```

The agent DaemonSet runs `privileged` + `hostNetwork` + `hostPID` (the last is
needed to find each container's libssl via `/proc`). Fine-grained capabilities
instead of `privileged` (kernel-dependent): `CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN,
CAP_SYS_ADMIN`.

**Visibility only** (no enforcement, no operator):

```bash
helm install ebfw ./helm/ebfw -n ebfw --create-namespace \
  --set operator.enabled=false --set agent.enforceMode=off
```

See [configuration.md](configuration.md) for every chart value and agent env var,
and [egresspolicy.md](egresspolicy.md) for the policy CRD reference.

## Run standalone (container hosts, no Kubernetes)

`ebfw` is Kubernetes-native, but it isn't tied to Kubernetes: the agent is a single
self-contained binary that watches and enforces egress for **every container on a
plain container host** (Docker / containerd) via the same root-cgroup eBPF hooks —
no orchestrator, API server, CRDs, or operator. Policy comes from a **YAML file**
instead of the CRDs. This is the right fit for a Docker/containerd VM, an edge
node, or trying enforcement out before wiring up the chart.

You can run ebfw either as the published agent image (the container-native way) or
as a host binary.

**As a container** — the agent image is just the static binary, so run it
privileged with host networking, host PID (to find each container's `libssl`), and
the cgroup + policy mounts:

```bash
docker run -d --name ebfw \
  --privileged --network host --pid host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v "$PWD/config.yaml:/etc/ebfw/config.yaml:ro" \
  -v "$PWD/policy.yaml:/etc/ebfw/policy.yaml:ro" \
  -e EBFW_CONFIG=/etc/ebfw/config.yaml \
  -e EBFW_ENFORCE_MODE=enforce -e EBFW_POLICY=/etc/ebfw/policy.yaml \
  ghcr.io/dvrkn/ebfw:latest
```

**As a host binary** — build it (no clang needed; compiled in Docker) and run it
as root with a filter config and, optionally, a policy file:

```bash
docker build --target bin --output type=local,dest=out .   # -> out/ebfw
                                                            # (or `make build` on Linux w/ clang + libbpf-dev)

# Visibility only — print every container's (and host process's) egress:
sudo EBFW_CONFIG=config.yaml ./out/ebfw

# With enforcement from a YAML policy (file is the default source):
sudo EBFW_CONFIG=config.yaml \
  EBFW_ENFORCE_MODE=enforce \
  EBFW_POLICY=policy.yaml \
  ./out/ebfw
```

- **Policy source is the file by default.** `EBFW_POLICY_SOURCE=file` (the default
  off-cluster) reads `EBFW_POLICY`; see
  [Policy file format](configuration.md#policy-file-format) for the schema and
  [`examples/policy.yaml`](https://github.com/dvrkn/ebfw/blob/main/examples/policy.yaml)
  for a worked example. The file is **hot-reloaded** on change — a bad reload is
  logged and ignored, keeping the last good policy. No `crd` source, operator, or
  RBAC is involved.
- **Capabilities.** Run as root, or grant `CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN,
  CAP_SYS_ADMIN` (kernel-dependent) and (for HTTPS path capture) read access to
  other processes' `/proc/<pid>/maps` to locate their `libssl`.
- **Enforcement is host-wide.** The hooks attach at the host's root cgroup, so a
  `defaultAction: Deny` policy cuts off **the whole host** — every container *and*
  the host itself (don't lock yourself out of SSH / package mirrors). On a container
  host, prefer a **blocklist** (`defaultAction: Allow` + `Deny` rules), and always
  keep `udp:53` reachable so DNS resolves.
- **Attribution degrades to PID/destination.** Pod attribution is built on the
  Kubernetes cgroup layout (`kubepods/…`) plus the Pods informer, so on a plain
  Docker/containerd host neither applies: there's no `namespace/name`, and
  `podSelector` / `match.pod` rules program nothing (they need pod labels). Events
  still show the connecting **PID and command** (HTTPS via the uprobe) and the
  **destination** (domain / IP / port), and **node-wide rules** (IP / CIDR / domain
  / port, no pod selector) see and enforce against every container's traffic
  normally — the visibility and the datapath are container-agnostic.

Validate a policy offline first — no kernel, no root:

```bash
./out/ebfw policy test --policy policy.yaml \
  --flow 'dst=203.0.113.5 port=443 domain=api.example.com' \
  --flow 'domain=evil.com port=443'
```

Everything else (env vars, filter config, metrics) is identical to the in-cluster
agent — see [configuration.md](configuration.md).

## Images

Published multi-arch by CI on `main`/tags after the test jobs pass:

- `ghcr.io/dvrkn/ebfw` — agent
- `ghcr.io/dvrkn/ebfw-operator` — operator

## Tests

```bash
# Host e2e: runs the binary on a Linux host, generates real curl traffic, and
# asserts captures — DNS / TLS SNI / HTTP+HTTPS paths / headers / filter / enforce.
docker build --target bin --output type=local,dest=out .   # -> out/ebfw
sudo ./test/e2e.sh out/ebfw

# Kubernetes e2e: installs the chart on a throwaway k3d cluster and asserts pod
# attribution + CRD-driven enforcement end to end.
./test/crd.sh
```

## Repository layout

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
config/                    kubebuilder kustomize tree (generated CRDs, RBAC, manager, samples)
helm/ebfw/                 Helm chart: CRDs + operator + agent DaemonSet
examples/policy.yaml       example file-based egress policy (also the `policy test` fixture)
bpf/egress.bpf.c           the cgroup_skb/egress program
bpf/sslsnoop.bpf.c         the SSL_write uprobe program
test/e2e.sh                host e2e (domain / ssl / paths / headers / filter / metrics / enforcement)
test/crd.sh                k3d e2e (Helm install + pod attribution + CRD-driven enforcement)
Dockerfile                 agent image: multi-stage (BPF + Go), or `--target bin` host binary
Dockerfile.operator        operator image (pure Go, no eBPF)
```
