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
