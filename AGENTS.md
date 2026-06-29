# AGENTS.md — guide for AI coding agents

Orientation for AI agents (and humans driving them) working on **ebfw**. The goal
of this file is to get you from "fresh clone" to "running the binary and making a
correct change" quickly.

- **User-facing docs:** [`README.md`](README.md) + [`docs/`](docs/) (install,
  configuration, egress policies, comparison).
- **Capabilities & what's deferred:** [`ROADMAP.md`](ROADMAP.md).
- **Deep, painful-to-rediscover gotchas:** `CLAUDE.md` (maintainer working notes —
  **git-ignored**, so it may be absent on a fresh clone; if it's there, read it
  before touching eBPF, attribution, or enforcement code).

## What ebfw is, in one paragraph

A single-binary node agent: a `cgroup_skb/egress` monitor **and** an `SSL_write`
uprobe in one process. It reports outgoing domains (DNS + TLS SNI), HTTP request
paths/headers, and new TCP connections, each attributed to the originating pod
(`namespace/name`), and allows/blocks egress by domain / IP / CIDR / port via a
pure policy engine (off / log / enforce). On Kubernetes it's driven by two CRDs
(`EgressPolicy` + `ClusterEgressPolicy`); off Kubernetes it reads a YAML policy
file. See [`README.md`](README.md) for architecture.

## Try the binary fast (standalone / container-host mode)

ebfw isn't tied to Kubernetes — the same agent watches and enforces egress for
every container (and host process) on a plain Docker/containerd host, driven by a
YAML file instead of CRDs. This is the quickest way to "try out the project."

### Step 0 — what can run where

| Task | macOS | Linux (kernel ≥ 5.8, cgroup v2, root) |
|---|---|---|
| `ebfw policy test` (offline policy eval) | ✅ | ✅ |
| Unit tests (`make test`) | ✅ | ✅ |
| Operator build + envtest (`make test-operator`) | ✅ | ✅ |
| **Run the agent (load eBPF, see live egress)** | ❌ | ✅ |

**eBPF cannot build or run on macOS** (Apple clang has no BPF backend). The agent
must run on Linux. The build itself happens *inside Docker* by default, so you
don't need clang locally — but loading the program needs a Linux kernel and root.

### Path A — evaluate a policy with zero setup (anywhere, no root, no kernel)

```bash
go run . policy test --policy examples/policy.yaml \
  --flow 'dst=203.0.113.5 port=443 domain=api.example.com' \
  --flow 'domain=evil.com port=443'
```

This exercises the pure `internal/policy` engine — the same code that drives
enforcement — without touching eBPF. Great first sanity check on any machine.

### Path B — build a host binary and run it on a Linux box

The binary is compiled in Docker (no local clang needed); you only need a Linux
host to *run* it as root.

```bash
# Build the host binary (any Docker host, incl. building cross via buildx):
docker build --target bin --output type=local,dest=out .   # -> out/ebfw
# (or, on a Linux box with clang + libbpf-dev:  make build  -> bin/ebfw)

# Visibility only — print every container's & host process's egress (defaults, no config):
sudo ./out/ebfw

# With enforcement from a YAML policy file (file is the default policy source):
sudo EBFW_ENFORCE_MODE=log    EBFW_POLICY=examples/policy.yaml ./out/ebfw   # annotate, no drops
sudo EBFW_ENFORCE_MODE=enforce EBFW_POLICY=examples/policy.yaml ./out/ebfw  # actually drop
```

Then generate traffic in another shell (`curl https://example.com/foo/bar`) and
watch it attributed. Add `EBFW_OUTPUT=json` for structured lines.

⚠️ **Enforcement is host-wide** (hooks attach at the root cgroup). A
`defaultAction: Deny` policy cuts off the *whole host* — keep `udp:53` reachable
and prefer a blocklist on a real box so you don't lock yourself out of SSH.

### Path C — run the published agent image as a privileged container

```bash
docker run -d --name ebfw \
  --privileged --network host --pid host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v "$PWD/examples/policy.yaml:/etc/ebfw/policy.yaml:ro" \
  -e EBFW_ENFORCE_MODE=log -e EBFW_POLICY=/etc/ebfw/policy.yaml \
  ghcr.io/dvrkn/ebfw:latest
```

Full standalone reference (config mounts, capabilities instead of `--privileged`,
attribution caveats off-Kubernetes):
[`docs/install.md` → Run standalone](docs/install.md#run-standalone-container-hosts-no-kubernetes).

### Kubernetes path

If you want the full CRD-driven experience, install the Helm chart on a throwaway
k3d cluster — see [`docs/install.md`](docs/install.md) and the automated loop in
[`test/crd.sh`](test/crd.sh).

> A Linux dev/test box (kernel ≥ 5.8, cgroup v2, Docker + k3d) is the only way to
> actually exercise TCP/TLS/HTTP and the verifier. Maintainer-specific box details
> (if any) live in the git-ignored `CLAUDE.md`, not here.

## Build / test cheat sheet

```bash
make test            # unit tests (no eBPF; runs on macOS/Linux) — run this before any commit
make docker          # build the agent image (BPF + Go compiled inside Docker; any host)
make build           # native agent binary (Linux only; needs clang + libbpf-dev)
make generate        # bpf2go (regenerate *_bpfel.go + *.o) — NOT controller-gen

# Operator subset — pure Go, builds & tests on macOS (never imports internal/egress):
make deepcopy        # controller-gen DeepCopy for api/v1
make manifests       # controller-gen CRDs (-> config/crd/bases) + operator RBAC
make test-operator   # api + controller envtest (downloads envtest binaries)
make operator-build  # bin/ebfw-operator

# Linux host e2e (root): builds out/ebfw, generates real curl traffic, asserts captures + drops:
docker build --target bin --output type=local,dest=out . && sudo ./test/e2e.sh out/ebfw
```

**Gotcha:** `make generate` is **bpf2go**, not kubebuilder's controller-gen.
controller-gen lives under `deepcopy` and `manifests`. Change a BPF event struct in
`bpf/*.bpf.c`? The Go side decodes by hand-coded offsets — **edit the C and Go
together** or you get silent corruption (see `CLAUDE.md` if present).

## Skills references

- **eBPF skill** — the project was built with the
  [ebpf-skill](https://github.com/h0x0er/ebpf-skill) (hook/map/verifier guidance).
  It's vendored at `./ebpf-skill/` but **git-ignored** (it's a separate repo); clone
  it yourself if it's missing:
  ```bash
  git clone https://github.com/h0x0er/ebpf-skill
  ```
  Point your agent at `ebpf-skill/SKILL.md` as the entry skill for anything touching
  `bpf/*.bpf.c`, map design, or verifier failures. Useful external links are in
  `ebpf-skill/references.md`. Also rely on
  [`cilium/ebpf`](https://pkg.go.dev/github.com/cilium/ebpf) (the loader) docs.

- **Claude Code workflow skills** most relevant here (invoke with `/<name>`):
  - `/code-review` — review the working diff for correctness bugs + cleanups.
  - `/security-review` — security review of pending changes (this is a firewall;
    use it for datapath/enforcement changes).
  - `/verify` & `/run` — run the app and confirm a change behaves (Linux box).
  - `/init` — regenerate CLAUDE.md-style codebase notes.

## Agentic contribution rules

Read these before committing — they override default agent behavior.

1. **Branch, don't push to `main` directly.** Branch off `main`, push over SSH, and
   open the PR via the web URL printed on push (the local `gh` CLI may not have API
   access to this repo). Commit/push only when the user asks.
2. **Always `make test` before committing.** For agent/eBPF changes, also build the
   image (`make docker`) and, when you can, run the binary or `test/e2e.sh` on a
   Linux box — the verifier only runs at program *load*, so a green Docker build
   proves compile, **not** acceptance.
3. **Keep `internal/policy` pure** (no eBPF / k8s / runtime / deepcopy imports).
   `api/v1` mirrors it for the CRDs via `Spec.ToPolicy()`; don't add kubebuilder
   markers to `internal/policy`.
4. **Keep the operator off the eBPF graph.** `cmd/operator` must never import
   `internal/egress` (it builds on macOS without clang). Verify:
   `go list -deps ./cmd/operator | grep internal/egress` (must be empty).
5. **Update docs with behavior.** User-facing changes → `README.md` / `docs/`;
   capability/roadmap changes → `ROADMAP.md`; hard-won internals → `CLAUDE.md`.

## Where things live

```
main.go                  agent entrypoint (config + signals; runs both data sources + enforcement wiring)
internal/config/         YAML config + env toggles + Filter
internal/egress/         cgroup_skb/egress program + loader            (Linux/eBPF)
internal/sslsnoop/       SSL_write uprobe + libssl auto-discovery      (Linux/eBPF)
internal/attr/           pod attribution (cgroup parser, id->path, k8s informer)
internal/output/         Event model + text/json sinks (single emit chokepoint)
internal/l7/             HTTP/1.x + HTTP/2 (HPACK) request parsing
internal/tlsparse/       TLS ClientHello -> SNI
internal/policy/         PURE policy model + engine + file source + aggregation
internal/enforce/        decorates the sink with verdicts + programs BPF maps
internal/crdsource/      PolicySource backed by the CRDs (in-process informer)
internal/controller/     thin status-only CRD reconcilers
internal/cli/            `ebfw policy test`
internal/metrics/        Prometheus /metrics
api/v1/                  EgressPolicy + ClusterEgressPolicy types (+ ToPolicy)
cmd/operator/            control-plane operator (pure Go)
config/, helm/ebfw/      kubebuilder kustomize tree + Helm chart
bpf/*.bpf.c              the eBPF C programs
examples/policy.yaml     example file-based policy (also the `policy test` fixture)
test/e2e.sh, test/crd.sh host e2e + k3d e2e
```
