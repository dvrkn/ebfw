# Tests

ebfw is exercised by unit tests, controller envtest, and two end-to-end suites
that run the real datapath against real traffic.

```bash
# Unit tests (no eBPF, runs anywhere); operator controllers under envtest.
make test            # everything except internal/controller (which needs envtest)
make test-operator   # api + controller envtest (downloads envtest binaries)

# Host e2e: runs the binary on a Linux host, generates real curl traffic, and
# asserts captures — DNS / TLS SNI / HTTP+HTTPS paths / headers / filter / enforce.
docker build --target bin --output type=local,dest=out .   # -> out/ebfw
sudo ./test/e2e.sh out/ebfw

# Kubernetes e2e: installs the chart on a throwaway k3d cluster and asserts the
# full CRD-driven path end to end.
./test/crd.sh
```

## Host e2e — `test/e2e.sh`

Linux host, eBPF, root. Covers visibility — DNS, TLS SNI, HTTP/1.x + HTTP/2
request paths, headers — plus internal-traffic filtering, IPv4 + IPv6 packet
decoding, JSON output, and enforcement: a CIDR deny drops the connection, a domain
deny blocks via DNS→IP learning, and `log` mode annotates the verdict without
dropping.

## Kubernetes e2e — `test/crd.sh`

k3d + Helm. Installs the CRDs, operator, and agent (enforce mode,
`EBFW_POLICY_SOURCE=crd`) on a throwaway cluster and asserts the full CRD-driven
path:

- pod attribution — DNS / TLS / HTTP / HTTPS events mapped to the originating pod;
- operator validation — valid resources are marked `Accepted=True`, invalid ones
  `Accepted=False`;
- a namespaced `EgressPolicy` deny, programmed by the agent and attributed to the pod;
- a namespaced `defaultAction: Deny` walls off only that namespace's pods while
  node-global egress stays open;
- a `ClusterEgressPolicy` deny applies node-wide;
- a `spec.podSelector` scopes a policy to a labeled subset of pods;
- **CR lifecycle** — editing a CR applies the new rule live (hot-reload), deleting a
  CR lifts its enforcement, and an invalid CR is dropped while valid CRs keep
  enforcing (asserted at both the operator status and the agent datapath);
- **policy merge** — multiple policies over one pod merge by the union of their
  denies, a `ClusterEgressPolicy` and a namespaced `EgressPolicy` stack on the same
  pod, and a longer-prefix Allow overrides a broader Deny (most-specific match);
- **cross-namespace isolation** — a namespaced deny stays in its own namespace and
  does not leak into another;
- **domain deny via CRD** — a `domains:` rule blocks the resolved IPs through the
  DNS→IP learner;
- **deferred dimensions** — port-only / IPv6 / L7 (method, path) rules are evaluated
  for log/metrics but not dropped at the cgroup datapath (logged-not-dropped);
- **node-wide lockdown** — a podSelector-less `ClusterEgressPolicy`
  `defaultAction: Deny` flips the global default to Deny; an internal-CIDR + `udp:53`
  allowlist keeps DNS and the API server up while external egress is denied, and
  deleting it restores egress;
- **log mode via CRD** — with `enforceMode=log`, a CRD deny annotates the verdict on
  the event without dropping the connection.

## CI

[`.github/workflows/e2e.yml`](https://github.com/dvrkn/ebfw/blob/main/.github/workflows/e2e.yml)
runs the unit tests, `make test-operator` (envtest), `test/e2e.sh`, and
`test/crd.sh` on `ubuntu-24.04` for every push and pull request.
