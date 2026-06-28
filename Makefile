IMAGE ?= ebfw:dev
OPERATOR_IMAGE ?= ebfw-operator:dev

.PHONY: generate build test docker kind-load k3d-import clean \
	deepcopy manifests operator-build operator-docker test-operator \
	controller-gen envtest setup-envtest install uninstall

# ── agent (eBPF) ────────────────────────────────────────────────────────────

# Compile the BPF programs and generate Go bindings (needs clang + libbpf-dev; Linux).
generate:
	go generate ./...

# Build the single ebfw agent binary (run `make generate` first). Native build; Linux.
build: generate
	CGO_ENABLED=0 go build -trimpath -o bin/ebfw .

# Unit tests that don't need eBPF (e.g. the TLS SNI parser, policy engine). Runs anywhere.
test:
	go test ./...

# Build the agent container image (BPF + Go compiled inside; works on any Docker host).
docker:
	docker build -t $(IMAGE) .

# Load the agent image into a local kind cluster.
kind-load: docker
	kind load docker-image $(IMAGE)

# Import the agent image into a k3d cluster (CLUSTER defaults to ebfw).
CLUSTER ?= ebfw
k3d-import: docker
	k3d image import $(IMAGE) -c $(CLUSTER)

clean:
	rm -rf bin out
	rm -f internal/*/*_bpfel.go internal/*/*_bpfeb.go internal/*/*.o

# ── operator (control plane; pure Go, no eBPF) ──────────────────────────────
# NOTE: `make generate` above is bpf2go. The operator's controller-gen codegen
# lives under `deepcopy` and `manifests`. Both scope paths to ./api and
# ./internal/controller so they run on machines without the bpf2go output.

# Generate DeepCopy methods for the API types.
deepcopy: controller-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./api/..."

# Generate CRDs + the operator ClusterRole from +kubebuilder markers.
manifests: controller-gen
	$(CONTROLLER_GEN) rbac:roleName=ebfw-operator crd webhook \
		paths="./api/..." paths="./internal/controller/..." \
		output:crd:artifacts:config=config/crd/bases

# Build the operator manager binary.
operator-build:
	CGO_ENABLED=0 go build -trimpath -o bin/ebfw-operator ./cmd/operator

# Build the operator container image (no eBPF toolchain needed).
operator-docker:
	docker build -f Dockerfile.operator -t $(OPERATOR_IMAGE) .

# Run the operator/API unit + envtest tests (pure Go; no root, no eBPF).
test-operator: manifests deepcopy setup-envtest
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" \
		go test ./api/... ./internal/controller/... -coverprofile cover-operator.out

# Install/uninstall just the CRDs into the cluster in ~/.kube/config.
install: manifests
	kubectl apply -f config/crd/bases

uninstall:
	kubectl delete --ignore-not-found -f config/crd/bases

# ── operator tooling (installed into ./bin, pinned) ─────────────────────────

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest

CONTROLLER_TOOLS_VERSION ?= v0.20.1
# release branch of controller-runtime to fetch the envtest setup tool (e.g. release-0.24).
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
# Kubernetes version for the ENVTEST binaries (e.g. 1.36), derived from k8s.io/api.
ENVTEST_K8S_VERSION ?= $(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{printf "1.%d", $$3}')

controller-gen: $(CONTROLLER_GEN)
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

envtest: $(ENVTEST)
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

setup-envtest: envtest
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path >/dev/null

# go-install-tool installs a versioned tool binary into $(LOCALBIN) (idempotent).
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef
