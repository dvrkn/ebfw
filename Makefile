IMAGE ?= ebfw:dev

.PHONY: generate build test docker kind-load k3d-import clean

# Compile the BPF programs and generate Go bindings (needs clang + libbpf-dev; Linux).
generate:
	go generate ./...

# Build the single ebfw binary (run `make generate` first). Native build; Linux.
build: generate
	CGO_ENABLED=0 go build -trimpath -o bin/ebfw .

# Unit tests that don't need eBPF (e.g. the TLS SNI parser). Runs anywhere.
test:
	go test ./...

# Build the container image (BPF + Go compiled inside; works on any Docker host).
docker:
	docker build -t $(IMAGE) .

# Load the image into a local kind cluster.
kind-load: docker
	kind load docker-image $(IMAGE)

# Import the image into a k3d cluster (CLUSTER defaults to ebfw).
CLUSTER ?= ebfw
k3d-import: docker
	k3d image import $(IMAGE) -c $(CLUSTER)

clean:
	rm -rf bin out
	rm -f internal/*/*_bpfel.go internal/*/*_bpfeb.go internal/*/*.o
