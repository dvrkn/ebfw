IMAGE ?= ebfw:dev

.PHONY: generate build test docker kind-load clean

# Compile the BPF program and generate Go bindings (needs clang + libbpf-dev; Linux).
generate:
	go generate ./...

# Build the agent binary (run `make generate` first). Native build; Linux.
build: generate
	CGO_ENABLED=0 go build -trimpath -o bin/ebfw .

# Unit tests that don't need eBPF (e.g. the TLS SNI parser). Runs anywhere.
test:
	go test ./...

# Build the container image. BPF + Go are compiled inside the image, so this
# works on any host with Docker (no local clang/kernel needed).
docker:
	docker build -t $(IMAGE) .

# Load the image into a local kind cluster.
kind-load: docker
	kind load docker-image $(IMAGE)

clean:
	rm -rf bin
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
