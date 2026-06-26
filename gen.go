package main

// Compile bpf/egress.bpf.c and generate Go bindings (bpf_bpfel.go + the
// embedded object). Runs as part of `go generate ./...` / `make generate`.
//
// The extra -I paths point clang at the multiarch UAPI headers (asm/types.h
// etc.) on Debian-based build images; the non-matching arch path is harmless.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu" bpf bpf/egress.bpf.c
