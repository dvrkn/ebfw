package egress

// Compile bpf/egress.bpf.c and generate Go bindings in this package.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu" bpf ../../bpf/egress.bpf.c
