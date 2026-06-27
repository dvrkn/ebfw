package sslsnoop

// Compile bpf/sslsnoop.bpf.c and generate Go bindings in this package.
//
// -target native builds for the host arch and sets the matching __TARGET_ARCH_*
// that bpf_tracing.h needs for the PT_REGS_* uprobe argument macros (so this
// works on amd64 CI and arm64 hosts alike). The extra -I paths supply the
// multiarch UAPI headers; only the host arch's directory exists and is used.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target native -cflags "-O2 -g -Wall -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu" ssl ../../bpf/sslsnoop.bpf.c
