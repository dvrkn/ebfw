package sslsnoop

// Compile bpf/sslsnoop.bpf.c and generate Go bindings in this package.
//
// Generation goes through bpf/gen-sslsnoop.sh so the -I include path can be
// pinned to the host arch's UAPI headers (uname -m). The uprobe's PT_REGS_*
// macros need the host's <asm/ptrace.h>, and the build image carries both
// multiarch dirs, so passing both would let clang grab the wrong arch's header.
// See bpf/gen-sslsnoop.sh for the full rationale.
//
//go:generate sh ../../bpf/gen-sslsnoop.sh
