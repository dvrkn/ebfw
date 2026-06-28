#!/bin/sh
# Generate Go bindings for the SSL_write uprobe. Invoked by `go generate` from the
# internal/sslsnoop package directory (see internal/sslsnoop/gen.go).
#
# Why a script instead of an inline //go:generate line: the uprobe uses
# bpf_tracing.h's PT_REGS_* macros, which need the *host* arch's <asm/ptrace.h>
# (x86 exposes `struct pt_regs`, arm64 exposes `struct user_pt_regs`). The build
# image ships BOTH multiarch include dirs (/usr/include/{x86_64,aarch64}-linux-gnu),
# so passing both -I lets clang pick whichever is listed first — wrong on the other
# arch, yielding "incomplete definition of struct pt_regs". We therefore point -I
# at only the host triplet (uname -m -> x86_64 / aarch64). `-target native`
# supplies the matching __TARGET_ARCH_* macro.
set -e
exec go run github.com/cilium/ebpf/cmd/bpf2go \
  -cc clang -target native \
  -cflags "-O2 -g -Wall -I/usr/include/$(uname -m)-linux-gnu" \
  ssl ../../bpf/sslsnoop.bpf.c
