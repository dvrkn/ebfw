// SPDX-License-Identifier: GPL-2.0
//
// sslsnoop (uprobe PoC).
//
// Attaches a uprobe to OpenSSL's SSL_write to capture the *plaintext* of TLS
// traffic before it is encrypted. This is the only non-MITM way to see HTTPS
// request paths (which are encrypted on the wire and therefore invisible to the
// packet-level egress monitor).
//
// int SSL_write(SSL *ssl, const void *buf, int num);
//   arg1 = SSL*   arg2 = buf (plaintext)   arg3 = num (length)
//
// The probe copies up to MAX_DATA bytes of the buffer to userspace via a ring
// buffer; HTTP parsing happens in Go.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// PT_REGS_* dereference the arch's pt_regs; provide its definition (we don't use
// vmlinux.h). The target arch macro (__TARGET_ARCH_*) needed by bpf_tracing.h is
// set by bpf2go via `-target native`, so this builds correctly on amd64 or arm64.
#include <asm/ptrace.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_DATA 4096
#define COMM_LEN 16

// barrier_var() is provided by bpf_helpers.h; it pins a value in one register
// so the verifier's bound on it survives to the helper call.

struct ssl_event {
	__u32 pid;
	__u32 data_len;
	__u8  comm[COMM_LEN];
	__u64 ssl;   // SSL* — per-connection key for HTTP/2 HPACK state
	__u8  data[MAX_DATA];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB
} ssl_events SEC(".maps");

// BPF_UPROBE (libbpf >= 1.2, provided by the trixie build image) extracts the
// function arguments from pt_regs.
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write, void *ssl, const void *buf, int num)
{
	if (num <= 0 || buf == 0)
		return 0;

	struct ssl_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ssl = (__u64)(unsigned long)ssl;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Same verifier-friendly clamp as the egress program: __u64 + clamp +
	// barrier + non-zero guard, so the bound lands on the register passed as
	// the read length.
	__u64 n = (__u32)num;
	if (n > MAX_DATA)
		n = MAX_DATA;
	barrier_var(n);
	e->data_len = 0;
	if (n != 0) {
		barrier_var(n);
		if (bpf_probe_read_user(e->data, n, buf) == 0)
			e->data_len = (__u32)n;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
