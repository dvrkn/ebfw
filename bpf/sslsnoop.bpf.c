// SPDX-License-Identifier: GPL-2.0
//
// sslsnoop (uprobe).
//
// Captures the *plaintext* of TLS traffic before it is encrypted — the only
// non-MITM way to see HTTPS request paths (encrypted on the wire, so invisible
// to the packet-level egress monitor). Two entry points feed one ring buffer:
//
//   1. OpenSSL's dynamically-linked SSL_write (curl, nginx, most C/Python/…):
//        int SSL_write(SSL *ssl, const void *buf, int num);
//        arg1 = SSL*   arg2 = buf (plaintext)   arg3 = num (length)
//
//   2. Go's statically-linked crypto/tls.(*Conn).Write (any net/http client):
//        func (c *Conn) Write(b []byte) (int, error)
//      Go does NOT call SSL_write, so OpenSSL's uprobe never sees it. We attach
//      directly to the Go symbol instead and read Go's register-based ABIInternal
//      (Go >= 1.17): integer/pointer args go in a fixed register sequence, not the
//      C ABI, so we cannot use BPF_UPROBE's PT_REGS_PARM* — we read the registers
//      by hand per arch. For (*Conn).Write the sequence is (c, b.ptr, b.len, b.cap):
//        amd64: RAX, RBX, RCX, RDI      arm64: R0, R1, R2, R3
//      The *Conn pointer stands in for SSL* as the per-connection key.
//
// Both paths copy up to MAX_DATA bytes of the buffer to userspace via the ring
// buffer; HTTP parsing (HTTP/1.x and HTTP/2 + HPACK) happens in Go.

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

// Field offsets are mirrored by hand in internal/sslsnoop/sslsnoop.go (hdrLen +
// the buf[a:b] slices). Keep them in sync. Layout: pid@0 data_len@4 comm@8(16)
// ssl@24 cgroup_id@32 data@40.
struct ssl_event {
	__u32 pid;
	__u32 data_len;
	__u8  comm[COMM_LEN];
	__u64 ssl;        // SSL* — per-connection key for HTTP/2 HPACK state
	__u64 cgroup_id;  // cgroup v2 id of the calling task — pod attribution
	__u8  data[MAX_DATA];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB
} ssl_events SEC(".maps");

// submit_plaintext reserves an event, tags it with the calling task's identity,
// copies up to MAX_DATA bytes of buf, and submits. `key` is the per-connection
// identifier (SSL* for OpenSSL, *Conn for Go). Shared by both uprobes.
static __always_inline int submit_plaintext(__u64 key, const void *buf, __u64 num)
{
	if (num == 0 || buf == 0)
		return 0;

	struct ssl_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ssl = key;
	// cgroup v2 id of the calling task, captured here (in process context) so
	// attribution doesn't race the process exiting — short-lived TLS clients
	// (curl, etc.) are often gone before userspace could read /proc.
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Verifier-friendly clamp as in the egress program: __u64 + clamp +
	// barrier + non-zero guard, so the bound lands on the register passed as
	// the read length.
	__u64 n = num;
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

// BPF_UPROBE (libbpf >= 1.2, provided by the trixie build image) extracts the
// function arguments from pt_regs following the C ABI.
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write, void *ssl, const void *buf, int num)
{
	if (num <= 0)
		return 0;
	return submit_plaintext((__u64)(unsigned long)ssl, buf, (__u32)num);
}

// Go's ABIInternal (Go >= 1.17) passes integer/pointer args in a fixed register
// sequence, NOT the C ABI, so BPF_UPROBE's PT_REGS_PARM* would read the wrong
// registers. Read them by hand per arch. go_arg(ctx, i) returns the i-th
// integer-class argument register in ABIInternal order.
#if defined(__TARGET_ARCH_x86)
static __always_inline __u64 go_arg(struct pt_regs *ctx, int i)
{
	switch (i) {
	case 0: return ctx->ax; // RAX
	case 1: return ctx->bx; // RBX
	case 2: return ctx->cx; // RCX
	case 3: return ctx->di; // RDI
	}
	return 0;
}
#elif defined(__TARGET_ARCH_arm64)
static __always_inline __u64 go_arg(struct pt_regs *ctx, int i)
{
	// arm64 UAPI exposes the register file as struct user_pt_regs (regs[0..30]);
	// ABIInternal integer args start at R0.
	return ((const struct user_pt_regs *)ctx)->regs[i & 31];
}
#else
static __always_inline __u64 go_arg(struct pt_regs *ctx, int i) { return 0; }
#endif

// crypto/tls.(*Conn).Write(b []byte): args in ABIInternal order are
// (c=*Conn, b.ptr, b.len, b.cap). We key on c and copy b.ptr[0:b.len].
SEC("uprobe/go_tls_write")
int go_tls_write(struct pt_regs *ctx)
{
	__u64 conn = go_arg(ctx, 0);
	const void *buf = (const void *)go_arg(ctx, 1);
	__s64 len = (__s64)go_arg(ctx, 2);
	if (len <= 0)
		return 0;
	return submit_plaintext(conn, buf, (__u64)len);
}
