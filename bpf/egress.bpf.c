// SPDX-License-Identifier: GPL-2.0
//
// ebfw egress monitor (Stage-0 PoC).
//
// A cgroup_skb/egress program. Attached at the node's root cgroup v2 it sees
// every egress packet from every pod on the node. It does NO protocol parsing
// itself: it bounds-checks, classifies the packet, and copies the relevant
// bytes up to userspace via a ring buffer. All DNS/TLS/HTTP parsing happens in
// Go where loops and string handling are safe.
//
// Event kinds emitted:
//   EVT_CONNECT  new TCP connection (SYN & !ACK)        -> dst ip:port
//   EVT_DNS      UDP datagram to port 53                -> raw DNS payload
//   EVT_TLS      TLS ClientHello (record 0x16, hs 0x01) -> raw TLS bytes (SNI)
//   EVT_HTTP     TCP payload starting with an HTTP verb -> raw request bytes
//
// No vmlinux.h / CO-RE: we use UAPI headers only, so the runtime needs no BTF.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define EVT_CONNECT 1
#define EVT_DNS     2
#define EVT_TLS     3
#define EVT_HTTP    4

#define MAX_PAYLOAD 512

// Force the compiler to keep a value in a single register so the verifier's
// bound on it isn't lost to a decoupled copy (a common variable-length copy
// pitfall). See libbpf's bpf_helpers.h barrier_var().
#define barrier_var(var) asm volatile("" : "+r"(var))

// Field offsets are mirrored by hand in internal/egress/egress.go (hdrLen + the
// raw[a:b] slices). If you change this layout, change that file in lockstep.
// _pad2 keeps cgroup_id 8-byte aligned so the leading fields (offsets 0..19)
// stay put and only the header tail moves.
struct event {
	__u8  evt_type;     // off 0   EVT_*
	__u8  ip_version;   // off 1   4 (IPv6 is a later stage)
	__u8  l4_proto;     // off 2   IPPROTO_TCP / IPPROTO_UDP
	__u8  _pad;         // off 3
	__be32 saddr;       // off 4   network byte order
	__be32 daddr;       // off 8   network byte order
	__be16 sport;       // off 12  network byte order
	__be16 dport;       // off 14  network byte order
	__u32 payload_len;  // off 16  bytes filled in payload[]
	__u32 _pad2;        // off 20  align cgroup_id to 8
	__u64 cgroup_id;    // off 24  cgroup v2 id of the sending pod (0 = unknown)
	__u8  payload[MAX_PAYLOAD]; // off 32
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); // 256 KiB
} events SEC(".maps");

static __always_inline void submit_event(struct __sk_buff *skb,
					 struct iphdr *iph,
					 __u8 evt_type, __u8 proto,
					 __be16 sport, __be16 dport,
					 __u32 payload_off, __u32 payload_avail)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->evt_type   = evt_type;
	e->ip_version = 4;
	e->l4_proto   = proto;
	e->_pad       = 0;
	e->saddr      = iph->saddr;
	e->daddr      = iph->daddr;
	e->sport      = sport;
	e->dport      = dport;
	e->payload_len = 0;
	e->_pad2      = 0;
	// cgroup v2 id of the skb's sending socket — the pod that emitted this
	// packet. Returns 0 when the skb has no cgroup association; userspace
	// treats 0 as "unknown" and skips attribution.
	e->cgroup_id  = bpf_skb_cgroup_id(skb);

	// payload_avail comes from a packet-pointer subtraction, so the verifier
	// treats it as an unbounded scalar. Clamp it, pin it in one register with
	// barrier_var(), then re-assert the bound right before the helper call so
	// the bound lands on the exact register passed as the length.
	__u64 copy_len = payload_avail;
	if (copy_len > MAX_PAYLOAD)
		copy_len = MAX_PAYLOAD;
	barrier_var(copy_len);
	if (copy_len != 0) {
		// Separate barrier so the != 0 check narrows the *same* register
		// the helper reads (otherwise the compiler tests a derived temp
		// and the call register keeps a zero lower bound).
		barrier_var(copy_len);
		if (bpf_skb_load_bytes(skb, payload_off, e->payload, copy_len) == 0)
			e->payload_len = (__u32)copy_len;
	}

	bpf_ringbuf_submit(e, 0);
}

// Matches the first four bytes of common HTTP request methods.
static __always_inline int looks_like_http(__u8 b0, __u8 b1, __u8 b2, __u8 b3)
{
	// GET␠ POST PUT␠ HEAD DELE PATC OPTI CONN TRAC
	if (b0 == 'G' && b1 == 'E' && b2 == 'T' && b3 == ' ') return 1;
	if (b0 == 'P' && b1 == 'O' && b2 == 'S' && b3 == 'T') return 1;
	if (b0 == 'P' && b1 == 'U' && b2 == 'T' && b3 == ' ') return 1;
	if (b0 == 'H' && b1 == 'E' && b2 == 'A' && b3 == 'D') return 1;
	if (b0 == 'D' && b1 == 'E' && b2 == 'L' && b3 == 'E') return 1;
	if (b0 == 'P' && b1 == 'A' && b2 == 'T' && b3 == 'C') return 1;
	if (b0 == 'O' && b1 == 'P' && b2 == 'T' && b3 == 'I') return 1;
	if (b0 == 'C' && b1 == 'O' && b2 == 'N' && b3 == 'N') return 1;
	if (b0 == 'T' && b1 == 'R' && b2 == 'A' && b3 == 'C') return 1;
	return 0;
}

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	// cgroup_skb egress packets start at the network (L3) header.
	struct iphdr *iph = data;
	if ((void *)(iph + 1) > data_end)
		return 1;
	if (iph->version != 4)
		return 1; // IPv6 is a later stage

	__u32 ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		return 1;

	void *l4 = (void *)iph + ihl;
	if (l4 > data_end)
		return 1;

	if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return 1;

		if (udp->dest == bpf_htons(53)) {
			// Use skb->len (covers non-linear data) rather than
			// data_end (linear head only) for the payload length.
			__u32 off = ihl + sizeof(*udp);
			__u32 avail = (off < skb->len) ? (skb->len - off) : 0;
			submit_event(skb, iph, EVT_DNS, IPPROTO_UDP,
				     udp->source, udp->dest, off, avail);
		}
		return 1;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return 1;

		// New connection: SYN set, ACK clear. No payload to copy.
		if (tcp->syn && !tcp->ack)
			submit_event(skb, iph, EVT_CONNECT, IPPROTO_TCP,
				     tcp->source, tcp->dest, 0, 0);

		__u32 doff = tcp->doff * 4;
		if (doff < sizeof(*tcp))
			return 1;

		// The TCP payload is often in the skb's non-linear (paged) part on
		// egress, so direct packet access (data/data_end) can't see it.
		// Classify via bpf_skb_load_bytes, which reads across the whole skb
		// and bounds against skb->len.
		__u32 off = ihl + doff;
		if (off >= skb->len)
			return 1; // no payload (pure ACK, etc.)
		__u32 avail = skb->len - off;
		if (avail < 6)
			return 1; // need 6 bytes to classify

		__u8 hdr[6];
		if (bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) != 0)
			return 1;

		if (hdr[0] == 0x16 && hdr[5] == 0x01) {
			// TLS handshake record carrying a ClientHello.
			submit_event(skb, iph, EVT_TLS, IPPROTO_TCP,
				     tcp->source, tcp->dest, off, avail);
		} else if (looks_like_http(hdr[0], hdr[1], hdr[2], hdr[3])) {
			submit_event(skb, iph, EVT_HTTP, IPPROTO_TCP,
				     tcp->source, tcp->dest, off, avail);
		}
		return 1;
	}

	return 1;
}
