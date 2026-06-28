// SPDX-License-Identifier: GPL-2.0
//
// ebfw egress monitor + enforcement datapath.
//
// Three programs sharing one object so they share the verdict maps:
//   cgroup_skb/egress    classify egress packets (+ drop denied flows)
//   cgroup_skb/ingress   capture DNS answers for domain→IP learning
//   cgroup/connect4      fail denied IPv4 TCP connect() with EPERM
//
// Attached at the node's root cgroup v2, the egress program sees every egress
// packet from every pod on the node. It does NO protocol parsing itself: it
// bounds-checks, classifies the packet (IPv4 and IPv6), and copies the relevant
// bytes up to userspace via a ring buffer. All DNS/TLS/HTTP parsing happens in
// Go where loops and string handling are safe. Enforcement is IPv4-only for now
// (the verdict maps are IPv4-keyed); IPv6 is observed but not dropped.
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
#include <linux/ipv6.h>
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

// Enforcement verdicts. These are the map *values*; they are also the
// SK_DROP/SK_PASS return codes, so ACTION_DENY must stay 0 and ACTION_ALLOW 1.
#define ACTION_DENY  0
#define ACTION_ALLOW 1

// Force the compiler to keep a value in a single register so the verifier's
// bound on it isn't lost to a decoupled copy (a common variable-length copy
// pitfall). See libbpf's bpf_helpers.h barrier_var().
#define barrier_var(var) asm volatile("" : "+r"(var))

// Field offsets are mirrored by hand in internal/egress/egress.go (parseHeader).
// If you change this layout, change that file in lockstep. Addresses are always
// 16 bytes so the layout is identical for v4 and v6: ip_version says how many
// leading bytes are meaningful (4 for IPv4, trailing 12 zeroed; 16 for IPv6).
// _pad2 keeps cgroup_id 8-byte aligned.
struct event {
	__u8  evt_type;     // off 0   EVT_*
	__u8  ip_version;   // off 1   4 or 6
	__u8  l4_proto;     // off 2   IPPROTO_TCP / IPPROTO_UDP
	__u8  action;       // off 3   enforcement verdict: ACTION_ALLOW / ACTION_DENY
	__u8  saddr[16];    // off 4   network byte order (IPv4 in first 4 bytes)
	__u8  daddr[16];    // off 20  network byte order (IPv4 in first 4 bytes)
	__be16 sport;       // off 36  network byte order
	__be16 dport;       // off 38  network byte order
	__u32 payload_len;  // off 40  bytes filled in payload[]
	__u32 _pad2;        // off 44  align cgroup_id to 8
	__u64 cgroup_id;    // off 48  cgroup v2 id of the sending pod (0 = unknown)
	__u8  payload[MAX_PAYLOAD]; // off 56
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); // 256 KiB
} events SEC(".maps");

// DNS answers captured on ingress for domain→IP learning. Mirrored by hand in
// internal/enforce/dnslearn.go: payload_len@0 _pad@4 cgroup_id@8 payload@16.
struct dns_answer {
	__u32 payload_len;          // off 0
	__u32 _pad;                 // off 4
	__u64 cgroup_id;            // off 8  receiving socket's cgroup = querying pod
	__u8  payload[MAX_PAYLOAD]; // off 16
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); // 256 KiB
} dns_answers SEC(".maps");

// ── Enforcement maps ────────────────────────────────────────────────────────
// Programmed in-process by the userspace Programmer (which holds the map
// handles), so no pinning is needed: policy updates re-apply without a program
// reload. Pinning these (LIBBPF_PIN_BY_NAME) would let an external CRD
// controller update them without a reload; not done yet. The connect4 and
// DNS-learning programs live in this same object to share the maps natively.
// Key/value layouts are mirrored in internal/enforce (hand-written Go structs);
// change both in lockstep.
//
// verdict_for() consults them most-specific first: exact (cgroup,ip,port) →
// (cgroup,ip,any) → (global,ip,port) → (global,ip,any) → CIDR(cgroup) →
// CIDR(global) → default_action(cgroup) → default_action(global) → ALLOW. The
// userspace Programmer computes each entry's value with the full policy engine,
// so per-IP entries are always faithful to rule order; CIDR ranges carry their
// rule's verdict.

// verdict_key: exact destination. dport == 0 means "any port".
struct verdict_key {
	__u64  cgroup_id; // 0 = node-global (applies to every pod)
	__be32 daddr;     // network byte order
	__be16 dport;     // network byte order; 0 = any
	__u16  _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH); // LRU so DNS-learned IPs self-evict
	__uint(max_entries, 1 << 16);        // 65536
	__type(key, struct verdict_key);
	__type(value, __u8);
} verdicts SEC(".maps");

// cidr_key: LPM trie key. The matched bitstring after prefixlen is
// cgroup_id(8B) || addr(4B); a /n CIDR for one cgroup is prefixlen 64+n, a
// node-global one uses cgroup_id 0 (still 64 significant bits) so the two never
// collide. Port-agnostic. Packed so the data starts immediately after prefixlen
// with no alignment padding (LPM matches the raw byte string).
struct cidr_key {
	__u32  prefixlen;
	__u64  cgroup_id;
	__be32 addr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1 << 14);
	__type(key, struct cidr_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC); // required for LPM_TRIE
} cidr_verdicts SEC(".maps");

// default_action: posture per cgroup id; key 0 is the node-global default.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} default_action SEC(".maps");

// enforce_cfg: single-entry runtime config. dry_run != 0 makes verdict_for
// compute + stamp the action but never drop (high-fidelity canary).
struct enforce_cfg_val {
	__u8 enabled; // 0 = no enforcement programmed (skip lookups, always allow)
	__u8 dry_run; // 1 = compute verdicts but never SK_DROP
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct enforce_cfg_val);
} enforce_cfg SEC(".maps");

// enforce_enabled reports whether policy maps have been programmed; dry is set
// to the dry-run flag. When disabled, verdict_for is skipped entirely so the
// observe-only path keeps its original cost.
static __always_inline int enforce_enabled(__u8 *dry)
{
	__u32 k = 0;
	struct enforce_cfg_val *c = bpf_map_lookup_elem(&enforce_cfg, &k);
	if (!c || !c->enabled)
		return 0;
	*dry = c->dry_run;
	return 1;
}

// verdict_for resolves the action for a destination, most-specific first.
static __always_inline __u8 verdict_for(__u64 cg, __be32 daddr, __be16 dport)
{
	__u8 *v;
	struct verdict_key vk = {};

	vk.cgroup_id = cg;
	vk.daddr = daddr;
	vk.dport = dport;
	v = bpf_map_lookup_elem(&verdicts, &vk);
	if (v)
		return *v;

	vk.dport = 0; // (cgroup, ip, any-port)
	v = bpf_map_lookup_elem(&verdicts, &vk);
	if (v)
		return *v;

	vk.cgroup_id = 0; // (global, ip, port)
	vk.dport = dport;
	v = bpf_map_lookup_elem(&verdicts, &vk);
	if (v)
		return *v;

	vk.dport = 0; // (global, ip, any-port)
	v = bpf_map_lookup_elem(&verdicts, &vk);
	if (v)
		return *v;

	struct cidr_key ck = {};
	ck.prefixlen = 64 + 32;
	ck.cgroup_id = cg; // CIDR for this cgroup
	ck.addr = daddr;
	v = bpf_map_lookup_elem(&cidr_verdicts, &ck);
	if (v)
		return *v;

	ck.cgroup_id = 0; // node-global CIDR
	v = bpf_map_lookup_elem(&cidr_verdicts, &ck);
	if (v)
		return *v;

	v = bpf_map_lookup_elem(&default_action, &cg);
	if (v)
		return *v;

	__u64 zero = 0;
	v = bpf_map_lookup_elem(&default_action, &zero);
	if (v)
		return *v;

	return ACTION_ALLOW;
}

// verdict_pass maps an action to the cgroup_skb return code, honouring dry-run.
static __always_inline int verdict_pass(__u8 action, __u8 dry)
{
	if (action == ACTION_DENY && !dry)
		return 0; // SK_DROP
	return 1;         // SK_PASS
}

// submit_event is version-agnostic: the caller passes the IP version and the skb
// byte offsets of the source/dest addresses. Addresses are read with
// bpf_skb_load_bytes (constant length per branch — verifier-safe) into the fixed
// 16-byte fields, so the L3 header layout never leaks into this helper. action
// carries the enforcement verdict for the flow.
static __always_inline void submit_event(struct __sk_buff *skb,
					 __u8 ip_version,
					 __u32 saddr_off, __u32 daddr_off,
					 __u8 evt_type, __u8 proto,
					 __be16 sport, __be16 dport,
					 __u32 payload_off, __u32 payload_avail,
					 __u8 action)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->evt_type   = evt_type;
	e->ip_version = ip_version;
	e->l4_proto   = proto;
	e->action     = action;
	__builtin_memset(e->saddr, 0, sizeof(e->saddr));
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	if (ip_version == 6) {
		bpf_skb_load_bytes(skb, saddr_off, e->saddr, 16);
		bpf_skb_load_bytes(skb, daddr_off, e->daddr, 16);
	} else {
		bpf_skb_load_bytes(skb, saddr_off, e->saddr, 4);
		bpf_skb_load_bytes(skb, daddr_off, e->daddr, 4);
	}
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

	// cgroup_skb egress packets start at the network (L3) header. The high
	// nibble of the first byte is the IP version (same position for v4 and v6).
	__u8 *vbyte = data;
	if ((void *)(vbyte + 1) > data_end)
		return 1;
	__u8 version = *vbyte >> 4;

	// Per-version L3 facts the rest of the program needs: where L4 starts, the
	// L4 protocol, the skb byte offsets of the src/dst addresses, and (IPv4
	// only, for enforcement) the destination address.
	__u8   ip_version;
	__u8   proto;
	__u32  l4_off, saddr_off, daddr_off;
	__be32 v4_daddr = 0;

	if (version == 4) {
		struct iphdr *iph = data;
		if ((void *)(iph + 1) > data_end)
			return 1;
		__u32 ihl = iph->ihl * 4;
		if (ihl < sizeof(*iph))
			return 1;
		ip_version = 4;
		proto      = iph->protocol;
		l4_off     = ihl;
		saddr_off  = __builtin_offsetof(struct iphdr, saddr);   // 12
		daddr_off  = __builtin_offsetof(struct iphdr, daddr);   // 16
		v4_daddr   = iph->daddr;
	} else if (version == 6) {
		struct ipv6hdr *ip6h = data;
		if ((void *)(ip6h + 1) > data_end)
			return 1;
		ip_version = 6;
		// No IPv6 extension-header walk: when nexthdr is not TCP/UDP (a
		// hop-by-hop/routing/fragment/dest-opts header) the packet falls
		// through unparsed. Rare on normal egress; see README limitations.
		proto      = ip6h->nexthdr;
		l4_off     = sizeof(*ip6h);                              // fixed 40
		saddr_off  = __builtin_offsetof(struct ipv6hdr, saddr);  // 8
		daddr_off  = __builtin_offsetof(struct ipv6hdr, daddr);  // 24
	} else {
		return 1;
	}

	void *l4 = data + l4_off;
	if (l4 > data_end)
		return 1;

	// Resolve the enforcement verdict once per packet (IPv4 only — the verdict
	// maps are IPv4-keyed; IPv6 is observed but not yet enforced). When no
	// policy is programmed this is a single array lookup and the observe-only
	// cost is unchanged: act stays ACTION_ALLOW and nothing is dropped.
	__u8 dry = 0;
	int enf = (ip_version == 4) && enforce_enabled(&dry);
	__u64 cg = enf ? bpf_skb_cgroup_id(skb) : 0;

	if (proto == IPPROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return 1;

		if (udp->dest == bpf_htons(53)) {
			// DNS is ALWAYS permitted — under default-deny, dropping it
			// would break name resolution and thus all egress. Use
			// skb->len (covers non-linear data) for the payload length.
			__u32 off = l4_off + sizeof(*udp);
			__u32 avail = (off < skb->len) ? (skb->len - off) : 0;
			submit_event(skb, ip_version, saddr_off, daddr_off,
				     EVT_DNS, IPPROTO_UDP,
				     udp->source, udp->dest, off, avail, ACTION_ALLOW);
			return 1;
		}
		if (enf) {
			__u8 act = verdict_for(cg, v4_daddr, udp->dest);
			return verdict_pass(act, dry);
		}
		return 1;
	}

	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return 1;

		__u8 act = enf ? verdict_for(cg, v4_daddr, tcp->dest) : ACTION_ALLOW;

		// New connection: SYN set, ACK clear. No payload to copy. Emit the
		// event (with its verdict) before any drop so denials are visible.
		if (tcp->syn && !tcp->ack)
			submit_event(skb, ip_version, saddr_off, daddr_off,
				     EVT_CONNECT, IPPROTO_TCP,
				     tcp->source, tcp->dest, 0, 0, act);

		__u32 doff = tcp->doff * 4;
		if (doff < sizeof(*tcp))
			return verdict_pass(act, dry);

		// The TCP payload is often in the skb's non-linear (paged) part on
		// egress, so direct packet access (data/data_end) can't see it.
		// Classify via bpf_skb_load_bytes, which reads across the whole skb
		// and bounds against skb->len.
		__u32 off = l4_off + doff;
		if (off >= skb->len)
			return verdict_pass(act, dry); // no payload (pure ACK, etc.)
		__u32 avail = skb->len - off;
		if (avail < 6)
			return verdict_pass(act, dry); // need 6 bytes to classify

		__u8 hdr[6];
		if (bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) != 0)
			return verdict_pass(act, dry);

		if (hdr[0] == 0x16 && hdr[5] == 0x01) {
			// TLS handshake record carrying a ClientHello.
			submit_event(skb, ip_version, saddr_off, daddr_off,
				     EVT_TLS, IPPROTO_TCP,
				     tcp->source, tcp->dest, off, avail, act);
		} else if (looks_like_http(hdr[0], hdr[1], hdr[2], hdr[3])) {
			submit_event(skb, ip_version, saddr_off, daddr_off,
				     EVT_HTTP, IPPROTO_TCP,
				     tcp->source, tcp->dest, off, avail, act);
		}
		return verdict_pass(act, dry);
	}

	return 1;
}

// dns_ingress captures DNS answers (UDP source port 53) so userspace can learn
// domain→IP mappings and program per-pod verdicts for domain rules. The
// receiving socket's cgroup attributes the answer to the querying pod. IPv4
// only (the verdict maps are IPv4-keyed); it never drops — DNS answers are
// always delivered.
SEC("cgroup_skb/ingress")
int dns_ingress(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct iphdr *iph = data;
	if ((void *)(iph + 1) > data_end)
		return 1;
	if (iph->version != 4)
		return 1;

	__u32 ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		return 1;

	void *l4 = (void *)iph + ihl;
	if (l4 > data_end)
		return 1;

	if (iph->protocol != IPPROTO_UDP)
		return 1;
	struct udphdr *udp = l4;
	if ((void *)(udp + 1) > data_end)
		return 1;
	if (udp->source != bpf_htons(53)) // answers come FROM port 53
		return 1;

	__u32 off = ihl + sizeof(*udp);
	__u32 avail = (off < skb->len) ? (skb->len - off) : 0;

	struct dns_answer *e = bpf_ringbuf_reserve(&dns_answers, sizeof(*e), 0);
	if (!e)
		return 1;
	e->cgroup_id   = bpf_skb_cgroup_id(skb);
	e->_pad        = 0;
	e->payload_len = 0;

	__u64 n = avail;
	if (n > MAX_PAYLOAD)
		n = MAX_PAYLOAD;
	barrier_var(n);
	if (n != 0) {
		barrier_var(n);
		if (bpf_skb_load_bytes(skb, off, e->payload, n) == 0)
			e->payload_len = (__u32)n;
	}
	bpf_ringbuf_submit(e, 0);
	return 1;
}

// emit_connect_deny reports a connect()-time denial on the events ringbuf. The
// SYN never leaves on a deny, so the egress hook won't see this connection —
// this keeps denied connects visible (saddr/sport are unknown at connect time).
static __always_inline void emit_connect_deny(__u64 cg, __be32 daddr, __be16 dport)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->evt_type    = EVT_CONNECT;
	e->ip_version  = 4;
	e->l4_proto    = IPPROTO_TCP;
	e->action      = ACTION_DENY;
	__builtin_memset(e->saddr, 0, sizeof(e->saddr));
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	__builtin_memcpy(e->daddr, &daddr, sizeof(daddr)); // IPv4 in first 4 bytes
	e->sport       = 0;
	e->dport       = dport;
	e->payload_len = 0;
	e->_pad2       = 0;
	e->cgroup_id   = cg;
	bpf_ringbuf_submit(e, 0);
}

// connect4 fails a TCP connect() to a denied IPv4 destination with -EPERM — a
// clean, immediate failure versus the SYN-timeout the egress drop produces. It
// consults the same verdict maps (including DNS-learned IPs). UDP, including
// DNS, is left to the egress hook (which always permits udp:53), so name
// resolution under default-deny is never broken here.
SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
	if (ctx->protocol != IPPROTO_TCP)
		return 1;
	__u8 dry = 0;
	if (!enforce_enabled(&dry))
		return 1;

	__u64 cg = bpf_get_current_cgroup_id();
	__be32 daddr = ctx->user_ip4;       // network byte order
	__be16 dport = (__u16)ctx->user_port; // low 16 bits are the be16 port

	if (verdict_for(cg, daddr, dport) == ACTION_DENY) {
		emit_connect_deny(cg, daddr, dport);
		if (!dry)
			return 0; // -EPERM
	}
	return 1;
}
