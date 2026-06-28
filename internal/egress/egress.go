// Package egress implements the cgroup_skb/egress monitor: it reports outgoing
// domains (DNS + TLS SNI), HTTP request paths, and new TCP connections, with
// internal traffic filtered out per config.
package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/dvrkn/ebfw/internal/attr"
	"github.com/dvrkn/ebfw/internal/config"
	"github.com/dvrkn/ebfw/internal/enforce"
	"github.com/dvrkn/ebfw/internal/l7"
	"github.com/dvrkn/ebfw/internal/metrics"
	"github.com/dvrkn/ebfw/internal/output"
	"github.com/dvrkn/ebfw/internal/policy"
	"github.com/dvrkn/ebfw/internal/tlsparse"
)

// Event kinds — must match bpf/egress.bpf.c.
const (
	evtConnect = 1
	evtDNS     = 2
	evtTLS     = 3
	evtHTTP    = 4
)

// hdrLen is the fixed header of struct event in bpf/egress.bpf.c. The C struct's
// field offsets are mirrored by parseHeader; keep both in sync with that struct.
// Addresses are always 16 bytes (ip_version says how many are meaningful: 4 for
// IPv4, 16 for IPv6), so the layout is identical for both. Layout: evt_type@0
// ip_version@1 l4_proto@2 action@3 saddr@4(16) daddr@20(16) sport@36 dport@38
// payload_len@40 _pad2@44 cgroup_id@48 payload@56.
const hdrLen = 56

// kernel action byte value — must match ACTION_* in bpf/egress.bpf.c.
const actionDeny = 0

// eventHeader is the decoded fixed header of a ringbuf event. The net.IP fields
// alias the raw sample, which the caller uses synchronously.
type eventHeader struct {
	evtType  uint8
	action   uint8
	src, dst net.IP
	dport    uint16
	plen     uint32
	cgroupID uint64
}

// parseHeader decodes the fixed event header. addrLen follows ip_version: an
// IPv4 event keeps its address in the first 4 of the 16 reserved bytes, so we
// slice 4 bytes (net.IP renders it as a dotted quad); IPv6 slices all 16.
func parseHeader(raw []byte) (eventHeader, bool) {
	if len(raw) < hdrLen {
		return eventHeader{}, false
	}
	alen := 4
	if raw[1] == 6 {
		alen = 16
	}
	return eventHeader{
		evtType:  raw[0],
		action:   raw[3],
		src:      net.IP(raw[4 : 4+alen]),
		dst:      net.IP(raw[20 : 20+alen]),
		dport:    binary.BigEndian.Uint16(raw[38:40]),
		plen:     binary.LittleEndian.Uint32(raw[40:44]),
		cgroupID: binary.LittleEndian.Uint64(raw[48:56]),
	}, true
}

// kernelAction renders the in-kernel verdict byte. It is authoritative for
// connection-level events in enforce mode (the engine cannot re-derive a
// domain-rule verdict from a bare CONNECT event, since the dropped SYN carries
// no SNI/Host).
func kernelAction(b uint8) string {
	if b == actionDeny {
		return "Deny"
	}
	return "Allow"
}

// Run loads and attaches the egress program and reports filtered events until
// ctx is cancelled, attributing each to its pod via resolver and emitting through
// sink. When src is non-nil (enforce mode) it also programs the enforcement maps
// from the policy. The caller owns rlimit setup and signal handling.
func Run(ctx context.Context, cfg *config.Config, filter *config.Filter, resolver *attr.Resolver, sink output.Sink, src policy.PolicySource) error {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load bpf objects: verifier error:\n%+v", ve)
		}
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cfg.Cgroup,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.Egress,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup egress at %s: %w", cfg.Cgroup, err)
	}
	defer l.Close()

	// Enforcement: program the verdict maps from policy in-process. The
	// Programmer holds the map handles directly, so no pinning is needed.
	if src != nil {
		prog := enforce.NewProgrammer(enforce.Maps{
			Default:  objs.DefaultAction,
			Verdicts: objs.Verdicts,
			CIDR:     objs.CidrVerdicts,
			Cfg:      objs.EnforceCfg,
		}, resolver, cfg.Enforce.DryRun)
		go func() {
			if err := prog.Run(ctx, src); err != nil {
				log.Printf("ebfw enforce: programmer stopped: %v", err)
			}
		}()
		log.Printf("ebfw enforce: cgroup datapath active (dry_run=%v)", cfg.Enforce.DryRun)

		// DNS→IP learning: capture DNS answers on ingress so domain rules can
		// be enforced by the IP-keyed verdicts map.
		il, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cfg.Cgroup,
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: objs.DnsIngress,
		})
		if err != nil {
			return fmt.Errorf("attach cgroup ingress at %s: %w", cfg.Cgroup, err)
		}
		defer il.Close()

		learner := enforce.NewDNSLearner(objs.DnsAnswers, objs.Verdicts, resolver)
		go func() {
			if err := learner.Run(ctx, src); err != nil {
				log.Printf("ebfw enforce: dns learner stopped: %v", err)
			}
		}()
		log.Printf("ebfw enforce: DNS→IP learning active (domain rules)")

		// connect4: fail denied IPv4 TCP connect() with EPERM (cleaner than a
		// SYN timeout). connect6 + IPv6 enforcement is not yet implemented.
		cl, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cfg.Cgroup,
			Attach:  ebpf.AttachCGroupInet4Connect,
			Program: objs.Connect4,
		})
		if err != nil {
			return fmt.Errorf("attach cgroup connect4 at %s: %w", cfg.Cgroup, err)
		}
		defer cl.Close()
		log.Printf("ebfw enforce: connect4 fast-fail (EPERM) active")
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	log.Printf("ebfw monitor: watching egress on cgroup %s", cfg.Cgroup)

	seen := make(map[string]struct{})
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("monitor ringbuf read: %v", err)
			continue
		}
		handleEvent(rec.RawSample, filter, cfg.Inspect, src != nil, resolver, sink, seen)
	}
}

func handleEvent(raw []byte, filter *config.Filter, inspect config.Inspection, enforcing bool, resolver *attr.Resolver, sink output.Sink, seen map[string]struct{}) {
	h, ok := parseHeader(raw)
	if !ok {
		return
	}

	// The kernel stamped the enforcement verdict; count denials (actual drops,
	// or would-be drops under dry-run). DNS is always allowed, so it never hits.
	if h.action == actionDeny {
		switch h.evtType {
		case evtConnect:
			metrics.EnforcementDropsTotal.WithLabelValues(string(output.KindConnect)).Inc()
		case evtTLS:
			metrics.EnforcementDropsTotal.WithLabelValues(string(output.KindTLS)).Inc()
		case evtHTTP:
			metrics.EnforcementDropsTotal.WithLabelValues(string(output.KindHTTP)).Inc()
		}
	}

	// In enforce mode the kernel verdict is authoritative for the event's
	// action (the engine cannot re-derive a domain rule from a bare CONNECT).
	// In observe/log mode actStr stays empty and the enforcement sink decides.
	actStr := ""
	if enforcing {
		actStr = kernelAction(h.action)
	}

	var payload []byte
	if h.plen > 0 && hdrLen+int(h.plen) <= len(raw) {
		payload = raw[hdrLen : hdrLen+int(h.plen)]
	}

	switch h.evtType {
	case evtConnect:
		if filter.SkipIP(h.dst) {
			metrics.FilteredTotal.WithLabelValues(string(output.KindConnect)).Inc()
			return
		}
		// Denied connects bypass the new-connection de-dup so every blocked
		// attempt is visible; allowed connects de-dup to avoid log spam.
		if h.action != actionDeny {
			key := "c|" + h.src.String() + "|" + h.dst.String() + "|" + fmt.Sprint(h.dport)
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
		}
		sink.Emit(output.Event{
			Kind: output.KindConnect, Src: h.src.String(), Dst: h.dst.String(), Port: int(h.dport),
			Pod: resolver.ByCgroupID(h.cgroupID), Action: actStr,
		})

	case evtDNS:
		pod := resolver.ByCgroupID(h.cgroupID)
		for _, q := range dnsQuestions(payload) {
			if filter.SkipDomain(q.name) {
				metrics.FilteredTotal.WithLabelValues(string(output.KindDNS)).Inc()
				continue
			}
			sink.Emit(output.Event{
				Kind: output.KindDNS, Src: h.src.String(), Domain: q.name, DNSType: q.typ, Pod: pod,
			})
		}

	case evtTLS:
		sni, err := tlsparse.ServerName(payload)
		if err != nil {
			return
		}
		if filter.SkipDomain(sni) || filter.SkipIP(h.dst) {
			metrics.FilteredTotal.WithLabelValues(string(output.KindTLS)).Inc()
			return
		}
		sink.Emit(output.Event{
			Kind: output.KindTLS, Src: h.src.String(), Domain: sni, Dst: h.dst.String(), Port: int(h.dport),
			Pod: resolver.ByCgroupID(h.cgroupID), Action: actStr,
		})

	case evtHTTP:
		req, ok := l7.ParseRequest(payload)
		if !ok {
			return
		}
		if filter.SkipDomain(req.Host) || filter.SkipIP(h.dst) {
			metrics.FilteredTotal.WithLabelValues(string(output.KindHTTP)).Inc()
			return
		}
		ev := output.Event{
			Kind: output.KindHTTP, Src: h.src.String(), Method: req.Method, Domain: req.Host, Path: req.Path,
			Dst: h.dst.String(), Port: int(h.dport), Pod: resolver.ByCgroupID(h.cgroupID), Action: actStr,
		}
		if inspect.Headers {
			ev.Headers = req.Headers
		}
		sink.Emit(ev)
	}
}

type question struct{ name, typ string }

// dnsQuestions returns the question names and types from a DNS message.
func dnsQuestions(payload []byte) []question {
	if len(payload) == 0 {
		return nil
	}
	var p dnsmessage.Parser
	if _, err := p.Start(payload); err != nil {
		return nil
	}
	var out []question
	for {
		q, err := p.Question()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			break
		}
		out = append(out, question{
			name: strings.TrimSuffix(q.Name.String(), "."),
			typ:  q.Type.String(),
		})
	}
	return out
}
