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

	"github.com/dvrkn/ebfw/internal/config"
	"github.com/dvrkn/ebfw/internal/l7"
	"github.com/dvrkn/ebfw/internal/tlsparse"
)

// Event kinds — must match bpf/egress.bpf.c.
const (
	evtConnect = 1
	evtDNS     = 2
	evtTLS     = 3
	evtHTTP    = 4
)

// hdrLen is the fixed header of struct event in bpf/egress.bpf.c (payload @ 20).
const hdrLen = 20

// Run loads and attaches the egress program and reports filtered events until
// ctx is cancelled. The caller owns rlimit setup and signal handling.
func Run(ctx context.Context, cfg *config.Config, filter *config.Filter) error {
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
		handleEvent(rec.RawSample, filter, cfg.Inspect, seen)
	}
}

func handleEvent(raw []byte, filter *config.Filter, inspect config.Inspection, seen map[string]struct{}) {
	if len(raw) < hdrLen {
		return
	}
	evtType := raw[0]
	src := net.IP(raw[4:8])
	dst := net.IP(raw[8:12])
	dport := binary.BigEndian.Uint16(raw[14:16])
	plen := binary.LittleEndian.Uint32(raw[16:20])

	var payload []byte
	if plen > 0 && hdrLen+int(plen) <= len(raw) {
		payload = raw[hdrLen : hdrLen+int(plen)]
	}

	switch evtType {
	case evtConnect:
		if filter.SkipIP(dst) {
			return
		}
		key := "c|" + src.String() + "|" + dst.String() + "|" + fmt.Sprint(dport)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		fmt.Printf("%-8s %s -> %s:%d\n", "CONNECT", src, dst, dport)

	case evtDNS:
		for _, q := range dnsQuestions(payload) {
			if filter.SkipDomain(q.name) {
				continue
			}
			fmt.Printf("%-8s %s ? %s (%s)\n", "DNS", src, q.name, q.typ)
		}

	case evtTLS:
		sni, err := tlsparse.ServerName(payload)
		if err != nil || filter.SkipDomain(sni) || filter.SkipIP(dst) {
			return
		}
		fmt.Printf("%-8s %s -> %s  (%s:%d)\n", "TLS", src, sni, dst, dport)

	case evtHTTP:
		req, ok := l7.ParseRequest(payload)
		if !ok || filter.SkipDomain(req.Host) || filter.SkipIP(dst) {
			return
		}
		fmt.Printf("%-8s %s -> %s %s%s\n", "HTTP", src, req.Method, req.Host, req.Path)
		if inspect.Headers {
			l7.PrintHeaders(req.Headers)
		}
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
