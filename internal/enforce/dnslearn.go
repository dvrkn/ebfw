package enforce

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/dvrkn/ebfw/internal/attr"
	"github.com/dvrkn/ebfw/internal/metrics"
	"github.com/dvrkn/ebfw/internal/policy"
)

// DNS answer event header from struct dns_answer in bpf/egress.bpf.c:
// payload_len@0 _pad@4 cgroup_id@8 payload@16.
const dnsHdrLen = 16

// TTL clamps for learned verdict entries: long enough to avoid churn, short
// enough that a domain dropped from policy (or an IP rotation) expires promptly.
const (
	minLearnTTL = 60 * time.Second
	maxLearnTTL = 60 * time.Minute
	sweepEvery  = 30 * time.Second
)

// DNSLearner reads captured DNS answers, matches each query name against the
// policy's domain rules for the querying pod, and programs the resolved IPv4
// addresses into the verdicts map so the cgroup datapath can enforce domain
// rules. Entries carry a TTL and are swept; the map is also LRU as a backstop.
type DNSLearner struct {
	answers  *ebpf.Map
	verdicts *ebpf.Map
	resolver *attr.Resolver

	mu      sync.Mutex
	eng     policy.Engine
	entries map[verdictKey]time.Time // learned key -> expiry
}

// NewDNSLearner returns a learner over the dns_answers ringbuf that programs the
// verdicts map.
func NewDNSLearner(answers, verdicts *ebpf.Map, resolver *attr.Resolver) *DNSLearner {
	return &DNSLearner{
		answers:  answers,
		verdicts: verdicts,
		resolver: resolver,
		entries:  map[verdictKey]time.Time{},
	}
}

// Run consumes DNS answers and keeps an up-to-date engine from src until ctx is
// cancelled.
func (l *DNSLearner) Run(ctx context.Context, src policy.PolicySource) error {
	eng, err := policy.NewEngine(src.Snapshot())
	if err != nil {
		return err
	}
	l.setEngine(eng)

	rd, err := ringbuf.NewReader(l.answers)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	go l.watch(ctx, src)
	go l.sweep(ctx)

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("ebfw enforce: dns ringbuf read: %v", err)
			continue
		}
		l.handle(rec.RawSample)
	}
}

func (l *DNSLearner) setEngine(e policy.Engine) {
	l.mu.Lock()
	l.eng = e
	l.mu.Unlock()
}

func (l *DNSLearner) engine() policy.Engine {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.eng
}

func (l *DNSLearner) watch(ctx context.Context, src policy.PolicySource) {
	ch := src.Subscribe()
	for {
		select {
		case <-ctx.Done():
			return
		case pol, ok := <-ch:
			if !ok {
				return
			}
			if e, err := policy.NewEngine(pol); err == nil {
				l.setEngine(e)
			}
		}
	}
}

func (l *DNSLearner) handle(raw []byte) {
	if len(raw) < dnsHdrLen {
		return
	}
	plen := binary.LittleEndian.Uint32(raw[0:4])
	cgroupID := binary.LittleEndian.Uint64(raw[8:16])
	if cgroupID == 0 || plen == 0 || dnsHdrLen+int(plen) > len(raw) {
		return
	}
	payload := raw[dnsHdrLen : dnsHdrLen+int(plen)]

	qname, ips, ttl := parseAnswers(payload)
	if qname == "" || len(ips) == 0 {
		return
	}

	pod := l.resolver.ByCgroupID(cgroupID)
	action, ports, ok := l.engine().DomainRuleVerdict(pod, pod.Labels, qname)
	if !ok {
		return // no domain rule matches this pod+name
	}
	if len(ports) == 0 {
		ports = []uint16{0} // any port
	}

	exp := time.Now().Add(clampTTL(ttl))
	act := actionByte(action)
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue // IPv6 — verdicts map is IPv4-only
		}
		for _, port := range ports {
			k := verdictKey{CgroupID: cgroupID}
			copy(k.DAddr[:], ip4)
			binary.BigEndian.PutUint16(k.DPort[:], port)
			if err := l.verdicts.Put(k, act); err != nil {
				continue
			}
			l.mu.Lock()
			l.entries[k] = exp
			l.mu.Unlock()
		}
	}
	metrics.DNSLearnedIPs.Set(float64(l.entryCount()))
}

func (l *DNSLearner) sweep(ctx context.Context) {
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			l.mu.Lock()
			for k, exp := range l.entries {
				if now.After(exp) {
					_ = l.verdicts.Delete(k)
					delete(l.entries, k)
				}
			}
			n := len(l.entries)
			l.mu.Unlock()
			metrics.DNSLearnedIPs.Set(float64(n))
		}
	}
}

func (l *DNSLearner) entryCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func clampTTL(ttl uint32) time.Duration {
	d := time.Duration(ttl) * time.Second
	if d < minLearnTTL {
		return minLearnTTL
	}
	if d > maxLearnTTL {
		return maxLearnTTL
	}
	return d
}

// parseAnswers extracts the first question name and the A-record IPs (with the
// smallest TTL) from a DNS response. Names are matched by the question, not the
// answer owner, so CNAME chains resolve to the queried domain's policy.
func parseAnswers(payload []byte) (qname string, ips []net.IP, ttl uint32) {
	var p dnsmessage.Parser
	if _, err := p.Start(payload); err != nil {
		return "", nil, 0
	}
	for {
		q, err := p.Question()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return "", nil, 0
		}
		if qname == "" {
			qname = strings.TrimSuffix(q.Name.String(), ".")
		}
	}
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			break
		}
		if h.Type == dnsmessage.TypeA {
			r, err := p.AResource()
			if err != nil {
				break
			}
			ip := make(net.IP, 4)
			copy(ip, r.A[:])
			ips = append(ips, ip)
			if ttl == 0 || h.TTL < ttl {
				ttl = h.TTL
			}
		} else if err := p.SkipAnswer(); err != nil {
			break
		}
	}
	return qname, ips, ttl
}
