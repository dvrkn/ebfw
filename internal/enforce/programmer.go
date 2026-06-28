package enforce

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"

	"github.com/dvrkn/ebfw/internal/attr"
	"github.com/dvrkn/ebfw/internal/metrics"
	"github.com/dvrkn/ebfw/internal/policy"
)

// reprogramInterval re-walks pod cgroups so rules with a pod selector pick up
// pods that started since the last apply. A future controller could drive
// reprogramming off the pods informer instead of this polling.
const reprogramInterval = 10 * time.Second

// kernel action bytes — must match ACTION_* in bpf/egress.bpf.c.
const (
	actDeny  uint8 = 0
	actAllow uint8 = 1
)

// Maps are the enforcement BPF map handles, owned by the egress collection and
// handed to the Programmer. Layouts are mirrored from bpf/egress.bpf.c.
type Maps struct {
	Default  *ebpf.Map // default_action: u64 cgroup_id -> u8 action (key 0 = global)
	Verdicts *ebpf.Map // verdicts: verdictKey -> u8 action
	CIDR     *ebpf.Map // cidr_verdicts: LPM cidrKey(bytes) -> u8 action
	Cfg      *ebpf.Map // enforce_cfg: ARRAY[0] -> cfgVal
}

// verdictKey mirrors struct verdict_key in bpf/egress.bpf.c (16 bytes, no
// padding). Address/port are network byte order; CgroupID is host order.
type verdictKey struct {
	CgroupID uint64
	DAddr    [4]byte
	DPort    [2]byte
	Pad      [2]byte
}

// cfgVal mirrors struct enforce_cfg_val in bpf/egress.bpf.c.
type cfgVal struct {
	Enabled uint8
	DryRun  uint8
}

// Programmer translates a policy snapshot into BPF map entries and re-applies on
// every policy change plus a periodic pod re-walk. It tracks the keys it wrote
// so it deletes only its own entries (not, e.g., DNS-learned ones added later).
type Programmer struct {
	maps     Maps
	resolver *attr.Resolver
	dryRun   bool

	prevCIDR    map[string]struct{}
	prevVerdict map[verdictKey]struct{}
	prevDefault map[uint64]struct{}
}

// NewProgrammer returns a Programmer over the given maps. dryRun programs the
// datapath but suppresses drops (the kernel computes + stamps verdicts only).
func NewProgrammer(maps Maps, resolver *attr.Resolver, dryRun bool) *Programmer {
	return &Programmer{
		maps:        maps,
		resolver:    resolver,
		dryRun:      dryRun,
		prevCIDR:    map[string]struct{}{},
		prevVerdict: map[verdictKey]struct{}{},
		prevDefault: map[uint64]struct{}{},
	}
}

// Run enables the datapath, applies the current policy, and re-applies on policy
// change or the re-walk ticker until ctx is cancelled. On exit it disables
// enforcement so a crashed/stopped agent fails open.
func (p *Programmer) Run(ctx context.Context, src policy.PolicySource) error {
	if err := p.maps.Cfg.Put(uint32(0), cfgVal{Enabled: 1, DryRun: b2u8(p.dryRun)}); err != nil {
		return fmt.Errorf("enable enforcement: %w", err)
	}
	defer p.disable()

	eng, err := policy.NewEngine(src.Snapshot())
	if err != nil {
		return err
	}
	p.apply(eng)

	ch := src.Subscribe()
	t := time.NewTicker(reprogramInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case pol, ok := <-ch:
			if !ok {
				return nil
			}
			ne, err := policy.NewEngine(pol)
			if err != nil {
				log.Printf("ebfw enforce: skipping invalid policy update: %v", err)
				continue
			}
			eng = ne
			p.apply(eng)
		case <-t.C:
			p.apply(eng)
		}
	}
}

func (p *Programmer) disable() {
	if err := p.maps.Cfg.Put(uint32(0), cfgVal{Enabled: 0, DryRun: 0}); err != nil {
		log.Printf("ebfw enforce: disable enforcement: %v", err)
	}
}

// apply computes the desired map contents for the policy and reconciles them.
func (p *Programmer) apply(eng policy.Engine) {
	pol := eng.Policy()
	pods := p.resolver.Pods()

	newCIDR := map[string]struct{}{}
	newVerdict := map[verdictKey]struct{}{}
	newDefault := map[uint64]struct{}{}

	// Global default posture (key 0); always present.
	if err := p.maps.Default.Put(uint64(0), actionByte(defaultActionOf(pol))); err == nil {
		newDefault[0] = struct{}{}
	}

	deferred := 0
	rules := pol.Rules
	// Reverse order so the FIRST matching rule wins on identical keys
	// (map writes are last-wins; reversing makes rule 0's write land last).
	for i := len(rules) - 1; i >= 0; i-- {
		r := &rules[i]
		act := actionByte(r.Action)

		cgs := matchCgroups(r.Match.Pod, pods)
		if len(cgs) == 0 {
			continue // selector matches no current pod (or labels not yet synced)
		}

		hasCIDR := len(r.Match.CIDRs) > 0
		hasDomain := len(r.Match.Domains) > 0
		hasPorts := len(r.Match.Ports) > 0
		hasL7 := len(r.Match.Methods) > 0 || r.Match.PathPrefix != ""

		if hasL7 {
			deferred++ // method/path need the (deferred) proxy datapath
			continue
		}
		if hasDomain {
			continue // enforced by the DNS learner, not the map programmer
		}

		switch {
		case hasCIDR:
			for _, cg := range cgs {
				for _, c := range r.Match.CIDRs {
					if p.programCIDR(cg, c, r.Match.Ports, act, newCIDR, newVerdict) {
						continue
					}
					deferred++
				}
			}
		case hasPorts:
			deferred++ // port-only (no destination IP) — not representable in the datapath
		default:
			// Pod-only rule: set the per-cgroup default for matched pods.
			for _, cg := range cgs {
				if err := p.maps.Default.Put(cg, act); err == nil {
					newDefault[cg] = struct{}{}
				}
			}
		}
	}

	p.reconcile(newCIDR, newVerdict, newDefault)
	metrics.PolicyRules.Set(float64(len(rules)))
	if deferred > 0 {
		log.Printf("ebfw enforce: %d policy dimension(s) not enforceable at the cgroup datapath yet "+
			"(domain/L7 need DNS learning or the proxy; port-only, IPv6 and CIDR+port are deferred) "+
			"— still evaluated for log/metrics", deferred)
	}
}

// programCIDR programs one CIDR (optionally port-scoped) for one cgroup. It
// returns false when the rule shape can't be represented at the datapath yet.
func (p *Programmer) programCIDR(cg uint64, cidr string, ports []uint16, act uint8,
	newCIDR map[string]struct{}, newVerdict map[verdictKey]struct{}) bool {

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return false // IPv6 CIDR — not yet supported
	}
	ones, _ := ipnet.Mask.Size()

	if len(ports) > 0 {
		if ones != 32 {
			return false // CIDR range + port not representable (LPM has no port)
		}
		for _, port := range ports {
			k := verdictKey{CgroupID: cg}
			copy(k.DAddr[:], ip4)
			binary.BigEndian.PutUint16(k.DPort[:], port)
			if err := p.maps.Verdicts.Put(k, act); err == nil {
				newVerdict[k] = struct{}{}
			}
		}
		return true
	}

	key := cidrKeyBytes(uint32(64+ones), cg, ip4)
	if err := p.maps.CIDR.Put(key, act); err == nil {
		newCIDR[string(key)] = struct{}{}
	}
	return true
}

// reconcile deletes entries this Programmer wrote previously that are no longer
// desired, then records the new key sets. The global default (key 0) is never
// deleted — it is rewritten every apply.
func (p *Programmer) reconcile(newCIDR map[string]struct{}, newVerdict map[verdictKey]struct{}, newDefault map[uint64]struct{}) {
	for k := range p.prevCIDR {
		if _, ok := newCIDR[k]; !ok {
			_ = p.maps.CIDR.Delete([]byte(k))
		}
	}
	for k := range p.prevVerdict {
		if _, ok := newVerdict[k]; !ok {
			_ = p.maps.Verdicts.Delete(k)
		}
	}
	for k := range p.prevDefault {
		if k == 0 {
			continue
		}
		if _, ok := newDefault[k]; !ok {
			_ = p.maps.Default.Delete(k)
		}
	}
	p.prevCIDR, p.prevVerdict, p.prevDefault = newCIDR, newVerdict, newDefault
}

// matchCgroups returns the cgroup ids whose pod matches the selector. An empty
// selector is node-global (cgroup id 0). Identity dimensions (namespace/name/uid)
// and label requirements (matchLabels + matchExpressions, including a folded
// policy-level subject selector) are matched against the resolved PodInfo. Pods
// whose labels haven't been enriched yet simply don't match until the next
// re-walk picks them up.
func matchCgroups(sel policy.PodSelector, pods map[uint64]attr.PodInfo) []uint64 {
	if sel.IsZero() {
		return []uint64{0}
	}
	var out []uint64
	for cg, info := range pods {
		if sel.Namespace != "" && sel.Namespace != info.Namespace {
			continue
		}
		if sel.Name != "" && sel.Name != info.Name {
			continue
		}
		if sel.UID != "" && sel.UID != info.UID {
			continue
		}
		if !sel.MatchesLabels(info.Labels) {
			continue
		}
		out = append(out, cg)
	}
	return out
}

func actionByte(a policy.Action) uint8 {
	if a == policy.ActionDeny {
		return actDeny
	}
	return actAllow // Allow, and Modify (the datapath cannot mutate, so it passes)
}

func defaultActionOf(p *policy.Policy) policy.Action {
	if p.EffectiveDefault() == policy.PostureDeny {
		return policy.ActionDeny
	}
	return policy.ActionAllow
}

// cidrKeyBytes builds the 16-byte LPM key matching struct cidr_key (packed):
// prefixlen(u32, host order) || cgroup_id(u64, host order) || addr(4B, network).
func cidrKeyBytes(prefixLen uint32, cgroupID uint64, ip4 net.IP) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], prefixLen)
	binary.LittleEndian.PutUint64(b[4:12], cgroupID)
	copy(b[12:16], ip4.To4())
	return b
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
