package policy

import (
	"fmt"
	"net"
	"strings"

	"github.com/dvrkn/ebfw/internal/attr"
)

// Engine evaluates a Flow against a policy and returns a Verdict. It is pure
// (no I/O, no kernel), so it is unit-testable with table tests exactly like
// internal/attr/parse_test.go. The dry-run/log path uses it per-flow; the
// future map programmer uses Policy() to walk rules.
type Engine interface {
	Evaluate(Flow) Verdict
	// Policy returns the policy this engine was compiled from.
	Policy() *Policy
	// DomainRuleVerdict returns the action and ports of the first domain-bearing
	// rule whose pod selector matches pod/labels and whose domains match qname.
	// The DNS learner uses it to program the verdict for a domain's resolved IPs.
	// ok is false when no domain rule matches (non-domain rules are handled by
	// the map programmer, not DNS learning).
	DomainRuleVerdict(pod attr.PodInfo, labels map[string]string, qname string) (action Action, ports []uint16, ok bool)
}

// NewEngine compiles a *Policy into an Engine (pre-parses CIDRs, lowercases
// domains/methods). A nil policy yields an allow-everything engine. Returns an
// error only for an invalid policy (see Policy.Validate).
func NewEngine(p *Policy) (Engine, error) {
	if p == nil {
		p = &Policy{}
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	e := &engine{policy: p, def: ActionAllow}
	if p.DefaultAction == PostureDeny {
		e.def = ActionDeny
	}
	for i := range p.Rules {
		cr, err := compile(&p.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", p.Rules[i].Name, err)
		}
		e.rules = append(e.rules, cr)
	}
	return e, nil
}

type engine struct {
	policy *Policy
	rules  []compiledRule
	def    Action // default action resolved from the posture
}

func (e *engine) Policy() *Policy { return e.policy }

func (e *engine) DomainRuleVerdict(pod attr.PodInfo, labels map[string]string, qname string) (Action, []uint16, bool) {
	f := Flow{Pod: pod, Labels: labels, Domain: qname}
	for i := range e.rules {
		r := &e.rules[i]
		if len(r.domains) == 0 {
			continue // not domain-specific — handled by the map programmer
		}
		if !r.pod.matches(f) {
			continue
		}
		for _, b := range r.domains {
			if domainMatches(b, qname) {
				return r.action, e.policy.Rules[i].Match.Ports, true
			}
		}
	}
	return "", nil, false
}

// Evaluate walks the rules first-match-wins, falling back to the default action.
func (e *engine) Evaluate(f Flow) Verdict {
	for i := range e.rules {
		if e.rules[i].matches(f) {
			r := &e.rules[i]
			return Verdict{Action: r.action, Rule: r.name, Mutations: r.muts}
		}
	}
	return Verdict{Action: e.def}
}

type compiledRule struct {
	name    string
	action  Action
	muts    []Mutation
	pod     PodSelector
	domains []string // normalized suffix bases; empty => match-all
	cidrs   []*net.IPNet
	ports   map[uint16]struct{}
	methods map[string]struct{} // uppercased
	path    string
}

func compile(r *Rule) (compiledRule, error) {
	cr := compiledRule{
		name:   r.Name,
		action: r.Action,
		muts:   r.Mutations,
		pod:    r.Match.Pod,
		path:   r.Match.PathPrefix,
	}
	for _, d := range r.Match.Domains {
		if base := normalizeDomainPattern(d); base != "" {
			cr.domains = append(cr.domains, base)
		}
	}
	for _, c := range r.Match.CIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return cr, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
		cr.cidrs = append(cr.cidrs, n)
	}
	if len(r.Match.Ports) > 0 {
		cr.ports = make(map[uint16]struct{}, len(r.Match.Ports))
		for _, p := range r.Match.Ports {
			cr.ports[p] = struct{}{}
		}
	}
	if len(r.Match.Methods) > 0 {
		cr.methods = make(map[string]struct{}, len(r.Match.Methods))
		for _, m := range r.Match.Methods {
			cr.methods[strings.ToUpper(strings.TrimSpace(m))] = struct{}{}
		}
	}
	return cr, nil
}

func (r *compiledRule) matches(f Flow) bool {
	if !r.pod.matches(f) {
		return false
	}
	if len(r.domains) > 0 {
		ok := false
		for _, b := range r.domains {
			if domainMatches(b, f.Domain) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.cidrs) > 0 {
		ok := false
		if f.DstIP != nil {
			for _, n := range r.cidrs {
				if n.Contains(f.DstIP) {
					ok = true
					break
				}
			}
		}
		if !ok {
			return false
		}
	}
	if r.ports != nil {
		if _, ok := r.ports[f.Port]; !ok {
			return false
		}
	}
	if r.methods != nil {
		if _, ok := r.methods[strings.ToUpper(f.Method)]; !ok {
			return false
		}
	}
	if r.path != "" && !strings.HasPrefix(f.Path, r.path) {
		return false
	}
	return true
}

func (s PodSelector) matches(f Flow) bool {
	if s.Namespace != "" && s.Namespace != f.Pod.Namespace {
		return false
	}
	if s.Name != "" && s.Name != f.Pod.Name {
		return false
	}
	if s.UID != "" && s.UID != f.Pod.UID {
		return false
	}
	for k, v := range s.Labels {
		if f.Labels[k] != v {
			return false
		}
	}
	return true
}

// normalizeDomainPattern lowercases, trims a trailing dot, and strips a leading
// "*." so "*.example.com", "example.com." and "Example.com" all reduce to the
// suffix base "example.com".
func normalizeDomainPattern(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	p = strings.TrimSuffix(p, ".")
	p = strings.TrimPrefix(p, "*.")
	return p
}

// domainMatches reports whether name equals base or is a subdomain of it. base
// must already be normalized; matching mirrors config.Filter.SkipDomain.
func domainMatches(base, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if base == "" || name == "" {
		return false
	}
	return name == base || strings.HasSuffix(name, "."+base)
}
