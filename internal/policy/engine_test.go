package policy

import (
	"net"
	"testing"

	"github.com/dvrkn/ebfw/internal/attr"
)

func mustEngine(t *testing.T, p *Policy) Engine {
	t.Helper()
	e, err := NewEngine(p)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestEvaluate(t *testing.T) {
	flow := func(domain, ip string, port uint16) Flow {
		var dst net.IP
		if ip != "" {
			dst = net.ParseIP(ip)
		}
		return Flow{Domain: domain, DstIP: dst, Port: port}
	}

	tests := []struct {
		name   string
		policy *Policy
		flow   Flow
		want   Action
		rule   string
	}{
		{
			name:   "no rules, default allow",
			policy: &Policy{},
			flow:   flow("example.com", "1.2.3.4", 443),
			want:   ActionAllow,
		},
		{
			name:   "allowlist, no match -> deny",
			policy: &Policy{DefaultAction: PostureDeny},
			flow:   flow("evil.com", "9.9.9.9", 443),
			want:   ActionDeny,
		},
		{
			name: "allowlist, domain match -> allow",
			policy: &Policy{DefaultAction: PostureDeny, Rules: []Rule{
				{Name: "gh", Action: ActionAllow, Match: Match{Domains: []string{"github.com"}}},
			}},
			flow: flow("api.github.com", "1.2.3.4", 443),
			want: ActionAllow,
			rule: "gh",
		},
		{
			name: "blocklist, deny rule match",
			policy: &Policy{DefaultAction: PostureAllow, Rules: []Rule{
				{Name: "block-evil", Action: ActionDeny, Match: Match{Domains: []string{"*.evil.com"}}},
			}},
			flow: flow("c2.evil.com", "9.9.9.9", 443),
			want: ActionDeny,
			rule: "block-evil",
		},
		{
			name: "wildcard does not match unrelated apex",
			policy: &Policy{DefaultAction: PostureAllow, Rules: []Rule{
				{Name: "block", Action: ActionDeny, Match: Match{Domains: []string{"example.com"}}},
			}},
			flow: flow("example.com.evil.com", "9.9.9.9", 443),
			want: ActionAllow, // suffix is ".example.com", not "example.com.evil.com"
		},
		{
			name: "CIDR match",
			policy: &Policy{DefaultAction: PostureAllow, Rules: []Rule{
				{Name: "block-net", Action: ActionDeny, Match: Match{CIDRs: []string{"10.8.0.0/16"}}},
			}},
			flow: flow("", "10.8.1.5", 443),
			want: ActionDeny,
			rule: "block-net",
		},
		{
			name: "port-only match",
			policy: &Policy{DefaultAction: PostureAllow, Rules: []Rule{
				{Name: "block-25", Action: ActionDeny, Match: Match{Ports: []uint16{25, 587}}},
			}},
			flow: flow("smtp.example.com", "1.2.3.4", 25),
			want: ActionDeny,
			rule: "block-25",
		},
		{
			name: "AND across dimensions: domain matches but port does not",
			policy: &Policy{DefaultAction: PostureAllow, Rules: []Rule{
				{Name: "r", Action: ActionDeny, Match: Match{Domains: []string{"example.com"}, Ports: []uint16{8080}}},
			}},
			flow: flow("example.com", "1.2.3.4", 443),
			want: ActionAllow, // port 443 not in {8080} -> rule does not match
		},
		{
			name: "first match wins",
			policy: &Policy{DefaultAction: PostureAllow, Rules: []Rule{
				{Name: "allow-api", Action: ActionAllow, Match: Match{Domains: []string{"api.example.com"}}},
				{Name: "deny-all-example", Action: ActionDeny, Match: Match{Domains: []string{"example.com"}}},
			}},
			flow: flow("api.example.com", "1.2.3.4", 443),
			want: ActionAllow,
			rule: "allow-api",
		},
		{
			name: "L7 method and path prefix",
			policy: &Policy{DefaultAction: PostureAllow, Rules: []Rule{
				{Name: "block-admin", Action: ActionDeny, Match: Match{Methods: []string{"post"}, PathPrefix: "/admin"}},
			}},
			flow: Flow{Domain: "x.com", Method: "POST", Path: "/admin/delete"},
			want: ActionDeny,
			rule: "block-admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := mustEngine(t, tt.policy).Evaluate(tt.flow)
			if v.Action != tt.want {
				t.Fatalf("Evaluate action = %s, want %s", v.Action, tt.want)
			}
			if tt.rule != "" && v.Rule != tt.rule {
				t.Errorf("Evaluate rule = %q, want %q", v.Rule, tt.rule)
			}
		})
	}
}

func TestEvaluatePodSelector(t *testing.T) {
	pol := &Policy{DefaultAction: PostureAllow, Rules: []Rule{
		{Name: "ns-deny", Action: ActionDeny, Match: Match{
			Pod:     PodSelector{Namespace: "team-a", Labels: map[string]string{"app": "web"}},
			Domains: []string{"example.com"},
		}},
	}}
	eng := mustEngine(t, pol)

	base := Flow{Domain: "example.com", Port: 443}

	// Matching pod + labels -> deny.
	f := base
	f.Pod = attr.PodInfo{Namespace: "team-a", Name: "web-1"}
	f.Labels = map[string]string{"app": "web", "tier": "fe"}
	if v := eng.Evaluate(f); v.Action != ActionDeny {
		t.Errorf("matching pod: got %s, want Deny", v.Action)
	}

	// Wrong namespace -> default allow.
	f = base
	f.Pod = attr.PodInfo{Namespace: "team-b"}
	f.Labels = map[string]string{"app": "web"}
	if v := eng.Evaluate(f); v.Action != ActionAllow {
		t.Errorf("wrong namespace: got %s, want Allow", v.Action)
	}

	// Right namespace, missing label -> default allow.
	f = base
	f.Pod = attr.PodInfo{Namespace: "team-a"}
	f.Labels = map[string]string{"tier": "fe"}
	if v := eng.Evaluate(f); v.Action != ActionAllow {
		t.Errorf("missing label: got %s, want Allow", v.Action)
	}
}

func TestEvaluatePodMatchExpressions(t *testing.T) {
	// A rule whose pod selector carries a folded subject's matchExpressions:
	// deny example.com only for pods whose tier is in {frontend}.
	pol := &Policy{DefaultAction: PostureAllow, Rules: []Rule{
		{Name: "deny-fe", Action: ActionDeny, Match: Match{
			Pod:     PodSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "tier", Operator: OpIn, Values: []string{"frontend"}}}},
			Domains: []string{"example.com"},
		}},
	}}
	eng := mustEngine(t, pol)
	base := Flow{Domain: "example.com", Port: 443}

	f := base
	f.Labels = map[string]string{"tier": "frontend"}
	if v := eng.Evaluate(f); v.Action != ActionDeny {
		t.Errorf("tier=frontend: got %s, want Deny", v.Action)
	}

	f = base
	f.Labels = map[string]string{"tier": "backend"}
	if v := eng.Evaluate(f); v.Action != ActionAllow {
		t.Errorf("tier=backend: got %s, want Allow", v.Action)
	}

	f = base // no labels at all
	if v := eng.Evaluate(f); v.Action != ActionAllow {
		t.Errorf("no labels: got %s, want Allow", v.Action)
	}
}

func TestEvaluateModifyCarriesMutations(t *testing.T) {
	pol := &Policy{Rules: []Rule{
		{Name: "inject", Action: ActionModify, Match: Match{Domains: []string{"example.com"}}, Mutations: []Mutation{
			{Type: MutSetHeader, Header: "X-Trace", Value: "1"},
		}},
	}}
	v := mustEngine(t, pol).Evaluate(Flow{Domain: "example.com"})
	if v.Action != ActionModify {
		t.Fatalf("action = %s, want Modify", v.Action)
	}
	if len(v.Mutations) != 1 || v.Mutations[0].Header != "X-Trace" {
		t.Fatalf("mutations = %+v, want one SetHeader X-Trace", v.Mutations)
	}
}

func TestDomainRuleVerdict(t *testing.T) {
	pol := &Policy{DefaultAction: PostureDeny, Rules: []Rule{
		{Name: "allow-gh", Action: ActionAllow, Match: Match{Domains: []string{"github.com", "*.githubusercontent.com"}, Ports: []uint16{443}}},
		{Name: "block-ns-evil", Action: ActionDeny, Match: Match{Pod: PodSelector{Namespace: "team-a"}, Domains: []string{"evil.com"}}},
		{Name: "cidr-only", Action: ActionAllow, Match: Match{CIDRs: []string{"10.0.0.0/8"}}}, // not domain-bearing
	}}
	eng := mustEngine(t, pol)

	// Domain match returns action + ports.
	act, ports, ok := eng.DomainRuleVerdict(attr.PodInfo{}, nil, "raw.githubusercontent.com")
	if !ok || act != ActionAllow || len(ports) != 1 || ports[0] != 443 {
		t.Fatalf("github subdomain: ok=%v act=%s ports=%v", ok, act, ports)
	}

	// Pod-scoped domain rule: matches only the right namespace.
	if _, _, ok := eng.DomainRuleVerdict(attr.PodInfo{Namespace: "team-b"}, nil, "evil.com"); ok {
		t.Error("evil.com should not match for team-b")
	}
	if act, _, ok := eng.DomainRuleVerdict(attr.PodInfo{Namespace: "team-a"}, nil, "evil.com"); !ok || act != ActionDeny {
		t.Errorf("evil.com for team-a: ok=%v act=%s", ok, act)
	}

	// Non-domain rule and unmatched name return ok=false.
	if _, _, ok := eng.DomainRuleVerdict(attr.PodInfo{}, nil, "unmatched.example.org"); ok {
		t.Error("unmatched name should return ok=false")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *Policy
		wantErr bool
	}{
		{name: "empty ok", policy: &Policy{}},
		{name: "nil ok", policy: nil},
		{name: "valid allow rule", policy: &Policy{Rules: []Rule{{Action: ActionAllow, Match: Match{Domains: []string{"x.com"}}}}}},
		{name: "bad default", policy: &Policy{DefaultAction: "Maybe"}, wantErr: true},
		{name: "bad action", policy: &Policy{Rules: []Rule{{Action: "Drop"}}}, wantErr: true},
		{name: "missing action", policy: &Policy{Rules: []Rule{{Name: "x"}}}, wantErr: true},
		{name: "allow with mutations", policy: &Policy{Rules: []Rule{{Action: ActionAllow, Mutations: []Mutation{{Type: MutAddHeader, Header: "X"}}}}}, wantErr: true},
		{name: "modify without mutations", policy: &Policy{Rules: []Rule{{Action: ActionModify}}}, wantErr: true},
		{name: "modify with bad mutation", policy: &Policy{Rules: []Rule{{Action: ActionModify, Mutations: []Mutation{{Type: MutSetHeader}}}}}, wantErr: true},
		{name: "bad cidr", policy: &Policy{Rules: []Rule{{Action: ActionDeny, Match: Match{CIDRs: []string{"not-a-cidr"}}}}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
			// NewEngine must reject exactly what Validate rejects.
			_, ne := NewEngine(tt.policy)
			if (ne != nil) != tt.wantErr {
				t.Fatalf("NewEngine() err = %v, wantErr %v", ne, tt.wantErr)
			}
		})
	}
}
