package v1

import (
	"testing"

	"github.com/dvrkn/ebfw/internal/policy"
)

func TestToPolicyConvertsAndValidates(t *testing.T) {
	spec := &EgressPolicySpec{
		DefaultAction: "Deny",
		Rules: []Rule{
			{
				Name:   "allow-github",
				Action: "Allow",
				Match: Match{
					Domains: []string{"github.com", "*.githubusercontent.com"},
					Ports:   []int32{443},
				},
			},
			{
				Name:   "tag",
				Action: "Modify",
				Match:  Match{Domains: []string{"api.internal"}},
				Mutations: []Mutation{
					{Type: "SetHeader", Header: "X-Egress", Value: "ebfw"},
				},
			},
		},
	}

	p := spec.ToPolicy()
	if p.DefaultAction != policy.PostureDeny {
		t.Fatalf("defaultAction = %q, want Deny", p.DefaultAction)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(p.Rules))
	}
	if p.Rules[0].Action != policy.ActionAllow {
		t.Fatalf("rule0 action = %q", p.Rules[0].Action)
	}
	if len(p.Rules[0].Match.Ports) != 1 || p.Rules[0].Match.Ports[0] != 443 {
		t.Fatalf("ports narrowing failed: %v", p.Rules[0].Match.Ports)
	}
	if p.Rules[1].Mutations[0].Type != policy.MutSetHeader {
		t.Fatalf("mutation type = %q", p.Rules[1].Mutations[0].Type)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("converted policy should validate: %v", err)
	}
}

func TestPortsNarrowingDropsOutOfRange(t *testing.T) {
	spec := &EgressPolicySpec{Rules: []Rule{{
		Action: "Allow",
		Match:  Match{Ports: []int32{0, 80, 65535, 70000, -1}},
	}}}
	got := spec.ToPolicy().Rules[0].Match.Ports
	want := []uint16{0, 80, 65535}
	if len(got) != len(want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ports[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestToPolicyInvalidSurfacesViaValidate(t *testing.T) {
	spec := &EgressPolicySpec{Rules: []Rule{{
		Name:   "bad",
		Action: "Deny",
		Match:  Match{CIDRs: []string{"not-a-cidr"}},
	}}}
	if err := spec.ToPolicy().Validate(); err == nil {
		t.Fatalf("expected validation error for bad CIDR")
	}
}

func TestNilSpecToPolicy(t *testing.T) {
	var s *EgressPolicySpec
	if p := s.ToPolicy(); p == nil || len(p.Rules) != 0 {
		t.Fatalf("nil spec should yield empty policy, got %+v", p)
	}
}
