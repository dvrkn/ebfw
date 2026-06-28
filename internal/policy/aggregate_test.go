package policy

import "testing"

func ruleNames(p *Policy) []string {
	n := make([]string, len(p.Rules))
	for i, r := range p.Rules {
		n[i] = r.Name
	}
	return n
}

func TestAggregateEmpty(t *testing.T) {
	out := Aggregate(nil, nil)
	if out.EffectiveDefault() != PostureAllow {
		t.Fatalf("empty aggregate default = %q, want Allow", out.EffectiveDefault())
	}
	if len(out.Rules) != 0 {
		t.Fatalf("empty aggregate rules = %d, want 0", len(out.Rules))
	}
}

func TestAggregateClusterDenyGoesGlobal(t *testing.T) {
	cl := []ClusterPolicy{{
		Name:   "node",
		Policy: &Policy{DefaultAction: PostureDeny, Rules: []Rule{{Name: "allow-dns", Action: ActionAllow, Match: Match{Ports: []uint16{53}}}}},
	}}
	out := Aggregate(cl, nil)
	if out.EffectiveDefault() != PostureDeny {
		t.Fatalf("cluster Deny did not set global default Deny: got %q", out.EffectiveDefault())
	}
	if got := ruleNames(out); len(got) != 1 || got[0] != "allow-dns" {
		t.Fatalf("cluster rules = %v, want [allow-dns]", got)
	}
}

func TestAggregateNamespacedDenyStaysScoped(t *testing.T) {
	ns := []NamespacedPolicy{{
		Namespace: "walled",
		Name:      "p",
		Policy: &Policy{DefaultAction: PostureDeny, Rules: []Rule{
			{Name: "allow-example", Action: ActionAllow, Match: Match{Domains: []string{"example.com"}}},
		}},
	}}
	out := Aggregate(nil, ns)

	// Global default must stay Allow — a namespaced Deny never cuts off the node.
	if out.EffectiveDefault() != PostureAllow {
		t.Fatalf("namespaced Deny leaked to global default: got %q", out.EffectiveDefault())
	}
	// Explicit rule must be scoped to its namespace.
	if out.Rules[0].Match.Pod.Namespace != "walled" {
		t.Fatalf("explicit rule not scoped: %+v", out.Rules[0].Match.Pod)
	}
	// A trailing catch-all Deny scoped to the namespace must be appended last.
	last := out.Rules[len(out.Rules)-1]
	if last.Action != ActionDeny || last.Match.Pod.Namespace != "walled" {
		t.Fatalf("missing per-namespace catch-all Deny, last=%+v", last)
	}
}

func TestAggregateOrderingClusterBeforeNamespaced(t *testing.T) {
	cl := []ClusterPolicy{{Name: "zzz", Policy: &Policy{Rules: []Rule{{Name: "cluster-rule", Action: ActionDeny}}}}}
	ns := []NamespacedPolicy{{Namespace: "aaa", Name: "n", Policy: &Policy{Rules: []Rule{{Name: "ns-rule", Action: ActionAllow}}}}}
	out := Aggregate(cl, ns)
	got := ruleNames(out)
	if len(got) < 2 || got[0] != "cluster-rule" || got[1] != "ns-rule" {
		t.Fatalf("ordering wrong: %v (cluster must precede namespaced)", got)
	}
}

func TestAggregateDeterministicAndIsolated(t *testing.T) {
	ns := []NamespacedPolicy{
		{Namespace: "b", Name: "p", Policy: &Policy{DefaultAction: PostureDeny, Rules: []Rule{{Name: "b-allow", Action: ActionAllow, Match: Match{Domains: []string{"b.example"}}}}}},
		{Namespace: "a", Name: "p", Policy: &Policy{DefaultAction: PostureDeny, Rules: []Rule{{Name: "a-allow", Action: ActionAllow, Match: Match{Domains: []string{"a.example"}}}}}},
	}
	// Pass in reverse order; result must be sorted by namespace.
	out := Aggregate(nil, ns)
	got := ruleNames(out)
	// Explicit rules first (a then b), then catch-alls (a then b).
	want := []string{"a-allow", "b-allow", "ns-default-deny/a/p", "ns-default-deny/b/p"}
	if len(got) != len(want) {
		t.Fatalf("rules = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rule[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
	// Each namespace's explicit rule is scoped to its own namespace.
	if out.Rules[0].Match.Pod.Namespace != "a" || out.Rules[1].Match.Pod.Namespace != "b" {
		t.Fatalf("namespace scoping wrong: %q %q", out.Rules[0].Match.Pod.Namespace, out.Rules[1].Match.Pod.Namespace)
	}
}

func TestScopeToNamespace(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Name: "r1", Action: ActionAllow, Match: Match{Pod: PodSelector{Namespace: "other", Name: "x"}}},
		{Name: "r2", Action: ActionDeny},
	}}
	ScopeToNamespace(p, "forced")
	for _, r := range p.Rules {
		if r.Match.Pod.Namespace != "forced" {
			t.Fatalf("rule %q namespace = %q, want forced", r.Name, r.Match.Pod.Namespace)
		}
	}
	// Other selector fields are preserved.
	if p.Rules[0].Match.Pod.Name != "x" {
		t.Fatalf("ScopeToNamespace clobbered Name: %q", p.Rules[0].Match.Pod.Name)
	}
	if ScopeToNamespace(nil, "x") != nil {
		t.Fatalf("ScopeToNamespace(nil) should return nil")
	}
}
