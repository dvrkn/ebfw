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

func TestAggregateFoldsSubjectIntoRules(t *testing.T) {
	subject := &LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	ns := []NamespacedPolicy{{
		Namespace: "team-a",
		Name:      "p",
		Policy: &Policy{
			PodSelector: subject,
			Rules:       []Rule{{Name: "allow-gh", Action: ActionAllow, Match: Match{Domains: []string{"github.com"}}}},
		},
	}}
	out := Aggregate(nil, ns)

	r := out.Rules[0]
	if r.Match.Pod.Namespace != "team-a" {
		t.Fatalf("rule not scoped to namespace: %+v", r.Match.Pod)
	}
	if r.Match.Pod.Labels["app"] != "web" {
		t.Fatalf("subject labels not folded into rule: %+v", r.Match.Pod)
	}
	// The aggregate must NOT keep a top-level subject (it has been folded away).
	if !out.PodSelector.Empty() {
		t.Fatalf("aggregate kept a top-level podSelector: %+v", out.PodSelector)
	}
	// Source policy's subject map must be untouched (shared with the CRD object).
	if len(subject.MatchLabels) != 1 {
		t.Fatalf("folding mutated the source subject: %v", subject.MatchLabels)
	}
}

func TestAggregateNamespacedSubjectDefaultDenyScopesToSelectedPods(t *testing.T) {
	ns := []NamespacedPolicy{{
		Namespace: "team-a",
		Name:      "p",
		Policy: &Policy{
			PodSelector:   &LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			DefaultAction: PostureDeny,
			Rules:         []Rule{{Name: "allow-dns", Action: ActionAllow, Match: Match{Ports: []uint16{53}}}},
		},
	}}
	out := Aggregate(nil, ns)

	// Global default stays Allow — a namespaced/subject Deny never cuts the node.
	if out.EffectiveDefault() != PostureAllow {
		t.Fatalf("global default = %q, want Allow", out.EffectiveDefault())
	}
	// The allow rule is scoped to the selected pods.
	if out.Rules[0].Match.Pod.Labels["app"] != "web" || out.Rules[0].Match.Pod.Namespace != "team-a" {
		t.Fatalf("allow rule not scoped to selected pods: %+v", out.Rules[0].Match.Pod)
	}
	// The trailing catch-all Deny is scoped to namespace AND subject labels, so
	// it only denies team-a pods labeled app=web, not the rest of team-a.
	last := out.Rules[len(out.Rules)-1]
	if last.Action != ActionDeny || last.Match.Pod.Namespace != "team-a" || last.Match.Pod.Labels["app"] != "web" {
		t.Fatalf("subject catch-all wrong: %+v", last)
	}
}

func TestAggregateClusterSubjectDenyDoesNotGoGlobal(t *testing.T) {
	cl := []ClusterPolicy{{
		Name: "lockdown",
		Policy: &Policy{
			PodSelector:   &LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			DefaultAction: PostureDeny,
			Rules:         []Rule{{Name: "allow-dns", Action: ActionAllow, Match: Match{Ports: []uint16{53}}}},
		},
	}}
	out := Aggregate(cl, nil)

	// A subject-scoped cluster Deny must NOT flip the node-global default.
	if out.EffectiveDefault() != PostureAllow {
		t.Fatalf("global default = %q, want Allow (subject-scoped cluster Deny)", out.EffectiveDefault())
	}
	// Instead it becomes a node-wide (no namespace) catch-all scoped to the labels.
	last := out.Rules[len(out.Rules)-1]
	if last.Action != ActionDeny || last.Match.Pod.Namespace != "" || last.Match.Pod.Labels["app"] != "web" {
		t.Fatalf("cluster subject catch-all wrong: %+v", last)
	}
	if last.Name != "cluster-default-deny/lockdown" {
		t.Fatalf("catch-all name = %q", last.Name)
	}
}

func TestFlatten(t *testing.T) {
	// No subject: returned unchanged (preserves the global default-deny path).
	plain := &Policy{DefaultAction: PostureDeny, Rules: []Rule{{Name: "r", Action: ActionAllow}}}
	if got := Flatten(plain); got != plain {
		t.Fatalf("Flatten of a subject-less policy should be identity")
	}
	if Flatten(nil) != nil {
		t.Fatalf("Flatten(nil) should be nil")
	}

	// With subject + default-deny: folds into rules + adds a scoped catch-all,
	// and the global default stays Allow.
	subj := &Policy{
		PodSelector:   &LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		DefaultAction: PostureDeny,
		Rules:         []Rule{{Name: "allow-dns", Action: ActionAllow, Match: Match{Ports: []uint16{53}}}},
	}
	out := Flatten(subj)
	if out.EffectiveDefault() != PostureAllow {
		t.Fatalf("flattened default = %q, want Allow", out.EffectiveDefault())
	}
	if out.Rules[0].Match.Pod.Labels["app"] != "web" {
		t.Fatalf("subject not folded into rule: %+v", out.Rules[0].Match.Pod)
	}
	last := out.Rules[len(out.Rules)-1]
	if last.Action != ActionDeny || last.Match.Pod.Labels["app"] != "web" {
		t.Fatalf("flattened catch-all wrong: %+v", last)
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
