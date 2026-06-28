package policy

import "sort"

// ClusterPolicy is one ClusterEgressPolicy CR projected to the pure model. Its
// rules apply node-wide as written (no namespace scoping).
type ClusterPolicy struct {
	Name   string
	Policy *Policy
}

// NamespacedPolicy is one EgressPolicy CR projected to the pure model, tagged
// with the namespace it governs. Aggregate scopes its rules to that namespace.
type NamespacedPolicy struct {
	Namespace string
	Name      string
	Policy    *Policy
}

// ScopeToNamespace forces every rule's pod selector to namespace so a namespaced
// EgressPolicy can only affect pods in its own namespace. It mutates p in place
// (callers pass freshly converted policies) and returns it. A nil policy is
// returned unchanged. Aggregate does this (plus subject folding) itself via
// foldRule; ScopeToNamespace remains for the operator's per-CR validation.
func ScopeToNamespace(p *Policy, namespace string) *Policy {
	if p == nil {
		return nil
	}
	for i := range p.Rules {
		p.Rules[i].Match.Pod.Namespace = namespace
	}
	return p
}

// foldRule returns a copy of r with the policy-level subject selector folded into
// its pod match (so the rule matches only pods satisfying both) and, for a
// namespaced policy, the pod namespace forced. It never mutates r or the source
// policy's maps/slices.
func foldRule(r Rule, subject *LabelSelector, namespace string) Rule {
	out := r
	if namespace != "" {
		out.Match.Pod.Namespace = namespace
	}
	subject.foldInto(&out.Match.Pod)
	return out
}

// subjectCatchAll builds the trailing pod-only Deny rule that realizes a
// subject-scoped (and/or namespace-scoped) defaultAction: Deny: it denies every
// selected pod that matched no explicit Allow. namespace is "" for a
// ClusterEgressPolicy.
func subjectCatchAll(name string, subject *LabelSelector, namespace string) Rule {
	r := Rule{Name: name, Action: ActionDeny, Match: Match{Pod: PodSelector{Namespace: namespace}}}
	subject.foldInto(&r.Match.Pod)
	return r
}

// Flatten folds a single Policy's top-level podSelector into its rules (and a
// trailing catch-all for a subject-scoped default-deny), yielding a Policy the
// Engine and Programmer consume directly. It is how the file source and
// `ebfw policy test` honor spec.podSelector. A policy with no subject selector is
// returned unchanged (preserving the global default-deny path), and nil is
// returned for nil.
func Flatten(p *Policy) *Policy {
	if p == nil || p.PodSelector.Empty() {
		return p
	}
	return Aggregate([]ClusterPolicy{{Name: "policy", Policy: p}}, nil)
}

// Aggregate merges cluster-scoped and namespaced policies into ONE node-wide
// *Policy that the existing Engine and enforce.Programmer consume unchanged. It
// is pure (no eBPF/k8s) and deterministic.
//
// Each policy's top-level podSelector (Policy.PodSelector) is folded into every
// one of its rules and into its default-deny catch-all, so a policy governs only
// its selected pods — including its defaultAction, which never affects unselected
// pods.
//
// Ordering (the engine is first-match-wins):
//  1. cluster-scoped rules (sorted by CR name), applied node-wide as written —
//     so a cluster admin's rules take precedence over namespace (tenant) rules;
//  2. namespaced rules (sorted by namespace, then CR name), each scoped to its
//     own namespace (and subject);
//  3. trailing pod-only catch-all Deny rules for default-deny postures, appended
//     after all explicit rules so a policy's own Allow rules win first, then its
//     remaining selected pods default-deny. A cluster policy's subject-scoped
//     default-deny becomes such a catch-all too (node-wide for its selected
//     pods); the enforce.Programmer realizes a pod-only Deny as a per-cgroup
//     default_action for the matched pods only.
//
// The node-global default becomes Deny only if some ClusterEgressPolicy sets
// defaultAction: Deny AND has no podSelector (the cluster-admin opt-in to true
// node-wide default-deny); otherwise it stays Allow, so a namespaced or
// subject-scoped Deny never cuts off the whole node.
func Aggregate(cluster []ClusterPolicy, namespaced []NamespacedPolicy) *Policy {
	cl := append([]ClusterPolicy(nil), cluster...)
	sort.Slice(cl, func(i, j int) bool { return cl[i].Name < cl[j].Name })

	ns := append([]NamespacedPolicy(nil), namespaced...)
	sort.Slice(ns, func(i, j int) bool {
		if ns[i].Namespace != ns[j].Namespace {
			return ns[i].Namespace < ns[j].Namespace
		}
		return ns[i].Name < ns[j].Name
	})

	out := &Policy{DefaultAction: PostureAllow}
	var clusterCatchAlls []Rule

	// 1. Cluster rules first (node-wide), subject folded. A cluster Deny posture
	// goes node-global only when unselected; a subject-scoped cluster Deny becomes
	// a trailing catch-all instead (appended after namespaced rules in step 3).
	for _, c := range cl {
		if c.Policy == nil {
			continue
		}
		sub := c.Policy.PodSelector
		for i := range c.Policy.Rules {
			out.Rules = append(out.Rules, foldRule(c.Policy.Rules[i], sub, ""))
		}
		if c.Policy.EffectiveDefault() == PostureDeny {
			if sub.Empty() {
				out.DefaultAction = PostureDeny
			} else {
				clusterCatchAlls = append(clusterCatchAlls, subjectCatchAll("cluster-default-deny/"+c.Name, sub, ""))
			}
		}
	}

	// 2. Namespaced explicit rules, each scoped to its namespace and subject.
	for _, n := range ns {
		if n.Policy == nil {
			continue
		}
		sub := n.Policy.PodSelector
		for i := range n.Policy.Rules {
			out.Rules = append(out.Rules, foldRule(n.Policy.Rules[i], sub, n.Namespace))
		}
	}

	// 3. Trailing catch-all Denies: cluster subject-scoped first, then per
	// namespaced default-deny (scoped to its namespace + subject).
	out.Rules = append(out.Rules, clusterCatchAlls...)
	for _, n := range ns {
		if n.Policy == nil || n.Policy.EffectiveDefault() != PostureDeny {
			continue
		}
		out.Rules = append(out.Rules, subjectCatchAll("ns-default-deny/"+n.Namespace+"/"+n.Name, n.Policy.PodSelector, n.Namespace))
	}

	return out
}
