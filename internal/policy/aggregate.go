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
// returned unchanged.
func ScopeToNamespace(p *Policy, namespace string) *Policy {
	if p == nil {
		return nil
	}
	for i := range p.Rules {
		p.Rules[i].Match.Pod.Namespace = namespace
	}
	return p
}

// Aggregate merges cluster-scoped and namespaced policies into ONE node-wide
// *Policy that the existing Engine and enforce.Programmer consume unchanged. It
// is pure (no eBPF/k8s) and deterministic.
//
// Ordering (the engine is first-match-wins):
//  1. cluster-scoped rules (sorted by CR name), applied node-wide as written —
//     so a cluster admin's rules take precedence over namespace (tenant) rules;
//  2. namespaced rules (sorted by namespace, then CR name), each scoped to its
//     own namespace via ScopeToNamespace;
//  3. a trailing pod-only catch-all Deny for each namespaced CR whose default
//     posture is Deny, scoped to that namespace — appended after all explicit
//     rules so a namespace's own Allow rules win first, then its remaining pods
//     default-deny. The enforce.Programmer realizes this as a per-cgroup
//     default_action for that namespace's pods only.
//
// The node-global default becomes Deny only if some ClusterEgressPolicy sets
// defaultAction: Deny (the cluster-admin opt-in to node-wide default-deny);
// otherwise it stays Allow, so a namespaced Deny never cuts off the whole node.
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

	// 1. Cluster rules first (node-wide); fold a cluster Deny posture into the
	// node-global default.
	for _, c := range cl {
		if c.Policy == nil {
			continue
		}
		out.Rules = append(out.Rules, c.Policy.Rules...)
		if c.Policy.EffectiveDefault() == PostureDeny {
			out.DefaultAction = PostureDeny
		}
	}

	// 2. Namespaced explicit rules, each scoped to its namespace.
	for _, n := range ns {
		if n.Policy == nil {
			continue
		}
		scoped := ScopeToNamespace(n.Policy, n.Namespace)
		out.Rules = append(out.Rules, scoped.Rules...)
	}

	// 3. Trailing per-namespace catch-all Deny for namespaced default-deny.
	for _, n := range ns {
		if n.Policy == nil || n.Policy.EffectiveDefault() != PostureDeny {
			continue
		}
		out.Rules = append(out.Rules, Rule{
			Name:   "ns-default-deny/" + n.Namespace + "/" + n.Name,
			Action: ActionDeny,
			Match:  Match{Pod: PodSelector{Namespace: n.Namespace}},
		})
	}

	return out
}
