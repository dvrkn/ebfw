package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dvrkn/ebfw/internal/policy"
)

// EgressPolicySpec is the egress policy applied to pods. It mirrors the pure
// internal/policy model so the same shape backs the file PolicySource and the
// CRD. Both EgressPolicy (namespaced) and ClusterEgressPolicy (cluster-scoped)
// embed this spec.
type EgressPolicySpec struct {
	// PodSelector selects the source pods this policy governs by label — its rules
	// AND its defaultAction apply only to matching pods, so a defaultAction: Deny
	// with a non-empty selector default-denies only the selected pods and never the
	// rest of the namespace/node. It is required (mirroring
	// NetworkPolicy.spec.podSelector): an EMPTY selector ({}) is explicit for
	// "every pod in scope" — the whole namespace for EgressPolicy, the whole node
	// for ClusterEgressPolicy (which is also how a ClusterEgressPolicy opts into a
	// node-global default-deny).
	// +kubebuilder:validation:Required
	PodSelector metav1.LabelSelector `json:"podSelector"`

	// DefaultAction picks the policy's posture — the verdict for a flow that matches
	// no rule. It is OPTIONAL and defaults to Allow (blocklist mode). It is not
	// inferred from whether rules exist, because each rule carries its own
	// Allow/Deny action: a blocklist is Deny rules + defaultAction Allow ("allow all
	// except these"); an allowlist is Allow rules + defaultAction Deny ("deny all
	// except these"). Set Deny explicitly to opt into allowlist mode.
	// It applies only to the pods selected by podSelector: on a namespaced
	// EgressPolicy, Deny default-denies that namespace's selected pods; on a
	// ClusterEgressPolicy it default-denies the selected pods node-wide, and only an
	// EMPTY podSelector ({}) makes it the true node-global default-deny.
	// +kubebuilder:validation:Enum=Allow;Deny
	// +optional
	DefaultAction string `json:"defaultAction,omitempty"`

	// Rules are evaluated in order; first match wins.
	// +optional
	Rules []Rule `json:"rules,omitempty"`
}

// Rule binds a Match to an Action (and Mutations when Action is Modify).
type Rule struct {
	// Name is a human label for the rule, surfaced in logs and metrics.
	// +optional
	Name string `json:"name,omitempty"`

	// Match selects the flows this rule applies to. An empty Match matches every flow.
	// +optional
	Match Match `json:"match,omitempty"`

	// Action is the verdict for matched flows. Modify permits the flow but
	// applies Mutations (L7; modeled now, not enforced by the datapath yet).
	// +kubebuilder:validation:Enum=Allow;Deny;Modify
	Action string `json:"action"`

	// Mutations are required when Action is Modify and forbidden otherwise.
	// +optional
	Mutations []Mutation `json:"mutations,omitempty"`
}

// Match is an AND across its dimensions; an empty dimension matches anything.
// Within a slice dimension (Domains, CIDRs, Ports, Methods) the semantics are OR.
type Match struct {
	// Domains are DNS qname / TLS SNI / HTTP Host suffix globs: "example.com"
	// and "*.example.com" both match example.com and any subdomain.
	// +optional
	Domains []string `json:"domains,omitempty"`

	// CIDRs are destination IP ranges, e.g. "10.0.0.0/8".
	// +optional
	CIDRs []string `json:"cidrs,omitempty"`

	// Ports are destination ports.
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=65535
	// +optional
	Ports []int32 `json:"ports,omitempty"`

	// Methods (L7) only apply to http/https flows; evaluated for log/metrics and
	// the future proxy, not by the L3/L4 drop datapath.
	// +optional
	Methods []string `json:"methods,omitempty"`

	// PathPrefix (L7): same scope as Methods.
	// +optional
	PathPrefix string `json:"pathPrefix,omitempty"`
}

// Mutation describes an L7 edit, carried as data only for now (the deferred
// proxy enforcer consumes them).
type Mutation struct {
	// +kubebuilder:validation:Enum=SetHeader;AddHeader;RemoveHeader;RewritePath
	Type string `json:"type"`
	// +optional
	Header string `json:"header,omitempty"`
	// +optional
	Value string `json:"value,omitempty"`
	// +optional
	PathReplace string `json:"pathReplace,omitempty"`
}

// EgressPolicyStatus is the observed state, shared by both kinds.
type EgressPolicyStatus struct {
	// ObservedGeneration is the .metadata.generation the controller last validated.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// RuleCount is the number of rules in the validated spec.
	// +optional
	RuleCount int32 `json:"ruleCount,omitempty"`

	// Conditions report acceptance state. Type "Accepted" is True when the spec
	// validates and False (with a reason) otherwise.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=egp
// +kubebuilder:printcolumn:name="Default",type=string,JSONPath=`.spec.defaultAction`
// +kubebuilder:printcolumn:name="Rules",type=integer,JSONPath=`.status.ruleCount`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`

// EgressPolicy controls egress for pods in its own namespace. Enforcement is
// physically node-wide, but a namespaced EgressPolicy only affects pods in its
// namespace and its defaultAction never alters the node-global posture.
type EgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressPolicySpec   `json:"spec,omitempty"`
	Status EgressPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EgressPolicyList contains a list of EgressPolicy.
type EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressPolicy `json:"items"`
}

// ToPolicy converts the spec to the pure internal/policy model. It does not
// scope pod selectors; callers handling a namespaced EgressPolicy apply
// policy.ScopeToNamespace afterwards (Aggregate does this automatically).
func (s *EgressPolicySpec) ToPolicy() *policy.Policy {
	if s == nil {
		return &policy.Policy{}
	}
	p := &policy.Policy{
		PodSelector:   labelSelectorToPolicy(&s.PodSelector),
		DefaultAction: policy.DefaultPosture(s.DefaultAction),
	}
	for i := range s.Rules {
		r := &s.Rules[i]
		pr := policy.Rule{
			Name:   r.Name,
			Action: policy.Action(r.Action),
			// Match.Pod is left zero: source-pod selection comes solely from the
			// top-level spec.podSelector, which Aggregate/Flatten folds into every
			// rule's Match.Pod (with the namespace, for a namespaced EgressPolicy).
			Match: policy.Match{
				Domains:    r.Match.Domains,
				CIDRs:      r.Match.CIDRs,
				Ports:      portsToUint16(r.Match.Ports),
				Methods:    r.Match.Methods,
				PathPrefix: r.Match.PathPrefix,
			},
		}
		for j := range r.Mutations {
			m := &r.Mutations[j]
			pr.Mutations = append(pr.Mutations, policy.Mutation{
				Type:        policy.MutationType(m.Type),
				Header:      m.Header,
				Value:       m.Value,
				PathReplace: m.PathReplace,
			})
		}
		p.Rules = append(p.Rules, pr)
	}
	return p
}

// labelSelectorToPolicy converts a metav1.LabelSelector (the idiomatic CRD shape)
// into the pure model's k8s-free LabelSelector. A nil/empty selector yields nil.
func labelSelectorToPolicy(sel *metav1.LabelSelector) *policy.LabelSelector {
	if sel == nil || (len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0) {
		return nil
	}
	out := &policy.LabelSelector{MatchLabels: sel.MatchLabels}
	for _, req := range sel.MatchExpressions {
		out.MatchExpressions = append(out.MatchExpressions, policy.LabelSelectorRequirement{
			Key:      req.Key,
			Operator: string(req.Operator),
			Values:   req.Values,
		})
	}
	return out
}

// portsToUint16 narrows CRD-friendly int32 ports to the engine's uint16,
// dropping out-of-range values (the CRD item validation also guards 1..65535).
func portsToUint16(in []int32) []uint16 {
	if len(in) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if v < 0 || v > 65535 {
			continue
		}
		out = append(out, uint16(v))
	}
	return out
}

func init() {
	SchemeBuilder.Register(&EgressPolicy{}, &EgressPolicyList{})
}
