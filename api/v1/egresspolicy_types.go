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
	// DefaultAction is applied to a flow that matches no rule. Empty defaults to
	// Allow (blocklist). On a namespaced EgressPolicy, Deny default-denies only
	// that namespace's pods; on a ClusterEgressPolicy it default-denies the node.
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
	// Pod selects source pods. On a namespaced EgressPolicy the namespace is
	// forced to the CR's own namespace.
	// +optional
	Pod PodSelector `json:"pod,omitempty"`

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

// PodSelector picks source pods. Namespace/Name/UID match the resolved pod
// identity exactly; Labels match the pod's labels. On a namespaced EgressPolicy
// the Namespace is overridden with the CR's own namespace.
type PodSelector struct {
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// +optional
	Name string `json:"name,omitempty"`
	// +optional
	UID string `json:"uid,omitempty"`
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
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
	p := &policy.Policy{DefaultAction: policy.DefaultPosture(s.DefaultAction)}
	for i := range s.Rules {
		r := &s.Rules[i]
		pr := policy.Rule{
			Name:   r.Name,
			Action: policy.Action(r.Action),
			Match: policy.Match{
				Pod: policy.PodSelector{
					Namespace: r.Match.Pod.Namespace,
					Name:      r.Match.Pod.Name,
					UID:       r.Match.Pod.UID,
					Labels:    r.Match.Pod.Labels,
				},
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
