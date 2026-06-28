// Package policy defines the ebfw egress policy model and a pure evaluator for
// it. The types here are deliberately free of eBPF and Kubernetes-runtime
// imports so they can be (a) unit-tested as pure data and (b) embedded verbatim
// as the spec of a future EgressPolicy CRD. Struct tags are JSON+YAML
// so the same type backs the file PolicySource now and the CRD later.
package policy

import (
	"fmt"
	"net"
)

// Action is the verdict a rule (or the default posture) yields for a flow.
type Action string

const (
	ActionAllow Action = "Allow"
	ActionDeny  Action = "Deny"
	// ActionModify permits the flow but applies Mutations. It is modeled here
	// for a stable CRD but NOT enforced yet — the L7-mutating datapath
	// (a terminating proxy + TLS MITM) is deferred. An engine still returns it;
	// the cgroup/connect datapaths treat it as Allow.
	ActionModify Action = "Modify"
)

// DefaultPosture is the verdict applied to a flow that matches no rule.
type DefaultPosture string

const (
	// PostureAllow is blocklist mode: deny only what rules deny; allow the rest.
	PostureAllow DefaultPosture = "Allow"
	// PostureDeny is allowlist mode: allow only what rules allow; deny the rest.
	PostureDeny DefaultPosture = "Deny"
)

// MutationType identifies an L7 edit (carried as data only; not enforced yet).
type MutationType string

const (
	MutSetHeader    MutationType = "SetHeader"
	MutAddHeader    MutationType = "AddHeader"
	MutRemoveHeader MutationType = "RemoveHeader"
	MutRewritePath  MutationType = "RewritePath"
)

// Policy is the whole node's egress policy. It is the natural basis for the
// future EgressPolicy CRD spec: wrap it in metav1.TypeMeta+ObjectMeta, add a
// status, and this struct becomes spec.
type Policy struct {
	// PodSelector limits the whole policy — every rule AND the DefaultAction — to
	// source pods matching this label selector. Empty/nil governs all pods in the
	// policy's scope (the namespace for a namespaced EgressPolicy, the node for a
	// ClusterEgressPolicy). It is "compiled away" by Aggregate/Flatten, which fold
	// it into each rule's pod match and the default-deny catch-all, so the Engine
	// and Programmer never read it directly.
	PodSelector *LabelSelector `json:"podSelector,omitempty" yaml:"podSelector,omitempty"`
	// DefaultAction is applied when no rule matches. Empty defaults to Allow
	// (blocklist) so an empty/observe policy never breaks egress.
	DefaultAction DefaultPosture `json:"defaultAction,omitempty" yaml:"defaultAction,omitempty"`
	// Rules are evaluated in order; first match wins.
	Rules []Rule `json:"rules,omitempty" yaml:"rules,omitempty"`
}

// Rule binds a Match to an Action (and Mutations when Action==Modify).
type Rule struct {
	Name      string     `json:"name,omitempty" yaml:"name,omitempty"`
	Match     Match      `json:"match,omitempty" yaml:"match,omitempty"`
	Action    Action     `json:"action" yaml:"action"`
	Mutations []Mutation `json:"mutations,omitempty" yaml:"mutations,omitempty"`
}

// Match is an AND across the set dimensions; an empty dimension matches
// anything. Within a slice dimension (Domains, CIDRs, Ports, Methods) the
// semantics are OR.
type Match struct {
	// Pod selects source pods (matched against attr.PodInfo + pod labels).
	Pod PodSelector `json:"pod,omitempty" yaml:"pod,omitempty"`
	// Domains are DNS qname / TLS SNI / HTTP Host suffix globs: "example.com"
	// and "*.example.com" both match example.com and any subdomain.
	Domains []string `json:"domains,omitempty" yaml:"domains,omitempty"`
	// CIDRs are destination IP ranges.
	CIDRs []string `json:"cidrs,omitempty" yaml:"cidrs,omitempty"`
	// Ports are destination ports.
	Ports []uint16 `json:"ports,omitempty" yaml:"ports,omitempty"`
	// Methods (L7) only apply to http/https flows; used by the engine for
	// logging/audit and the future proxy, not by the L3/L4 drop datapath.
	Methods []string `json:"methods,omitempty" yaml:"methods,omitempty"`
	// PathPrefix (L7) is the same: engine/log + future proxy only.
	PathPrefix string `json:"pathPrefix,omitempty" yaml:"pathPrefix,omitempty"`
}

// PodSelector picks source pods. Namespace/Name/UID are matched exactly against
// the resolved pod identity; Labels (matchLabels) and MatchExpressions are
// matched against the pod's labels (which require the Kubernetes informer —
// surfaced into attr.PodInfo.Labels). MatchExpressions is normally populated
// only by folding a policy-level subject selector (Policy.PodSelector) in.
type PodSelector struct {
	Namespace        string                     `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Name             string                     `json:"name,omitempty" yaml:"name,omitempty"`
	UID              string                     `json:"uid,omitempty" yaml:"uid,omitempty"`
	Labels           map[string]string          `json:"labels,omitempty" yaml:"labels,omitempty"`
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty" yaml:"matchExpressions,omitempty"`
}

// IsZero reports whether the selector constrains nothing (matches every pod).
func (s PodSelector) IsZero() bool {
	return s.Namespace == "" && s.Name == "" && s.UID == "" &&
		len(s.Labels) == 0 && len(s.MatchExpressions) == 0
}

// Mutation describes an L7 edit. These are carried as data only for now; the
// deferred proxy enforcer consumes them. Defining them now keeps the CRD stable.
type Mutation struct {
	Type        MutationType `json:"type" yaml:"type"`
	Header      string       `json:"header,omitempty" yaml:"header,omitempty"`
	Value       string       `json:"value,omitempty" yaml:"value,omitempty"`
	PathReplace string       `json:"pathReplace,omitempty" yaml:"pathReplace,omitempty"`
}

// EffectiveDefault returns the default posture, resolving the empty value to
// Allow (the safe blocklist default).
func (p *Policy) EffectiveDefault() DefaultPosture {
	if p == nil || p.DefaultAction == "" {
		return PostureAllow
	}
	return p.DefaultAction
}

// Validate checks the policy for internal consistency: known actions/postures,
// parseable CIDRs, and well-formed mutations. It is the same check a future CRD
// admission webhook will call. A nil policy is valid (the empty default).
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	switch p.DefaultAction {
	case "", PostureAllow, PostureDeny:
	default:
		return fmt.Errorf("invalid defaultAction %q (want Allow or Deny)", p.DefaultAction)
	}
	if err := p.PodSelector.validate(); err != nil {
		return fmt.Errorf("podSelector: %w", err)
	}
	for i := range p.Rules {
		if err := p.Rules[i].validate(); err != nil {
			return fmt.Errorf("rule %d (%q): %w", i, p.Rules[i].Name, err)
		}
	}
	return nil
}

func (r *Rule) validate() error {
	switch r.Action {
	case ActionAllow, ActionDeny:
		if len(r.Mutations) > 0 {
			return fmt.Errorf("action %s must not carry mutations", r.Action)
		}
	case ActionModify:
		if len(r.Mutations) == 0 {
			return fmt.Errorf("action Modify requires at least one mutation")
		}
		for j := range r.Mutations {
			if err := r.Mutations[j].validate(); err != nil {
				return fmt.Errorf("mutation %d: %w", j, err)
			}
		}
	case "":
		return fmt.Errorf("missing action")
	default:
		return fmt.Errorf("invalid action %q (want Allow, Deny, or Modify)", r.Action)
	}
	for _, c := range r.Match.CIDRs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
	}
	for i := range r.Match.Pod.MatchExpressions {
		if err := r.Match.Pod.MatchExpressions[i].validate(); err != nil {
			return fmt.Errorf("pod.matchExpressions[%d]: %w", i, err)
		}
	}
	return nil
}

func (m *Mutation) validate() error {
	switch m.Type {
	case MutSetHeader, MutAddHeader, MutRemoveHeader:
		if m.Header == "" {
			return fmt.Errorf("%s requires a header name", m.Type)
		}
	case MutRewritePath:
		if m.PathReplace == "" {
			return fmt.Errorf("%s requires pathReplace", m.Type)
		}
	case "":
		return fmt.Errorf("missing mutation type")
	default:
		return fmt.Errorf("invalid mutation type %q", m.Type)
	}
	return nil
}
