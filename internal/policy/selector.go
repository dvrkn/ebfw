package policy

import "fmt"

// LabelSelector is a k8s-free mirror of metav1.LabelSelector. It is the
// policy-level *subject* selector: which source pods a whole Policy governs.
// Keeping it free of k8s/runtime imports lets internal/policy stay pure (see the
// package doc); api/v1 converts metav1.LabelSelector into this on the way in.
//
// An empty selector (no matchLabels and no matchExpressions) matches every pod,
// so a Policy with no podSelector governs all pods in its scope.
type LabelSelector struct {
	// MatchLabels is a set of {key: value} requirements, ANDed: a pod matches
	// only if it carries every listed label with the listed value.
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`
	// MatchExpressions is a list of set-based requirements, also ANDed with each
	// other and with MatchLabels.
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty" yaml:"matchExpressions,omitempty"`
}

// LabelSelectorRequirement is one set-based label requirement, mirroring
// metav1.LabelSelectorRequirement.
type LabelSelectorRequirement struct {
	Key      string   `json:"key" yaml:"key"`
	Operator string   `json:"operator" yaml:"operator"`
	Values   []string `json:"values,omitempty" yaml:"values,omitempty"`
}

// Set-based operators, matching metav1.LabelSelectorOperator string values.
const (
	OpIn           = "In"
	OpNotIn        = "NotIn"
	OpExists       = "Exists"
	OpDoesNotExist = "DoesNotExist"
)

// Empty reports whether the selector constrains nothing (matches every pod). A
// nil selector is empty.
func (s *LabelSelector) Empty() bool {
	return s == nil || (len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0)
}

// Matches reports whether a pod with the given labels satisfies the selector.
// An empty selector matches everything.
func (s *LabelSelector) Matches(labels map[string]string) bool {
	if s.Empty() {
		return true
	}
	for k, v := range s.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for i := range s.MatchExpressions {
		if !s.MatchExpressions[i].matches(labels) {
			return false
		}
	}
	return true
}

// foldInto merges the subject selector into a per-rule PodSelector so the rule
// matches only pods that satisfy BOTH. It allocates fresh maps/slices and never
// mutates the receiver or p's existing maps/slices (callers share them with the
// source CRD/file objects). A no-op for an empty selector.
func (s *LabelSelector) foldInto(p *PodSelector) {
	if s.Empty() {
		return
	}
	if len(s.MatchLabels) > 0 {
		merged := make(map[string]string, len(p.Labels)+len(s.MatchLabels))
		for k, v := range p.Labels {
			merged[k] = v
		}
		for k, v := range s.MatchLabels {
			merged[k] = v
		}
		p.Labels = merged
	}
	if len(s.MatchExpressions) > 0 {
		out := make([]LabelSelectorRequirement, 0, len(p.MatchExpressions)+len(s.MatchExpressions))
		out = append(out, p.MatchExpressions...)
		out = append(out, s.MatchExpressions...)
		p.MatchExpressions = out
	}
}

// validate checks operators and value arity, mirroring apimachinery's selector
// validation closely enough to reject malformed requirements at admission.
func (s *LabelSelector) validate() error {
	if s == nil {
		return nil
	}
	for i := range s.MatchExpressions {
		if err := s.MatchExpressions[i].validate(); err != nil {
			return fmt.Errorf("matchExpressions[%d]: %w", i, err)
		}
	}
	return nil
}

func (r LabelSelectorRequirement) validate() error {
	if r.Key == "" {
		return fmt.Errorf("missing key")
	}
	switch r.Operator {
	case OpIn, OpNotIn:
		if len(r.Values) == 0 {
			return fmt.Errorf("operator %s requires at least one value", r.Operator)
		}
	case OpExists, OpDoesNotExist:
		if len(r.Values) > 0 {
			return fmt.Errorf("operator %s must not have values", r.Operator)
		}
	case "":
		return fmt.Errorf("missing operator")
	default:
		return fmt.Errorf("invalid operator %q (want In, NotIn, Exists, or DoesNotExist)", r.Operator)
	}
	return nil
}

func (r LabelSelectorRequirement) matches(labels map[string]string) bool {
	v, has := labels[r.Key]
	switch r.Operator {
	case OpIn:
		return has && contains(r.Values, v)
	case OpNotIn:
		return !has || !contains(r.Values, v)
	case OpExists:
		return has
	case OpDoesNotExist:
		return !has
	}
	return false
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
