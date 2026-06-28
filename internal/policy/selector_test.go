package policy

import "testing"

func TestLabelSelectorMatches(t *testing.T) {
	labels := map[string]string{"app": "web", "tier": "frontend", "env": "prod"}

	tests := []struct {
		name string
		sel  *LabelSelector
		want bool
	}{
		{"nil matches all", nil, true},
		{"empty matches all", &LabelSelector{}, true},
		{"matchLabels hit", &LabelSelector{MatchLabels: map[string]string{"app": "web"}}, true},
		{"matchLabels miss value", &LabelSelector{MatchLabels: map[string]string{"app": "api"}}, false},
		{"matchLabels missing key", &LabelSelector{MatchLabels: map[string]string{"missing": "x"}}, false},
		{"matchLabels all-of (AND)", &LabelSelector{MatchLabels: map[string]string{"app": "web", "env": "prod"}}, true},
		{"matchLabels one wrong (AND)", &LabelSelector{MatchLabels: map[string]string{"app": "web", "env": "dev"}}, false},
		{"In hit", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "tier", Operator: OpIn, Values: []string{"frontend", "backend"}}}}, true},
		{"In miss", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "tier", Operator: OpIn, Values: []string{"backend"}}}}, false},
		{"In missing key", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "missing", Operator: OpIn, Values: []string{"x"}}}}, false},
		{"NotIn hit", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "tier", Operator: OpNotIn, Values: []string{"backend"}}}}, true},
		{"NotIn miss", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "tier", Operator: OpNotIn, Values: []string{"frontend"}}}}, false},
		{"NotIn missing key is true", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "missing", Operator: OpNotIn, Values: []string{"x"}}}}, true},
		{"Exists hit", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "env", Operator: OpExists}}}, true},
		{"Exists miss", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "missing", Operator: OpExists}}}, false},
		{"DoesNotExist hit", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "missing", Operator: OpDoesNotExist}}}, true},
		{"DoesNotExist miss", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "env", Operator: OpDoesNotExist}}}, false},
		{"matchLabels AND matchExpressions both hit", &LabelSelector{
			MatchLabels:      map[string]string{"app": "web"},
			MatchExpressions: []LabelSelectorRequirement{{Key: "env", Operator: OpIn, Values: []string{"prod"}}},
		}, true},
		{"matchLabels hit but expression miss", &LabelSelector{
			MatchLabels:      map[string]string{"app": "web"},
			MatchExpressions: []LabelSelectorRequirement{{Key: "env", Operator: OpIn, Values: []string{"dev"}}},
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sel.Matches(labels); got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLabelSelectorMatchesNilLabels(t *testing.T) {
	// A pod with no labels satisfies only empty / DoesNotExist / NotIn selectors.
	if !(&LabelSelector{}).Matches(nil) {
		t.Error("empty selector should match a pod with nil labels")
	}
	if (&LabelSelector{MatchLabels: map[string]string{"app": "web"}}).Matches(nil) {
		t.Error("matchLabels should not match a pod with nil labels")
	}
	if !(&LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "app", Operator: OpDoesNotExist}}}).Matches(nil) {
		t.Error("DoesNotExist should match a pod with nil labels")
	}
}

func TestLabelSelectorValidate(t *testing.T) {
	tests := []struct {
		name    string
		sel     *LabelSelector
		wantErr bool
	}{
		{"nil ok", nil, false},
		{"matchLabels only ok", &LabelSelector{MatchLabels: map[string]string{"a": "b"}}, false},
		{"In with values ok", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "k", Operator: OpIn, Values: []string{"v"}}}}, false},
		{"Exists no values ok", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "k", Operator: OpExists}}}, false},
		{"In without values err", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "k", Operator: OpIn}}}, true},
		{"Exists with values err", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "k", Operator: OpExists, Values: []string{"v"}}}}, true},
		{"missing key err", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Operator: OpExists}}}, true},
		{"missing operator err", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "k"}}}, true},
		{"bad operator err", &LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "k", Operator: "Maybe"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.sel.validate(); (err != nil) != tt.wantErr {
				t.Errorf("validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFoldIntoDoesNotMutateSource(t *testing.T) {
	subjectLabels := map[string]string{"app": "web"}
	sub := &LabelSelector{
		MatchLabels:      subjectLabels,
		MatchExpressions: []LabelSelectorRequirement{{Key: "env", Operator: OpIn, Values: []string{"prod"}}},
	}
	ruleLabels := map[string]string{"tier": "fe"}
	pod := PodSelector{Labels: ruleLabels}

	sub.foldInto(&pod)

	// Folded pod carries both sets.
	if pod.Labels["app"] != "web" || pod.Labels["tier"] != "fe" {
		t.Fatalf("folded labels = %v, want app=web tier=fe", pod.Labels)
	}
	if len(pod.MatchExpressions) != 1 || pod.MatchExpressions[0].Key != "env" {
		t.Fatalf("folded expressions = %+v", pod.MatchExpressions)
	}
	// Source maps/slices must be untouched.
	if len(subjectLabels) != 1 || len(ruleLabels) != 1 {
		t.Fatalf("foldInto mutated a source map: subject=%v rule=%v", subjectLabels, ruleLabels)
	}
	if len(sub.MatchExpressions) != 1 {
		t.Fatalf("foldInto mutated subject expressions: %+v", sub.MatchExpressions)
	}
}
