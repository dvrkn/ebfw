package controller

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ebfwv1 "github.com/dvrkn/ebfw/api/v1"
)

// condTypeAccepted is the status condition both controllers manage: True when
// the spec validates, False (with a reason) otherwise.
const condTypeAccepted = "Accepted"

// refreshStatus updates the shared EgressPolicyStatus in place from a validation
// result and reports whether anything changed (so the caller can skip a no-op
// Status().Update and avoid a reconcile hot-loop). validationErr nil means the
// spec is valid.
func refreshStatus(st *ebfwv1.EgressPolicyStatus, generation int64, ruleCount int32, validationErr error) bool {
	changed := false
	if st.ObservedGeneration != generation {
		st.ObservedGeneration = generation
		changed = true
	}
	if st.RuleCount != ruleCount {
		st.RuleCount = ruleCount
		changed = true
	}

	cond := metav1.Condition{Type: condTypeAccepted, ObservedGeneration: generation}
	if validationErr == nil {
		cond.Status = metav1.ConditionTrue
		cond.Reason = "Validated"
		cond.Message = "policy spec is valid"
	} else {
		cond.Status = metav1.ConditionFalse
		cond.Reason = "ValidationFailed"
		cond.Message = validationErr.Error()
	}
	if meta.SetStatusCondition(&st.Conditions, cond) {
		changed = true
	}
	return changed
}
