package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ebfwv1 "github.com/dvrkn/ebfw/api/v1"
	"github.com/dvrkn/ebfw/internal/policy"
)

// EgressPolicyReconciler validates EgressPolicy specs and records their
// acceptance status. It is intentionally thin: the per-node agents watch the
// CRDs directly and program the datapath, so the controller never touches eBPF
// maps or renders config — it is the admission-quality status reporter.
type EgressPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=ebfw.dvrkn.com,resources=egresspolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=ebfw.dvrkn.com,resources=egresspolicies/status,verbs=get;update;patch

// Reconcile validates the spec (scoped to the CR's namespace) and stamps the
// Accepted condition + observedGeneration/ruleCount onto status.
func (r *EgressPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var egp ebfwv1.EgressPolicy
	if err := r.Get(ctx, req.NamespacedName, &egp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// A namespaced EgressPolicy can only govern pods in its own namespace.
	pol := policy.ScopeToNamespace(egp.Spec.ToPolicy(), egp.Namespace)
	if !refreshStatus(&egp.Status, egp.Generation, int32(len(egp.Spec.Rules)), pol.Validate()) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Update(ctx, &egp); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *EgressPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ebfwv1.EgressPolicy{}).
		Named("egresspolicy").
		Complete(r)
}
