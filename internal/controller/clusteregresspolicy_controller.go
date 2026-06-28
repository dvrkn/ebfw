package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ebfwv1 "github.com/dvrkn/ebfw/api/v1"
)

// ClusterEgressPolicyReconciler validates ClusterEgressPolicy specs and records
// their acceptance status. Like EgressPolicyReconciler it is thin (status only);
// the agents watch the CRD directly. A cluster-scoped policy's rules are not
// namespace-scoped — they apply node-wide as written.
type ClusterEgressPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=ebfw.dvrkn.com,resources=clusteregresspolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=ebfw.dvrkn.com,resources=clusteregresspolicies/status,verbs=get;update;patch

// Reconcile validates the spec and stamps the Accepted condition +
// observedGeneration/ruleCount onto status.
func (r *ClusterEgressPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cegp ebfwv1.ClusterEgressPolicy
	if err := r.Get(ctx, req.NamespacedName, &cegp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	pol := cegp.Spec.ToPolicy() // cluster-scoped: no namespace forcing.
	if !refreshStatus(&cegp.Status, cegp.Generation, int32(len(cegp.Spec.Rules)), pol.Validate()) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Update(ctx, &cegp); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterEgressPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ebfwv1.ClusterEgressPolicy{}).
		Named("clusteregresspolicy").
		Complete(r)
}
