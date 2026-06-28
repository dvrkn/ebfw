package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ebfwv1 "github.com/dvrkn/ebfw/api/v1"
)

var _ = Describe("ClusterEgressPolicy Controller", func() {
	ctx := context.Background()

	reconcileAndGet := func(name string) *ebfwv1.ClusterEgressPolicy {
		r := &ClusterEgressPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
		Expect(err).NotTo(HaveOccurred())
		got := &ebfwv1.ClusterEgressPolicy{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name}, got)).To(Succeed())
		return got
	}

	It("marks a valid cluster policy Accepted", func() {
		cegp := &ebfwv1.ClusterEgressPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "node-deny"},
			Spec: ebfwv1.EgressPolicySpec{
				DefaultAction: "Deny",
				Rules: []ebfwv1.Rule{
					{Name: "allow-dns", Action: "Allow", Match: ebfwv1.Match{Ports: []int32{53}}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, cegp)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, cegp) })

		got := reconcileAndGet("node-deny")
		cond := meta.FindStatusCondition(got.Status.Conditions, condTypeAccepted)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(got.Status.RuleCount).To(Equal(int32(1)))
		Expect(got.Status.ObservedGeneration).To(Equal(got.Generation))
	})

	It("marks a Modify rule without mutations not Accepted", func() {
		cegp := &ebfwv1.ClusterEgressPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-modify"},
			Spec: ebfwv1.EgressPolicySpec{
				Rules: []ebfwv1.Rule{
					{Name: "modify", Action: "Modify", Match: ebfwv1.Match{Domains: []string{"example.com"}}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, cegp)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, cegp) })

		got := reconcileAndGet("bad-modify")
		cond := meta.FindStatusCondition(got.Status.Conditions, condTypeAccepted)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal("ValidationFailed"))
	})
})
