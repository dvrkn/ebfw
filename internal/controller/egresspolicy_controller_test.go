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

var _ = Describe("EgressPolicy Controller", func() {
	ctx := context.Background()

	reconcileAndGet := func(name string) *ebfwv1.EgressPolicy {
		r := &EgressPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: "default"}})
		Expect(err).NotTo(HaveOccurred())
		got := &ebfwv1.EgressPolicy{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, got)).To(Succeed())
		return got
	}

	It("marks a valid policy Accepted with the rule count", func() {
		egp := &ebfwv1.EgressPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "valid", Namespace: "default"},
			Spec: ebfwv1.EgressPolicySpec{
				DefaultAction: "Deny",
				Rules: []ebfwv1.Rule{
					{Name: "allow-dns", Action: "Allow", Match: ebfwv1.Match{Ports: []int32{53}}},
					{Name: "block-cidr", Action: "Deny", Match: ebfwv1.Match{CIDRs: []string{"1.1.1.0/24"}}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, egp)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, egp) })

		got := reconcileAndGet("valid")
		cond := meta.FindStatusCondition(got.Status.Conditions, condTypeAccepted)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(cond.Reason).To(Equal("Validated"))
		Expect(got.Status.RuleCount).To(Equal(int32(2)))
		Expect(got.Status.ObservedGeneration).To(Equal(got.Generation))
	})

	It("marks a policy with a bad CIDR not Accepted", func() {
		egp := &ebfwv1.EgressPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "invalid", Namespace: "default"},
			Spec: ebfwv1.EgressPolicySpec{
				Rules: []ebfwv1.Rule{
					{Name: "bad", Action: "Deny", Match: ebfwv1.Match{CIDRs: []string{"not-a-cidr"}}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, egp)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, egp) })

		got := reconcileAndGet("invalid")
		cond := meta.FindStatusCondition(got.Status.Conditions, condTypeAccepted)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal("ValidationFailed"))
		Expect(cond.Message).To(ContainSubstring("CIDR"))
	})
})
