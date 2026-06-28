package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cegp
// +kubebuilder:printcolumn:name="Default",type=string,JSONPath=`.spec.defaultAction`
// +kubebuilder:printcolumn:name="Rules",type=integer,JSONPath=`.status.ruleCount`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`

// ClusterEgressPolicy controls egress cluster/node-wide. It reuses
// EgressPolicySpec but is cluster-scoped: its rules apply to pods in any
// namespace, and a defaultAction of Deny sets the node-global default-deny
// posture (the cluster-admin opt-in — be sure to allow the API server, image
// registries, and DNS, or node egress breaks).
type ClusterEgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressPolicySpec   `json:"spec,omitempty"`
	Status EgressPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterEgressPolicyList contains a list of ClusterEgressPolicy.
type ClusterEgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterEgressPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterEgressPolicy{}, &ClusterEgressPolicyList{})
}
