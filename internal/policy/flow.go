package policy

import (
	"net"

	"github.com/dvrkn/ebfw/internal/attr"
)

// Flow is the evaluable shape of a single egress attempt. It is the union of
// what the cgroup datapath knows (pod via cgroup_id, dst IP, port) and what L7
// parsing adds (domain/method/path). Absent dimensions are treated by the
// engine as "unconstrained" — a Flow with only Pod+DstIP+Port is enough for
// L3/L4 rules.
type Flow struct {
	Pod    attr.PodInfo
	Labels map[string]string // pod labels, when known (populated from the informer)
	DstIP  net.IP
	Port   uint16
	Domain string // DNS qname / SNI / Host, when known
	Method string // HTTP(S) only
	Path   string // HTTP(S) only
}

// Verdict is the engine's decision for a Flow.
type Verdict struct {
	Action    Action
	Rule      string     // matched rule name ("" means the default posture), for logs/metrics
	Mutations []Mutation // populated only when Action==Modify
}
