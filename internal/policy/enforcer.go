package policy

import "context"

// Enforcer turns policy into action on a datapath. Implementations are
// independent and may run concurrently (e.g. a cgroup_skb drop enforcer, a
// connect4/6 deny enforcer, and the deferred proxy modify enforcer). Each
// follows the constructor + Run + graceful-fallback pattern of
// egress.Run/sslsnoop.Run: Run owns its resources (BPF maps, listeners),
// re-applies on every PolicySource change, and returns when ctx is cancelled.
//
// Log mode ships no Enforcer implementation — it evaluates the engine in the
// output decorator. The kernel datapaths implement this.
type Enforcer interface {
	Run(ctx context.Context, src PolicySource, eng Engine) error
	// Name identifies the enforcer in logs and metrics.
	Name() string
}
