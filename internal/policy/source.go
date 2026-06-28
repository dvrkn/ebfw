package policy

// PolicySource provides the current policy and notifies on change. The file
// source and a future CRD-informer source implement the same contract, so the
// engine and enforcers are agnostic to where policy comes from.
type PolicySource interface {
	// Snapshot returns the current policy. It never returns nil; an
	// unconfigured source returns the empty (DefaultAction=Allow) policy.
	Snapshot() *Policy
	// Subscribe returns a channel that receives the new *Policy on every
	// change (hot-reload now, CRD update later). The channel is buffered and
	// lossy: a subscriber that falls behind only ever misses intermediate
	// states, never the need to re-read Snapshot.
	Subscribe() <-chan *Policy
}

// EmptySource is a PolicySource that always returns the safe default policy and
// never changes. It is the graceful fallback when no policy file is configured.
func EmptySource() PolicySource { return emptySource{} }

type emptySource struct{}

func (emptySource) Snapshot() *Policy { return &Policy{DefaultAction: PostureAllow} }

func (emptySource) Subscribe() <-chan *Policy { return make(chan *Policy) } // never fires
