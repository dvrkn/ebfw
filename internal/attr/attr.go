package attr

import "sync"

// PodInfo is the resolved identity of the pod that produced a flow. Fields are
// best-effort: UID/Container/QoS come from the cgroup path (node-local, always
// available for pod traffic); Namespace/Name/Node/Labels require the Kubernetes
// API and are empty off-cluster or before the informer has synced. Labels back
// label-selector policy matching (Policy.PodSelector and per-rule pod labels).
type PodInfo struct {
	Namespace string
	Name      string
	UID       string
	Container string
	QoS       string
	Node      string
	Labels    map[string]string
}

// Known reports whether the flow was attributed to a pod at all.
func (p PodInfo) Known() bool { return p.UID != "" }

// String renders "namespace/name" when enriched, "uid:<uid>" when only the
// node-local identity is known, and "" when unattributed.
func (p PodInfo) String() string {
	switch {
	case p.Namespace != "" && p.Name != "":
		return p.Namespace + "/" + p.Name
	case p.UID != "":
		return "uid:" + p.UID
	default:
		return ""
	}
}

// Enricher turns a pod UID into namespace/name/node + labels. Implementations
// must be safe for concurrent use and cheap (called per event). The returned
// labels map must be treated read-only by callers.
type Enricher interface {
	Enrich(uid string) (namespace, name, node string, labels map[string]string, ok bool)
	Close()
}

// nopEnricher is used when no in-cluster Kubernetes API is available; it leaves
// PodInfo with only the node-local identity.
type nopEnricher struct{}

func (nopEnricher) Enrich(string) (string, string, string, map[string]string, bool) {
	return "", "", "", nil, false
}
func (nopEnricher) Close() {}

type cacheEntry struct {
	id PodID
	ok bool
}

// Resolver maps a cgroup v2 id (captured in-kernel by both the egress monitor and
// the SSL_write uprobe) to a PodInfo. The expensive cgroup-tree walk is done
// lazily and cached; the parse/enrich steps are cheap and run per call so
// enrichment is never stale (e.g. a pod resolved before the informer synced
// becomes named on the next hit).
type Resolver struct {
	root     string
	enricher Enricher

	mu       sync.Mutex
	inoIndex map[uint64]string // cgroup id (dir inode) -> cgroup path
	idCache  map[uint64]cacheEntry
}

// NewResolver returns a resolver over the cgroup v2 tree mounted at cgroupRoot.
// A nil enricher disables namespace/name enrichment (node-local identity only).
func NewResolver(cgroupRoot string, e Enricher) *Resolver {
	if e == nil {
		e = nopEnricher{}
	}
	return &Resolver{
		root:     cgroupRoot,
		enricher: e,
		inoIndex: map[uint64]string{},
		idCache:  map[uint64]cacheEntry{},
	}
}

// Close releases the enricher (e.g. stops the informer).
func (r *Resolver) Close() { r.enricher.Close() }

// ByCgroupID resolves the pod for a cgroup v2 id from bpf_skb_cgroup_id. id == 0
// means the kernel had no cgroup association — unattributable.
func (r *Resolver) ByCgroupID(id uint64) PodInfo {
	if id == 0 {
		return PodInfo{}
	}
	r.mu.Lock()
	ent, cached := r.idCache[id]
	r.mu.Unlock()
	if !cached {
		if path, ok := r.lookupPath(id); ok {
			ent.id, ent.ok = ParsePath(path)
		}
		r.mu.Lock()
		r.idCache[id] = ent
		r.mu.Unlock()
	}
	if !ent.ok {
		return PodInfo{}
	}
	return r.enrich(ent.id)
}

// Pods walks the cgroup tree and returns the current pod cgroups keyed by
// cgroup id, each resolved (and best-effort enriched) to a PodInfo. The
// enforcement programmer uses it to map a pod selector to the cgroup ids it
// must program. The walk also refreshes the resolver's inode index.
func (r *Resolver) Pods() map[uint64]PodInfo {
	idx := buildInoIndex(r.root)
	out := make(map[uint64]PodInfo, len(idx))
	for id, path := range idx {
		if pid, ok := ParsePath(path); ok {
			out[id] = r.enrich(pid)
		}
	}
	r.mu.Lock()
	r.inoIndex = idx
	r.mu.Unlock()
	return out
}

// lookupPath returns the cgroup path for a cgroup id, rebuilding the inode index
// once on a miss (a new pod appeared since the last walk).
func (r *Resolver) lookupPath(id uint64) (string, bool) {
	r.mu.Lock()
	p, ok := r.inoIndex[id]
	r.mu.Unlock()
	if ok {
		return p, true
	}
	idx := buildInoIndex(r.root)
	r.mu.Lock()
	r.inoIndex = idx
	r.mu.Unlock()
	p, ok = idx[id]
	return p, ok
}

func (r *Resolver) enrich(id PodID) PodInfo {
	info := PodInfo{UID: id.UID, Container: id.ContainerID, QoS: id.QoS}
	if ns, name, node, labels, ok := r.enricher.Enrich(id.UID); ok {
		info.Namespace, info.Name, info.Node, info.Labels = ns, name, node, labels
	}
	return info
}
