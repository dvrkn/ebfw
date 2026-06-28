package attr

import (
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const uidIndex = "uid"

// k8sEnricher resolves pod UIDs to namespace/name via a node-scoped pod informer
// (a shared cache.Indexer keyed on metadata.uid). Lookups are O(1) in-memory.
type k8sEnricher struct {
	indexer cache.Indexer
	node    string
	stop    chan struct{}
}

// NewK8sEnricher builds a best-effort enricher. When no in-cluster Kubernetes
// config is present (e.g. the bare-host e2e), it returns a no-op enricher and a
// non-nil error so the caller can log and continue with node-local identity only.
//
// nodeName scopes the Pods informer with a spec.nodeName field selector, which
// both limits memory and keeps the required RBAC narrow. An empty nodeName falls
// back to watching all pods.
func NewK8sEnricher(nodeName string) (Enricher, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nopEnricher{}, fmt.Errorf("in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nopEnricher{}, fmt.Errorf("kube client: %w", err)
	}

	var opts []informers.SharedInformerOption
	if nodeName != "" {
		opts = append(opts, informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = "spec.nodeName=" + nodeName
		}))
	}
	factory := informers.NewSharedInformerFactoryWithOptions(cs, 0, opts...)
	informer := factory.Core().V1().Pods().Informer()
	if err := informer.AddIndexers(cache.Indexers{
		uidIndex: func(obj any) ([]string, error) {
			p, ok := obj.(*corev1.Pod)
			if !ok {
				return nil, nil
			}
			return []string{string(p.UID)}, nil
		},
	}); err != nil {
		return nopEnricher{}, fmt.Errorf("add uid indexer: %w", err)
	}

	e := &k8sEnricher{
		indexer: informer.GetIndexer(),
		node:    nodeName,
		stop:    make(chan struct{}),
	}
	factory.Start(e.stop)

	// Don't block startup on the initial sync: enrichment is per-call, so it
	// self-heals once the cache fills. Log the sync outcome in the background so
	// "names never appear" is diagnosable (client-go logs reflector/RBAC errors
	// to klog independently).
	go func() {
		if cache.WaitForCacheSync(e.stop, informer.HasSynced) {
			log.Printf("ebfw attr: pod informer synced (node=%q)", nodeName)
		}
	}()
	return e, nil
}

func (e *k8sEnricher) Enrich(uid string) (namespace, name, node string, labels map[string]string, ok bool) {
	objs, err := e.indexer.ByIndex(uidIndex, uid)
	if err != nil || len(objs) == 0 {
		return "", "", "", nil, false
	}
	p, ok := objs[0].(*corev1.Pod)
	if !ok {
		return "", "", "", nil, false
	}
	// p.Labels is owned by the shared informer cache; callers treat it read-only.
	return p.Namespace, p.Name, p.Spec.NodeName, p.Labels, true
}

func (e *k8sEnricher) Close() { close(e.stop) }
