// Package crdsource provides a policy.PolicySource backed by the EgressPolicy
// and ClusterEgressPolicy CRDs. The per-node agent watches both kinds
// cluster-wide, aggregates them into one node policy, and broadcasts changes —
// so the existing enforce stack (Programmer, DNSLearner, sink) consumes
// CRD-driven policy with no datapath change. It lives outside internal/policy
// because it imports controller-runtime/client-go, and internal/policy is pure.
package crdsource

import (
	"context"
	"fmt"
	"log"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ebfwv1 "github.com/dvrkn/ebfw/api/v1"
	"github.com/dvrkn/ebfw/internal/policy"
)

// Source watches EgressPolicy + ClusterEgressPolicy and presents their
// aggregate as a policy.PolicySource. It mirrors the file source's lossy
// buffered broadcast contract.
type Source struct {
	cache ctrlcache.Cache

	mu  sync.RWMutex
	cur *policy.Policy

	subMu sync.Mutex
	subs  []chan *policy.Policy
}

// New starts informers for both CRD kinds (cluster-wide), blocks until the
// initial cache sync completes so Snapshot is meaningful on return, then keeps
// them running until ctx is cancelled. It fails if the in-cluster client cannot
// be built (caller falls back to the file/empty source off-cluster).
func New(ctx context.Context, restConfig *rest.Config, nodeName string) (*Source, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ebfwv1.AddToScheme(scheme))

	c, err := ctrlcache.New(restConfig, ctrlcache.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}

	s := &Source{cache: c, cur: &policy.Policy{DefaultAction: policy.PostureAllow}}

	go func() {
		if err := c.Start(ctx); err != nil {
			log.Printf("ebfw crdsource: cache stopped: %v", err)
		}
	}()
	if !c.WaitForCacheSync(ctx) {
		return nil, fmt.Errorf("cache sync failed")
	}

	handler := toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(interface{}) { s.rebuild(ctx) },
		UpdateFunc: func(interface{}, interface{}) { s.rebuild(ctx) },
		DeleteFunc: func(interface{}) { s.rebuild(ctx) },
	}
	for _, obj := range []client.Object{&ebfwv1.EgressPolicy{}, &ebfwv1.ClusterEgressPolicy{}} {
		inf, err := c.GetInformer(ctx, obj)
		if err != nil {
			return nil, fmt.Errorf("get informer: %w", err)
		}
		if _, err := inf.AddEventHandler(handler); err != nil {
			return nil, fmt.Errorf("add event handler: %w", err)
		}
	}

	s.rebuild(ctx)
	log.Printf("ebfw crdsource: watching EgressPolicy + ClusterEgressPolicy (node %q)", nodeName)
	return s, nil
}

// Snapshot returns the current aggregated policy. Never nil.
func (s *Source) Snapshot() *policy.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Subscribe returns a buffered, lossy channel that receives the new aggregate on
// every CRD change.
func (s *Source) Subscribe() <-chan *policy.Policy {
	ch := make(chan *policy.Policy, 1)
	s.subMu.Lock()
	s.subs = append(s.subs, ch)
	s.subMu.Unlock()
	return ch
}

// rebuild lists both kinds, drops any CR that fails validation (so one bad CR
// never breaks the node), aggregates the rest, and broadcasts.
func (s *Source) rebuild(ctx context.Context) {
	var clList ebfwv1.ClusterEgressPolicyList
	if err := s.cache.List(ctx, &clList); err != nil {
		log.Printf("ebfw crdsource: list ClusterEgressPolicy: %v", err)
		return
	}
	var nsList ebfwv1.EgressPolicyList
	if err := s.cache.List(ctx, &nsList); err != nil {
		log.Printf("ebfw crdsource: list EgressPolicy: %v", err)
		return
	}

	var cluster []policy.ClusterPolicy
	for i := range clList.Items {
		cep := &clList.Items[i]
		p := cep.Spec.ToPolicy()
		if err := p.Validate(); err != nil {
			log.Printf("ebfw crdsource: skipping invalid ClusterEgressPolicy %s: %v", cep.Name, err)
			continue
		}
		cluster = append(cluster, policy.ClusterPolicy{Name: cep.Name, Policy: p})
	}

	var namespaced []policy.NamespacedPolicy
	for i := range nsList.Items {
		ep := &nsList.Items[i]
		p := ep.Spec.ToPolicy()
		if err := p.Validate(); err != nil {
			log.Printf("ebfw crdsource: skipping invalid EgressPolicy %s/%s: %v", ep.Namespace, ep.Name, err)
			continue
		}
		namespaced = append(namespaced, policy.NamespacedPolicy{Namespace: ep.Namespace, Name: ep.Name, Policy: p})
	}

	agg := policy.Aggregate(cluster, namespaced)
	s.mu.Lock()
	s.cur = agg
	s.mu.Unlock()
	s.broadcast(agg)
}

func (s *Source) broadcast(p *policy.Policy) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for _, ch := range s.subs {
		// Lossy on purpose: replace the latest in a full channel slot.
		select {
		case ch <- p:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- p:
			default:
			}
		}
	}
}
