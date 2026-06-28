// Package enforce wires the policy engine into the agent. It provides an
// output.Sink decorator that evaluates each connection-level event against the
// policy and annotates it with the verdict (the basis for "log" mode and for
// observability of enforce mode), the Programmer that compiles the policy into
// the BPF verdict maps, and the DNS learner that turns domain rules into
// IP-keyed verdicts.
package enforce

import (
	"context"
	"log"
	"net"
	"sync/atomic"

	"github.com/dvrkn/ebfw/internal/metrics"
	"github.com/dvrkn/ebfw/internal/output"
	"github.com/dvrkn/ebfw/internal/policy"
)

// sink decorates an output.Sink: for every connection-level event it evaluates
// the policy, stamps the verdict onto the event (so text/JSON output shows it),
// records the decision metric, then delegates to the inner sink. DNS events
// pass through unannotated — name resolution is always permitted; the verdict
// applies to the ensuing connection, shown on the connect/tls/http(s) event.
//
// The engine is hot-swapped on PolicySource changes via an atomic pointer, so
// Emit stays lock-free on the hot path.
type sink struct {
	mode  string
	inner output.Sink
	eng   atomic.Pointer[engineBox]
}

type engineBox struct{ e policy.Engine }

// NewSink builds the engine from src's current snapshot and returns an
// output.Sink that annotates events with policy verdicts. It watches src for
// hot-reloads until ctx is cancelled. mode is the metric label ("log" or
// "enforce"). It errors only if the initial policy is invalid.
func NewSink(ctx context.Context, src policy.PolicySource, mode string, inner output.Sink) (output.Sink, error) {
	snap := src.Snapshot()
	eng, err := policy.NewEngine(snap)
	if err != nil {
		return nil, err
	}
	s := &sink{mode: mode, inner: inner}
	s.eng.Store(&engineBox{eng})
	metrics.PolicyRules.Set(float64(len(snap.Rules)))
	go s.watch(ctx, src)
	return s, nil
}

func (s *sink) watch(ctx context.Context, src policy.PolicySource) {
	ch := src.Subscribe()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			eng, err := policy.NewEngine(p)
			if err != nil {
				log.Printf("ebfw enforce: ignoring invalid policy update: %v", err)
				continue
			}
			s.eng.Store(&engineBox{eng})
			metrics.PolicyRules.Set(float64(len(p.Rules)))
		}
	}
}

func (s *sink) Emit(e output.Event) {
	switch e.Kind {
	case output.KindConnect, output.KindTLS, output.KindHTTP, output.KindHTTPS:
		v := s.eng.Load().e.Evaluate(flowFromEvent(e))
		if e.Action == "" {
			// log mode (and uprobe HTTPS events): the engine is the source of
			// truth and the flow carries the domain, so the rule name is known.
			e.Action = string(v.Action)
			e.Rule = v.Rule
		} else if string(v.Action) == e.Action {
			// enforce mode: the kernel verdict (already on the event) is
			// authoritative; enrich the rule name only when the engine agrees
			// (it won't for a domain rule on a bare CONNECT — no SNI/Host).
			e.Rule = v.Rule
		}
		metrics.EnforcementDecisionsTotal.WithLabelValues(e.Action, s.mode).Inc()
	}
	s.inner.Emit(e)
}

// flowFromEvent projects an observed event onto the policy Flow shape. Pod
// labels (when the informer has them) drive label-selector and policy-level
// podSelector matching.
func flowFromEvent(e output.Event) policy.Flow {
	var dst net.IP
	if e.Dst != "" {
		dst = net.ParseIP(e.Dst)
	}
	return policy.Flow{
		Pod:    e.Pod,
		Labels: e.Pod.Labels,
		DstIP:  dst,
		Port:   uint16(e.Port),
		Domain: e.Domain,
		Method: e.Method,
		Path:   e.Path,
	}
}
