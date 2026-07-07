// Package metrics exposes the agent's Prometheus counters and serves them over
// HTTP. Counters are process-global and always recorded; the /metrics endpoint is
// optional (controlled by the address passed to Serve). Labels are deliberately
// low-cardinality — pod identity lives in the event log lines, not in labels.
package metrics

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// EventsTotal counts reported (post-filter) events by kind.
	EventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebfw_events_total",
		Help: "Egress events reported, by kind (dns/tls/http/https/connect).",
	}, []string{"kind"})

	// FilteredTotal counts events suppressed by the internal-traffic filter.
	FilteredTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebfw_filtered_total",
		Help: "Egress events suppressed by the internal-traffic filter, by kind.",
	}, []string{"kind"})

	// AttributionTotal counts pod-attribution outcomes for reported events
	// (result=hit when the flow mapped to a pod, miss otherwise).
	AttributionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebfw_attribution_total",
		Help: "Pod attribution outcomes for reported events.",
	}, []string{"result"})

	// UprobesAttached is the number of libssl SSL_write uprobes attached.
	UprobesAttached = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebfw_uprobe_attached",
		Help: "Number of libssl SSL_write uprobes currently attached.",
	})

	// GoUprobesAttached is the number of Go crypto/tls (*Conn).Write uprobes
	// attached — one per unique Go binary that links crypto/tls statically.
	GoUprobesAttached = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebfw_go_uprobe_attached",
		Help: "Number of Go crypto/tls (*Conn).Write uprobes currently attached.",
	})

	// EnforcementDecisionsTotal counts policy verdicts applied to connection-level
	// events, by action (allow/deny/modify) and mode (log/enforce).
	EnforcementDecisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebfw_enforcement_decisions_total",
		Help: "Egress enforcement decisions, by action and mode.",
	}, []string{"action", "mode"})

	// PolicyRules is the number of rules in the currently loaded egress policy.
	PolicyRules = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebfw_policy_rules",
		Help: "Number of rules in the currently loaded egress policy.",
	})

	// EnforcementDropsTotal counts denials observed at the cgroup datapath, by
	// kind. Under dry-run these are would-be drops (nothing is actually dropped).
	EnforcementDropsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebfw_enforcement_drops_total",
		Help: "Egress denials at the cgroup datapath, by kind (connect/tls/http).",
	}, []string{"kind"})

	// DNSLearnedIPs is the number of domain→IP verdict entries currently
	// programmed by DNS learning.
	DNSLearnedIPs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebfw_dns_learned_ips",
		Help: "Domain→IP verdict entries currently programmed by DNS learning.",
	})
)

// Serve starts an HTTP server exposing /metrics at addr, blocking until the
// process exits. An empty addr disables the endpoint. Errors are logged, not
// fatal — metrics must never take the monitor down.
func Serve(addr string) {
	if addr == "" {
		log.Printf("ebfw metrics: disabled (no address)")
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: addr, Handler: mux}
	log.Printf("ebfw metrics: serving /metrics on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("ebfw metrics: server stopped: %v", err)
	}
}
