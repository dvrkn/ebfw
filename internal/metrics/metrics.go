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
