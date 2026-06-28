// Command ebfw is a node-level egress visibility agent for Kubernetes.
//
// It always runs the cgroup_skb/egress monitor (outgoing domains via DNS + TLS
// SNI, HTTP request paths, and new TCP connections). When path inspection is
// enabled it additionally runs an SSL_write uprobe to recover HTTPS request
// paths that are encrypted on the wire.
//
// Configuration:
//   - filtering of internal domains/IPs comes from a YAML file (-config / EBFW_CONFIG)
//   - inspection depth comes from environment variables (set via a ConfigMap):
//     EBFW_INSPECT_PATHS (default on), EBFW_INSPECT_HEADERS, EBFW_INSPECT_BODY (stub)
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/rlimit"

	"github.com/dvrkn/ebfw/internal/attr"
	"github.com/dvrkn/ebfw/internal/config"
	"github.com/dvrkn/ebfw/internal/egress"
	"github.com/dvrkn/ebfw/internal/metrics"
	"github.com/dvrkn/ebfw/internal/output"
	"github.com/dvrkn/ebfw/internal/sslsnoop"
)

func main() {
	log.SetFlags(log.LstdFlags)

	cfgPath := flag.String("config", os.Getenv("EBFW_CONFIG"), "path to YAML config file (or env EBFW_CONFIG)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("ebfw: %v", err)
	}
	cfg.FromEnv()

	filter, err := cfg.Filter()
	if err != nil {
		log.Fatalf("ebfw: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("ebfw: remove memlock: %v", err)
	}

	if cfg.Inspect.Body {
		log.Printf("ebfw: EBFW_INSPECT_BODY is set, but request-body inspection is not implemented yet (stub)")
	}

	// Pod attribution: node-local cgroup parsing, best-effort enriched with
	// namespace/name from the Kubernetes API. Off-cluster, enrichment no-ops and
	// only the node-local identity is reported.
	enricher, err := attr.NewK8sEnricher(cfg.NodeName)
	if err != nil {
		log.Printf("ebfw: pod-name enrichment disabled (%v); using node-local identity only", err)
	}
	resolver := attr.NewResolver(cfg.Cgroup, enricher)
	defer resolver.Close()

	sink := output.New(cfg.Output)
	go metrics.Serve(cfg.MetricsAddr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	// Path inspection (HTTPS via SSL_write uprobe) — best-effort: if it fails,
	// the core monitor keeps running.
	if cfg.Inspect.Paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sslsnoop.Run(ctx, cfg, filter, resolver, sink); err != nil {
				log.Printf("ebfw: path inspection stopped: %v", err)
			}
		}()
	} else {
		log.Printf("ebfw: path inspection disabled (EBFW_INSPECT_PATHS=false)")
	}

	// Egress monitor — the core. If it dies, bring the agent down.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := egress.Run(ctx, cfg, filter, resolver, sink); err != nil {
			log.Printf("ebfw: monitor stopped: %v", err)
			stop()
		}
	}()

	wg.Wait()
}
