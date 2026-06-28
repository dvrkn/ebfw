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
//   - egress enforcement is off by default; EBFW_ENFORCE_MODE
//     (off|log|enforce) + EBFW_POLICY (policy YAML path) enable it.
//
// The `ebfw policy test` subcommand evaluates a policy file against sample flows
// without touching the kernel.
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
	"k8s.io/client-go/rest"

	"github.com/dvrkn/ebfw/internal/attr"
	"github.com/dvrkn/ebfw/internal/cli"
	"github.com/dvrkn/ebfw/internal/config"
	"github.com/dvrkn/ebfw/internal/crdsource"
	"github.com/dvrkn/ebfw/internal/egress"
	"github.com/dvrkn/ebfw/internal/enforce"
	"github.com/dvrkn/ebfw/internal/metrics"
	"github.com/dvrkn/ebfw/internal/output"
	"github.com/dvrkn/ebfw/internal/policy"
	"github.com/dvrkn/ebfw/internal/sslsnoop"
)

func main() {
	log.SetFlags(log.LstdFlags)

	// Subcommands run before any eBPF/kernel setup so they work anywhere
	// (no root, no Linux): `ebfw policy test ...` evaluates a policy file.
	if len(os.Args) > 1 && os.Args[1] == "policy" {
		os.Exit(cli.PolicyMain(os.Args[2:]))
	}

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

	baseSink := output.New(cfg.Output)
	go metrics.Serve(cfg.MetricsAddr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Egress enforcement: wrap the output sink so events carry their
	// policy verdict. Observe-only unless EBFW_ENFORCE_MODE is log or enforce.
	// kernelSrc is non-nil only in enforce mode, where egress programs the
	// cgroup drop datapath from it.
	sink, kernelSrc := setupEnforcement(ctx, cfg, baseSink)

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
		if err := egress.Run(ctx, cfg, filter, resolver, sink, kernelSrc); err != nil {
			log.Printf("ebfw: monitor stopped: %v", err)
			stop()
		}
	}()

	wg.Wait()
}

// setupEnforcement wraps the output sink with policy evaluation when
// enforcement is enabled. It returns the wrapped sink and, in enforce mode, the
// PolicySource that egress uses to program the cgroup drop datapath (nil
// otherwise). Loading is best-effort: mode=off or a missing policy keeps the
// agent observe-only; an explicitly invalid policy file (or bad mode) is fatal
// so misconfiguration is loud rather than silently ignored.
func setupEnforcement(ctx context.Context, cfg *config.Config, inner output.Sink) (output.Sink, policy.PolicySource) {
	mode := cfg.Enforce.Mode
	if mode == "" || mode == "off" {
		if cfg.Enforce.PolicyPath != "" {
			log.Printf("ebfw: enforcement off (observe-only); set EBFW_ENFORCE_MODE=log|enforce to apply %s", cfg.Enforce.PolicyPath)
		}
		return inner, nil
	}
	if mode != "log" && mode != "enforce" {
		log.Fatalf("ebfw: invalid EBFW_ENFORCE_MODE %q (want off, log, or enforce)", mode)
	}

	src := policySource(ctx, cfg, mode)

	s, err := enforce.NewSink(ctx, src, mode, inner)
	if err != nil {
		log.Fatalf("ebfw: %v", err)
	}
	p := src.Snapshot()
	log.Printf("ebfw: enforcement %s — %d rules, default %s, source=%q",
		mode, len(p.Rules), p.EffectiveDefault(), cfg.Enforce.Source)

	// Only enforce mode programs the kernel datapath. Log mode is userspace-only.
	if mode == "enforce" {
		return s, src
	}
	return s, nil
}

// policySource builds the policy source for the configured EBFW_POLICY_SOURCE.
// "crd" watches the EgressPolicy + ClusterEgressPolicy CRDs in-cluster; if that
// is unavailable (e.g. off-cluster) it falls back to the file/empty source so
// the host e2e keeps working. "file" (default) loads EBFW_POLICY, or the empty
// allow-all policy when unset.
func policySource(ctx context.Context, cfg *config.Config, mode string) policy.PolicySource {
	if cfg.Enforce.Source == "crd" {
		rc, err := rest.InClusterConfig()
		if err == nil {
			s, serr := crdsource.New(ctx, rc, cfg.NodeName)
			if serr == nil {
				log.Printf("ebfw: enforcement %s — policy source CRD (EgressPolicy + ClusterEgressPolicy)", mode)
				return s
			}
			err = serr
		}
		log.Printf("ebfw: CRD policy source unavailable (%v); falling back to file/empty", err)
	}
	if cfg.Enforce.PolicyPath == "" {
		log.Printf("ebfw: enforcement mode=%s but no EBFW_POLICY; using empty allow-all policy", mode)
		return policy.EmptySource()
	}
	s, err := policy.NewFileSource(cfg.Enforce.PolicyPath)
	if err != nil {
		log.Fatalf("ebfw: %v", err)
	}
	return s
}
