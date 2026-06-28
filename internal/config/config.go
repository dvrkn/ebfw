// Package config holds the ebfw agent configuration and the traffic filter
// derived from it. Config comes from an optional YAML file (e.g. a k8s
// ConfigMap); any field left unset falls back to a built-in default.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the full agent configuration.
type Config struct {
	// Cgroup is the cgroup v2 root the egress monitor attaches to.
	Cgroup string `yaml:"cgroup"`
	// Exclude lists traffic that should be dropped from monitor output.
	Exclude Exclude `yaml:"exclude"`
	// Inspect controls L7 inspection depth. Sourced from env (a ConfigMap),
	// not from the YAML file.
	Inspect Inspection `yaml:"-"`
	// Output selects the event format: "text" (default) or "json" (EBFW_OUTPUT).
	Output string `yaml:"-"`
	// MetricsAddr is the listen address for the Prometheus /metrics endpoint
	// (EBFW_METRICS_ADDR); empty disables it.
	MetricsAddr string `yaml:"-"`
	// NodeName scopes the pod-attribution informer to this node (EBFW_NODE_NAME,
	// set via the downward API). Empty falls back to watching all pods.
	NodeName string `yaml:"-"`
	// Enforce controls egress policy enforcement. Sourced from env (a ConfigMap);
	// the policy itself lives in its own YAML file (1:1 with the future CRD).
	Enforce Enforcement `yaml:"-"`
}

// Enforcement holds the egress-enforcement operational toggles.
type Enforcement struct {
	// Mode is "off" (observe-only, default), "log" (evaluate the policy and
	// annotate events, no drops), or "enforce" (drop denied egress at the
	// kernel datapath). EBFW_ENFORCE_MODE.
	Mode string
	// Source selects where the policy comes from: "file" (default; the YAML at
	// PolicyPath, used off-cluster and for the host e2e) or "crd" (watch the
	// EgressPolicy + ClusterEgressPolicy CRDs in-cluster). EBFW_POLICY_SOURCE.
	Source string
	// PolicyPath is the path to the policy YAML file. EBFW_POLICY.
	PolicyPath string
	// PinPath is the bpffs directory for pinned enforcement maps, so an external
	// controller could update policy without a program reload. EBFW_BPF_PIN_PATH.
	PinPath string
	// DryRun, in enforce mode, programs the datapath and computes verdicts but
	// never drops — a high-fidelity canary. EBFW_ENFORCE_DRY_RUN.
	DryRun bool
}

// EnforcementFromEnv reads the enforcement toggles from the environment.
// Enforcement defaults off so the agent stays observe-only until enabled.
func EnforcementFromEnv() Enforcement {
	return Enforcement{
		Mode:       strings.ToLower(envStr("EBFW_ENFORCE_MODE", "off")),
		Source:     strings.ToLower(envStr("EBFW_POLICY_SOURCE", "file")),
		PolicyPath: strings.TrimSpace(os.Getenv("EBFW_POLICY")),
		PinPath:    envStr("EBFW_BPF_PIN_PATH", "/sys/fs/bpf/ebfw"),
		DryRun:     envBool("EBFW_ENFORCE_DRY_RUN", false),
	}
}

// FromEnv populates the env-sourced runtime fields (inspection depth, output
// format, metrics address, node name). Filtering still comes from the YAML file.
func (c *Config) FromEnv() {
	c.Inspect = InspectionFromEnv()
	c.Output = envStr("EBFW_OUTPUT", "text")
	c.MetricsAddr = envStr("EBFW_METRICS_ADDR", ":9090")
	c.NodeName = strings.TrimSpace(os.Getenv("EBFW_NODE_NAME"))
	c.Enforce = EnforcementFromEnv()
}

func envStr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// Inspection controls how deeply HTTP/HTTPS requests are inspected. These are
// operational toggles read from environment variables (set from the ConfigMap).
type Inspection struct {
	// Paths enables HTTPS path capture via the SSL_write uprobe (EBFW_INSPECT_PATHS).
	Paths bool
	// Headers includes HTTP request headers in output (EBFW_INSPECT_HEADERS).
	Headers bool
	// Body is a STUB toggle (EBFW_INSPECT_BODY): request-body capture is not
	// implemented yet — see internal/l7. Enabling it currently does nothing.
	Body bool
}

// InspectionFromEnv reads the inspection toggles from the environment. Path
// inspection defaults on (it is essential); headers/body default off.
func InspectionFromEnv() Inspection {
	return Inspection{
		Paths:   envBool("EBFW_INSPECT_PATHS", true),
		Headers: envBool("EBFW_INSPECT_HEADERS", false),
		Body:    envBool("EBFW_INSPECT_BODY", false),
	}
}

func envBool(key string, def bool) bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv(key))) {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// Exclude defines what counts as "internal" traffic to suppress.
type Exclude struct {
	// CIDRs whose destination IPs are suppressed (e.g. pod/service/private ranges).
	CIDRs []string `yaml:"cidrs"`
	// DomainSuffixes whose DNS/SNI/HTTP host is suppressed (e.g. cluster.local).
	DomainSuffixes []string `yaml:"domainSuffixes"`
}

// Default returns the built-in configuration: suppress private/loopback/cluster
// ranges and common internal domain suffixes so the monitor shows external egress.
func Default() *Config {
	return &Config{
		Cgroup: "/sys/fs/cgroup",
		Exclude: Exclude{
			CIDRs: []string{
				"127.0.0.0/8", "::1/128",
				"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
				"169.254.0.0/16", "fe80::/10", "fc00::/7",
			},
			DomainSuffixes: []string{
				"cluster.local", "svc", "local",
				"in-addr.arpa", "ip6.arpa",
			},
		},
	}
}

// Load returns Default() if path is empty, otherwise YAML-merges path over the
// defaults (slices present in the file replace the corresponding default slice).
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

// Filter is a compiled form of Exclude for fast per-event checks.
type Filter struct {
	cidrs    []*net.IPNet
	suffixes []string // lowercase, no leading/trailing dot
}

// Filter compiles the exclude lists, validating CIDRs.
func (c *Config) Filter() (*Filter, error) {
	f := &Filter{}
	for _, s := range c.Exclude.CIDRs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude CIDR %q: %w", s, err)
		}
		f.cidrs = append(f.cidrs, n)
	}
	for _, s := range c.Exclude.DomainSuffixes {
		s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "."))
		if s != "" {
			f.suffixes = append(f.suffixes, s)
		}
	}
	return f, nil
}

// SkipIP reports whether ip falls in any excluded CIDR.
func (f *Filter) SkipIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range f.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// SkipDomain reports whether name matches (or is a subdomain of) any excluded suffix.
func (f *Filter) SkipDomain(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return false
	}
	for _, suf := range f.suffixes {
		if name == suf || strings.HasSuffix(name, "."+suf) {
			return true
		}
	}
	return false
}
