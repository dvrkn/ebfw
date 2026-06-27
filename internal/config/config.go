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
