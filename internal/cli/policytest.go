// Package cli implements ebfw subcommands that run without the kernel datapath,
// so they work anywhere (no root, no Linux). Today the only one is `policy
// test`, which evaluates a policy file against sample flows.
package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/dvrkn/ebfw/internal/attr"
	"github.com/dvrkn/ebfw/internal/policy"
)

// PolicyMain implements `ebfw policy <subcommand>` and returns a process exit
// code (0 ok, 1 runtime error, 2 usage error).
func PolicyMain(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, policyUsage)
		return 2
	}
	switch args[0] {
	case "test":
		return policyTest(args[1:])
	case "-h", "--help", "help":
		fmt.Println(policyUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "ebfw policy: unknown subcommand %q\n%s\n", args[0], policyUsage)
		return 2
	}
}

const policyUsage = `usage: ebfw policy test --policy <file> [--flow '<spec>' ...]

Evaluate a policy against one or more flows and print the verdict for each.
A flow spec is space-separated key=value tokens, e.g.:

  ebfw policy test --policy policy.yaml \
    --flow 'pod=team-a/web dst=140.82.112.3 port=443 domain=api.github.com' \
    --flow 'domain=evil.com port=443'

Keys: pod=ns/name, namespace=, name=, uid=, dst=<ip>, port=, domain=,
      method=, path=, label.<k>=<v>

With no --flow, newline-delimited JSON flow objects are read from stdin:
  {"namespace":"team-a","domain":"evil.com","port":443}`

func policyTest(args []string) int {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	path := fs.String("policy", os.Getenv("EBFW_POLICY"), "path to policy YAML (or env EBFW_POLICY)")
	var flows multiFlag
	fs.Var(&flows, "flow", "flow spec (repeatable); see usage")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "ebfw policy test: --policy is required")
		return 2
	}

	p, err := policy.LoadFile(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ebfw policy test: %v\n", err)
		return 1
	}
	eng, err := policy.NewEngine(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ebfw policy test: %v\n", err)
		return 1
	}

	specs, err := collectSpecs(flows)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ebfw policy test: %v\n", err)
		return 2
	}

	for _, sp := range specs {
		v := eng.Evaluate(sp.toFlow())
		rule := v.Rule
		if rule == "" {
			rule = "(default)"
		}
		fmt.Printf("%-7s rule=%-20s %s\n", v.Action, rule, sp.describe())
	}
	return 0
}

// flowSpec is the CLI-friendly description of a flow.
type flowSpec struct {
	Namespace string            `json:"namespace,omitempty"`
	Name      string            `json:"name,omitempty"`
	UID       string            `json:"uid,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Dst       string            `json:"dst,omitempty"`
	Port      uint16            `json:"port,omitempty"`
	Domain    string            `json:"domain,omitempty"`
	Method    string            `json:"method,omitempty"`
	Path      string            `json:"path,omitempty"`
}

func (s flowSpec) toFlow() policy.Flow {
	var dst net.IP
	if s.Dst != "" {
		dst = net.ParseIP(s.Dst)
	}
	return policy.Flow{
		Pod:    attr.PodInfo{Namespace: s.Namespace, Name: s.Name, UID: s.UID},
		Labels: s.Labels,
		DstIP:  dst,
		Port:   s.Port,
		Domain: s.Domain,
		Method: s.Method,
		Path:   s.Path,
	}
}

func (s flowSpec) describe() string {
	var b strings.Builder
	if s.Namespace != "" || s.Name != "" {
		fmt.Fprintf(&b, "pod=%s/%s ", s.Namespace, s.Name)
	}
	if s.Domain != "" {
		fmt.Fprintf(&b, "domain=%s ", s.Domain)
	}
	if s.Dst != "" {
		fmt.Fprintf(&b, "dst=%s ", s.Dst)
	}
	if s.Port != 0 {
		fmt.Fprintf(&b, "port=%d ", s.Port)
	}
	if s.Method != "" || s.Path != "" {
		fmt.Fprintf(&b, "%s %s ", s.Method, s.Path)
	}
	return strings.TrimSpace(b.String())
}

// collectSpecs parses --flow specs, or reads newline-delimited JSON from stdin
// when none are given.
func collectSpecs(flows multiFlag) ([]flowSpec, error) {
	if len(flows) > 0 {
		out := make([]flowSpec, 0, len(flows))
		for _, f := range flows {
			sp, err := parseFlowSpec(f)
			if err != nil {
				return nil, err
			}
			out = append(out, sp)
		}
		return out, nil
	}
	// No --flow: read JSON flows from stdin (unless it's an interactive tty).
	if st, _ := os.Stdin.Stat(); st != nil && st.Mode()&os.ModeCharDevice != 0 {
		return nil, fmt.Errorf("no flows: pass --flow or pipe JSON on stdin")
	}
	var out []flowSpec
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var sp flowSpec
		if err := json.Unmarshal([]byte(line), &sp); err != nil {
			return nil, fmt.Errorf("bad JSON flow %q: %w", line, err)
		}
		out = append(out, sp)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no flows: pass --flow or pipe JSON on stdin")
	}
	return out, nil
}

func parseFlowSpec(s string) (flowSpec, error) {
	var sp flowSpec
	for _, tok := range strings.Fields(s) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			return sp, fmt.Errorf("bad token %q (want key=value)", tok)
		}
		switch {
		case k == "pod":
			if ns, name, found := strings.Cut(v, "/"); found {
				sp.Namespace, sp.Name = ns, name
			} else {
				sp.Name = v
			}
		case k == "namespace" || k == "ns":
			sp.Namespace = v
		case k == "name":
			sp.Name = v
		case k == "uid":
			sp.UID = v
		case k == "dst" || k == "ip":
			sp.Dst = v
		case k == "port":
			n, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return sp, fmt.Errorf("bad port %q: %w", v, err)
			}
			sp.Port = uint16(n)
		case k == "domain" || k == "host" || k == "sni":
			sp.Domain = v
		case k == "method":
			sp.Method = v
		case k == "path":
			sp.Path = v
		case strings.HasPrefix(k, "label."):
			if sp.Labels == nil {
				sp.Labels = map[string]string{}
			}
			sp.Labels[strings.TrimPrefix(k, "label.")] = v
		default:
			return sp, fmt.Errorf("unknown key %q", k)
		}
	}
	return sp, nil
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
