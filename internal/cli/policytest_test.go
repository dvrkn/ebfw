package cli

import "testing"

func TestParseFlowSpec(t *testing.T) {
	sp, err := parseFlowSpec("pod=team-a/web dst=1.2.3.4 port=443 domain=api.github.com method=GET path=/x label.app=web")
	if err != nil {
		t.Fatalf("parseFlowSpec: %v", err)
	}
	if sp.Namespace != "team-a" || sp.Name != "web" {
		t.Errorf("pod = %s/%s, want team-a/web", sp.Namespace, sp.Name)
	}
	if sp.Dst != "1.2.3.4" || sp.Port != 443 || sp.Domain != "api.github.com" {
		t.Errorf("dst/port/domain = %s/%d/%s", sp.Dst, sp.Port, sp.Domain)
	}
	if sp.Method != "GET" || sp.Path != "/x" {
		t.Errorf("method/path = %s/%s", sp.Method, sp.Path)
	}
	if sp.Labels["app"] != "web" {
		t.Errorf("label app = %q, want web", sp.Labels["app"])
	}
}

func TestParseFlowSpecErrors(t *testing.T) {
	for _, s := range []string{"justaword", "port=notanumber", "bogus=1"} {
		if _, err := parseFlowSpec(s); err == nil {
			t.Errorf("parseFlowSpec(%q) = nil err, want error", s)
		}
	}
}

// TestExamplePolicyEvaluates exercises the shipped example policy end-to-end
// through the test subcommand: it must load, validate, and evaluate flows.
func TestExamplePolicyEvaluates(t *testing.T) {
	const policyPath = "../../examples/policy.yaml"
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"allowed github", []string{"test", "--policy", policyPath, "--flow", "domain=api.github.com port=443"}, 0},
		{"denied default", []string{"test", "--policy", policyPath, "--flow", "domain=evil.com port=443"}, 0},
		{"missing policy flag", []string{"test"}, 2},
		{"bad policy path", []string{"test", "--policy", "/no/such/file.yaml", "--flow", "domain=x"}, 1},
		{"unknown subcommand", []string{"frobnicate"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PolicyMain(tc.args); got != tc.code {
				t.Errorf("PolicyMain(%v) = %d, want %d", tc.args, got, tc.code)
			}
		})
	}
}
