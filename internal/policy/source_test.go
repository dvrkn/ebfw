package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmptySource(t *testing.T) {
	s := EmptySource()
	p := s.Snapshot()
	if p == nil {
		t.Fatal("Snapshot returned nil")
	}
	if p.DefaultAction != PostureAllow {
		t.Errorf("default posture = %s, want Allow", p.DefaultAction)
	}
	if v, _ := NewEngine(p); v.Evaluate(Flow{Domain: "anything.com"}).Action != ActionAllow {
		t.Error("empty source must allow everything")
	}
}

func TestFileSourceLoad(t *testing.T) {
	const doc = `
defaultAction: Deny
rules:
  - name: allow-github
    action: Allow
    match:
      domains: ["github.com", "*.githubusercontent.com"]
      ports: [443]
  - name: block-smtp
    action: Deny
    match:
      ports: [25]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := NewFileSource(path)
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	p := s.Snapshot()
	if p.DefaultAction != PostureDeny {
		t.Errorf("default = %s, want Deny", p.DefaultAction)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(p.Rules))
	}

	eng, err := NewEngine(p)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if v := eng.Evaluate(Flow{Domain: "raw.githubusercontent.com", Port: 443}); v.Action != ActionAllow {
		t.Errorf("github subdomain on 443: got %s, want Allow", v.Action)
	}
	if v := eng.Evaluate(Flow{Domain: "github.com", Port: 80}); v.Action != ActionDeny {
		t.Errorf("github on wrong port: got %s, want Deny (allowlist default)", v.Action)
	}
}

func TestFileSourceErrors(t *testing.T) {
	if _, err := NewFileSource(""); err == nil {
		t.Error("empty path should error")
	}
	if _, err := NewFileSource(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file should error")
	}

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("rules:\n  - action: Drop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSource(bad); err == nil {
		t.Error("invalid policy should error at load")
	}
}
