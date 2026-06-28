package policy

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// reloadInterval is how often the file source re-stats the policy file. A
// Kubernetes ConfigMap update is eventually-consistent (the projected file is
// swapped within ~a minute), so polling is sufficient and avoids an fsnotify
// dependency.
const reloadInterval = 2 * time.Second

// fileSource reads a YAML Policy from disk and watches it for changes. A reload
// that fails to parse or validate is logged and ignored — the last good policy
// stays in effect.
type fileSource struct {
	path string

	mu  sync.RWMutex
	cur *Policy

	subMu sync.Mutex
	subs  []chan *Policy
}

// NewFileSource loads and validates the policy at path, then starts watching it
// for hot-reload. It fails only if the initial load is unreadable/invalid, so a
// misconfigured policy is surfaced at startup rather than silently ignored.
func NewFileSource(path string) (PolicySource, error) {
	if path == "" {
		return nil, fmt.Errorf("no policy path configured")
	}
	p, err := loadPolicyFile(path)
	if err != nil {
		return nil, err
	}
	fs := &fileSource{path: path, cur: p}
	go fs.watch()
	return fs, nil
}

// LoadFile reads and validates a policy YAML file without watching it, for
// one-shot tooling such as `ebfw policy test`.
func LoadFile(path string) (*Policy, error) { return loadPolicyFile(path) }

func loadPolicyFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy %s: %w", path, err)
	}
	return &p, nil
}

func (fs *fileSource) Snapshot() *Policy {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.cur
}

func (fs *fileSource) Subscribe() <-chan *Policy {
	ch := make(chan *Policy, 1)
	fs.subMu.Lock()
	fs.subs = append(fs.subs, ch)
	fs.subMu.Unlock()
	return ch
}

func (fs *fileSource) watch() {
	last := modTime(fs.path)
	t := time.NewTicker(reloadInterval)
	defer t.Stop()
	for range t.C {
		mt := modTime(fs.path)
		if !mt.After(last) {
			continue
		}
		last = mt
		p, err := loadPolicyFile(fs.path)
		if err != nil {
			log.Printf("ebfw policy: reload failed, keeping previous: %v", err)
			continue
		}
		fs.mu.Lock()
		fs.cur = p
		fs.mu.Unlock()
		fs.broadcast(p)
		log.Printf("ebfw policy: reloaded %s (%d rules, default %s)", fs.path, len(p.Rules), p.EffectiveDefault())
	}
}

func (fs *fileSource) broadcast(p *Policy) {
	fs.subMu.Lock()
	defer fs.subMu.Unlock()
	for _, ch := range fs.subs {
		// Lossy on purpose: drop the latest into a full channel slot.
		select {
		case ch <- p:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- p:
			default:
			}
		}
	}
}

func modTime(path string) time.Time {
	if st, err := os.Stat(path); err == nil {
		return st.ModTime()
	}
	return time.Time{}
}
