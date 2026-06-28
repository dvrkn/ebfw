// Package output renders egress events as either human-readable text (default)
// or one JSON object per line. It is the single emit chokepoint for both data
// sources (the egress monitor and the SSL_write uprobe), so it also records the
// per-event Prometheus counters and is safe for concurrent use.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dvrkn/ebfw/internal/attr"
	"github.com/dvrkn/ebfw/internal/l7"
	"github.com/dvrkn/ebfw/internal/metrics"
)

// Kind classifies an event.
type Kind string

const (
	KindDNS     Kind = "dns"
	KindTLS     Kind = "tls"
	KindHTTP    Kind = "http"
	KindHTTPS   Kind = "https"
	KindConnect Kind = "connect"
)

// Event is a single observed egress fact. Fields are populated per kind; Headers
// is set only when header inspection is enabled, and Pod is the zero value when
// the flow could not be attributed to a pod.
type Event struct {
	Kind    Kind
	Src     string // source IP (packet monitor); empty for the uprobe
	Dst     string // destination IP
	Port    int    // destination port
	Domain  string // DNS qname / TLS SNI / HTTP Host
	DNSType string // DNS query type (DNS only)
	Method  string // HTTP(S) method
	Path    string // HTTP(S) request path
	Headers []l7.Header
	PID     int    // SSL_write uprobe
	Comm    string // SSL_write uprobe
	Pod     attr.PodInfo
}

// Sink consumes events. Implementations are safe for concurrent use: the egress
// monitor and the SSL_write uprobe emit from separate goroutines.
type Sink interface {
	Emit(Event)
}

// New returns a Sink for the given format ("json" or anything else => text).
func New(format string) Sink {
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		return &jsonSink{enc: json.NewEncoder(os.Stdout)}
	}
	return &textSink{w: os.Stdout}
}

// record bumps the per-event counters shared by both sinks.
func record(e Event) {
	metrics.EventsTotal.WithLabelValues(string(e.Kind)).Inc()
	result := "miss"
	if e.Pod.Known() {
		result = "hit"
	}
	metrics.AttributionTotal.WithLabelValues(result).Inc()
}

// podSuffix renders the trailing " pod=..." attribution for text output.
func podSuffix(p attr.PodInfo) string {
	if s := p.String(); s != "" {
		return "  pod=" + s
	}
	return ""
}

type textSink struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *textSink) Emit(e Event) {
	record(e)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch e.Kind {
	case KindConnect:
		fmt.Fprintf(s.w, "%-8s %s -> %s:%d%s\n", "CONNECT", e.Src, e.Dst, e.Port, podSuffix(e.Pod))
	case KindDNS:
		fmt.Fprintf(s.w, "%-8s %s ? %s (%s)%s\n", "DNS", e.Src, e.Domain, e.DNSType, podSuffix(e.Pod))
	case KindTLS:
		fmt.Fprintf(s.w, "%-8s %s -> %s  (%s:%d)%s\n", "TLS", e.Src, e.Domain, e.Dst, e.Port, podSuffix(e.Pod))
	case KindHTTP:
		fmt.Fprintf(s.w, "%-8s %s -> %s %s%s%s\n", "HTTP", e.Src, e.Method, e.Domain, e.Path, podSuffix(e.Pod))
	case KindHTTPS:
		fmt.Fprintf(s.w, "HTTPS  [pid=%d %s] %s %s%s%s\n", e.PID, e.Comm, e.Method, e.Domain, e.Path, podSuffix(e.Pod))
	}
	for _, h := range e.Headers {
		fmt.Fprintf(s.w, "           %s: %s\n", h.Name, h.Value)
	}
}

type jsonSink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

type jsonHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type jsonPod struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	UID       string `json:"uid,omitempty"`
	Container string `json:"container,omitempty"`
	QoS       string `json:"qos,omitempty"`
	Node      string `json:"node,omitempty"`
}

type jsonEvent struct {
	TS      string       `json:"ts"`
	Kind    Kind         `json:"kind"`
	Src     string       `json:"src,omitempty"`
	Dst     string       `json:"dst,omitempty"`
	Port    int          `json:"port,omitempty"`
	Domain  string       `json:"domain,omitempty"`
	DNSType string       `json:"dns_type,omitempty"`
	Method  string       `json:"method,omitempty"`
	Path    string       `json:"path,omitempty"`
	Headers []jsonHeader `json:"headers,omitempty"`
	PID     int          `json:"pid,omitempty"`
	Comm    string       `json:"comm,omitempty"`
	Pod     *jsonPod     `json:"pod,omitempty"`
}

func (s *jsonSink) Emit(e Event) {
	record(e)
	je := jsonEvent{
		TS:      time.Now().UTC().Format(time.RFC3339Nano),
		Kind:    e.Kind,
		Src:     e.Src,
		Dst:     e.Dst,
		Port:    e.Port,
		Domain:  e.Domain,
		DNSType: e.DNSType,
		Method:  e.Method,
		Path:    e.Path,
		PID:     e.PID,
		Comm:    e.Comm,
	}
	for _, h := range e.Headers {
		je.Headers = append(je.Headers, jsonHeader{Name: h.Name, Value: h.Value})
	}
	if e.Pod.Known() {
		je.Pod = &jsonPod{
			Namespace: e.Pod.Namespace,
			Name:      e.Pod.Name,
			UID:       e.Pod.UID,
			Container: e.Pod.Container,
			QoS:       e.Pod.QoS,
			Node:      e.Pod.Node,
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(&je) // Encode appends a newline; stdout errors are non-fatal
}
