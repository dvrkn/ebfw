// Package l7 holds small application-layer parsers shared by the agent.
package l7

import (
	"bufio"
	"bytes"
	"strings"
)

// Header is one HTTP request header.
type Header struct{ Name, Value string }

// Body is a stub for future request-body inspection. Capturing bodies would
// require reading beyond the first packet/segment we copy from the kernel, so it
// is intentionally not implemented yet.
//
// TODO: implement request-body capture (multi-segment reassembly + size cap).
type Body struct{}

// Request is a parsed plaintext HTTP/1.x request.
type Request struct {
	Method  string
	Host    string
	Path    string
	Headers []Header
	Body    Body // stub — not populated; see Body
}

// ParseRequest parses a plaintext HTTP/1.x request: request line, Host, and all
// headers. ok is false for non-requests (including the HTTP/2 "PRI *" preface).
// The body is not parsed (see Body).
func ParseRequest(payload []byte) (*Request, bool) {
	nl := bytes.IndexByte(payload, '\n')
	if nl < 0 {
		return nil, false
	}
	line := strings.TrimRight(string(payload[:nl]), "\r")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return nil, false
	}
	if parts[0] == "PRI" {
		return nil, false // HTTP/2 connection preface, not a request
	}

	r := &Request{Method: parts[0], Path: parts[1]}
	sc := bufio.NewScanner(bytes.NewReader(payload[nl+1:]))
	for sc.Scan() {
		hl := sc.Text()
		if hl == "" {
			break // end of headers (start of body, which we don't parse)
		}
		i := strings.IndexByte(hl, ':')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(hl[:i])
		val := strings.TrimSpace(hl[i+1:])
		r.Headers = append(r.Headers, Header{Name: name, Value: val})
		if strings.EqualFold(name, "Host") {
			r.Host = val
		}
	}
	return r, true
}
