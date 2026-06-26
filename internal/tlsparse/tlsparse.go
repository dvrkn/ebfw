// Package tlsparse extracts the SNI server name from a TLS ClientHello.
//
// It is a deliberately small, allocation-free walk over the handshake. The
// standard library exposes no public ClientHello parser, and we only need one
// field, so a hand-rolled parser keeps the agent dependency-free.
package tlsparse

import "errors"

var (
	// ErrNotClientHello means the bytes are not a TLS handshake ClientHello.
	ErrNotClientHello = errors.New("tlsparse: not a TLS ClientHello")
	// ErrTruncated means the SNI lies beyond the captured bytes.
	ErrTruncated = errors.New("tlsparse: record truncated before SNI")
	// ErrNoSNI means the ClientHello carried no server_name extension.
	ErrNoSNI = errors.New("tlsparse: no SNI extension")
)

const (
	recordHandshake = 0x16   // TLS record content type: handshake
	hsClientHello   = 0x01   // handshake type: ClientHello
	extServerName   = 0x0000 // extension type: server_name
	sniHostName     = 0x00   // server_name type: host_name
)

// ServerName parses a buffer that begins with the 5-byte TLS record header and
// returns the SNI host name carried in the ClientHello.
func ServerName(b []byte) (string, error) {
	// TLS record header: type(1) version(2) length(2).
	if len(b) < 5 || b[0] != recordHandshake {
		return "", ErrNotClientHello
	}
	p := b[5:]

	// Handshake header: msg_type(1) length(3).
	if len(p) < 4 || p[0] != hsClientHello {
		return "", ErrNotClientHello
	}
	p = p[4:]

	// client_version(2) + random(32).
	if len(p) < 34 {
		return "", ErrTruncated
	}
	p = p[34:]

	// session_id: len(1) + bytes.
	var ok bool
	if p, ok = skip8(p); !ok {
		return "", ErrTruncated
	}
	// cipher_suites: len(2) + bytes.
	if p, ok = skip16(p); !ok {
		return "", ErrTruncated
	}
	// compression_methods: len(1) + bytes.
	if p, ok = skip8(p); !ok {
		return "", ErrTruncated
	}

	// extensions: total_len(2) + extensions.
	if len(p) < 2 {
		return "", ErrNoSNI // no extensions block at all
	}
	extTotal := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) > extTotal {
		p = p[:extTotal]
	}

	for len(p) >= 4 {
		extType := int(p[0])<<8 | int(p[1])
		extLen := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < extLen {
			return "", ErrTruncated
		}
		ext := p[:extLen]
		p = p[extLen:]

		if extType != extServerName {
			continue
		}
		return parseServerNameList(ext)
	}
	return "", ErrNoSNI
}

// parseServerNameList parses a server_name extension body and returns the first
// host_name entry.
func parseServerNameList(ext []byte) (string, error) {
	// server_name_list: list_len(2) + entries.
	if len(ext) < 2 {
		return "", ErrTruncated
	}
	listLen := int(ext[0])<<8 | int(ext[1])
	sn := ext[2:]
	if len(sn) > listLen {
		sn = sn[:listLen]
	}
	for len(sn) >= 3 {
		nameType := sn[0]
		nameLen := int(sn[1])<<8 | int(sn[2])
		sn = sn[3:]
		if len(sn) < nameLen {
			return "", ErrTruncated
		}
		if nameType == sniHostName {
			return string(sn[:nameLen]), nil
		}
		sn = sn[nameLen:]
	}
	return "", ErrNoSNI
}

// skip8 consumes a 1-byte-length-prefixed field.
func skip8(p []byte) ([]byte, bool) {
	if len(p) < 1 {
		return p, false
	}
	n := int(p[0])
	if len(p) < 1+n {
		return p, false
	}
	return p[1+n:], true
}

// skip16 consumes a 2-byte-length-prefixed field.
func skip16(p []byte) ([]byte, bool) {
	if len(p) < 2 {
		return p, false
	}
	n := int(p[0])<<8 | int(p[1])
	if len(p) < 2+n {
		return p, false
	}
	return p[2+n:], true
}
