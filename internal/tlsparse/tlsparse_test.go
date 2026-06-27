package tlsparse

import (
	"errors"
	"testing"
)

// clientHello builds a minimal but well-formed TLS ClientHello record carrying
// a single server_name (host_name) extension.
func clientHello(sni string) []byte {
	name := []byte(sni)

	entry := []byte{0x00} // host_name
	entry = append(entry, byte(len(name)>>8), byte(len(name)))
	entry = append(entry, name...)

	snList := []byte{byte(len(entry) >> 8), byte(len(entry))}
	snList = append(snList, entry...)

	ext := []byte{0x00, 0x00} // extension type: server_name
	ext = append(ext, byte(len(snList)>>8), byte(len(snList)))
	ext = append(ext, snList...)

	exts := []byte{byte(len(ext) >> 8), byte(len(ext))}
	exts = append(exts, ext...)

	hs := []byte{0x03, 0x03}                // client_version TLS 1.2
	hs = append(hs, make([]byte, 32)...)    // random
	hs = append(hs, 0x00)                   // session_id length
	hs = append(hs, 0x00, 0x02, 0x00, 0x2f) // cipher_suites
	hs = append(hs, 0x01, 0x00)             // compression methods
	hs = append(hs, exts...)                // extensions

	handshake := []byte{0x01} // ClientHello
	handshake = append(handshake, byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)))
	handshake = append(handshake, hs...)

	record := []byte{0x16, 0x03, 0x01} // handshake record, TLS 1.0 record version
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}

func TestServerName(t *testing.T) {
	const want = "example.com"
	got, err := ServerName(clientHello(want))
	if err != nil {
		t.Fatalf("ServerName: unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("ServerName = %q, want %q", got, want)
	}
}

func TestServerNameTruncated(t *testing.T) {
	full := clientHello("example.com")
	if _, err := ServerName(full[:len(full)-4]); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated record: got err %v, want ErrTruncated", err)
	}
}

func TestServerNameNotClientHello(t *testing.T) {
	if _, err := ServerName([]byte{0x17, 0x03, 0x03, 0x00, 0x00}); !errors.Is(err, ErrNotClientHello) {
		t.Fatalf("non-handshake record: got err %v, want ErrNotClientHello", err)
	}
}
