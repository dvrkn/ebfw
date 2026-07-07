// Command gotls-client is the e2e fixture that exercises ebfw's Go crypto/tls
// uprobe. crypto/tls is linked statically into the binary, so its requests never
// call OpenSSL's SSL_write and are invisible to that uprobe — they are captured
// ONLY via the crypto/tls.(*Conn).Write uprobe. HTTP/1.1 is forced so the
// captured plaintext is a deterministic "GET <path>".
//
// It sleeps briefly before sending so uprobe discovery — which scans /proc on a
// ~1s cadence — can attach to this binary while the process is alive; a client
// that fired immediately could exit before it was ever seen. After the wait it
// issues a single request: that one capture proves host/path/header extraction.
//
// Usage: gotls-client <url> <header-name> <header-value>
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// attachWait must exceed the agent's ~1s uprobe-discovery interval by a margin so
// the probe is guaranteed live before the single request goes out.
const attachWait = 4 * time.Second

func main() {
	url, name, val := os.Args[1], os.Args[2], os.Args[3]
	time.Sleep(attachWait)

	tr := &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set(name, val)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}
