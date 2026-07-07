// Command gotls-client is the e2e fixture that exercises ebfw's Go crypto/tls
// uprobe. crypto/tls is linked statically into the binary, so its requests never
// call OpenSSL's SSL_write and are invisible to that uprobe — they are captured
// ONLY via the crypto/tls.(*Conn).Write uprobe. HTTP/1.1 is forced so the
// captured plaintext is a deterministic "GET <path>".
//
// It loops, issuing a request every second, because uprobe discovery scans /proc
// on a ~1s cadence: a one-shot process can exit before it is ever seen. Looping
// guarantees requests keep firing after the uprobe attaches to this binary.
//
// Usage: gotls-client <url> <header-name> <header-value>
package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	url, name, val := os.Args[1], os.Args[2], os.Args[3]
	tr := &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	client := &http.Client{Transport: tr}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(name, val)
		if resp, err := client.Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
}
