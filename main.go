// Command ebfw is a node-level egress monitor (Stage-0 PoC).
//
// It loads a cgroup_skb/egress eBPF program, attaches it at the node's root
// cgroup v2 (so it sees every pod's egress traffic), and prints the outgoing
// domains (DNS queries and TLS SNI), HTTP request paths, and new TCP
// connection destinations it observes. Observe-only: nothing is blocked.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/dvrkn/ebfw/internal/tlsparse"
)

// Event kinds — must match bpf/egress.bpf.c.
const (
	evtConnect = 1
	evtDNS     = 2
	evtTLS     = 3
	evtHTTP    = 4
)

// Fixed header of struct event in bpf/egress.bpf.c (payload follows at offset 20).
const hdrLen = 20

func main() {
	cgroupPath := flag.String("cgroup", envOr("EBFW_CGROUP", "/sys/fs/cgroup"),
		"path to the cgroup v2 root to attach the egress program to")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock rlimit: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("load bpf objects: verifier error:\n%+v", ve)
		}
		log.Fatalf("load bpf objects: %v", err)
	}
	defer objs.Close()

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.Egress,
	})
	if err != nil {
		log.Fatalf("attach cgroup egress at %s: %v", *cgroupPath, err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf reader: %v", err)
	}
	defer rd.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		rd.Close() // unblocks rd.Read()
	}()

	log.Printf("ebfw: monitoring egress on cgroup %s (Ctrl-C to stop)", *cgroupPath)

	seen := make(map[string]struct{})
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("ebfw: detached, exiting")
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}
		handleEvent(rec.RawSample, seen)
	}
}

// handleEvent decodes one ring-buffer record and prints a line for it.
func handleEvent(raw []byte, seen map[string]struct{}) {
	if len(raw) < hdrLen {
		return
	}
	evtType := raw[0]
	src := net.IP(raw[4:8]).String()
	dst := net.IP(raw[8:12]).String()
	dport := binary.BigEndian.Uint16(raw[14:16])
	plen := binary.LittleEndian.Uint32(raw[16:20])

	var payload []byte
	if plen > 0 && hdrLen+int(plen) <= len(raw) {
		payload = raw[hdrLen : hdrLen+int(plen)]
	}

	switch evtType {
	case evtConnect:
		key := "c|" + src + "|" + dst + "|" + fmt.Sprint(dport)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		fmt.Printf("%-8s %s -> %s:%d\n", "CONNECT", src, dst, dport)

	case evtDNS:
		for _, q := range dnsQuestions(payload) {
			fmt.Printf("%-8s %s ? %s\n", "DNS", src, q)
		}

	case evtTLS:
		if sni, err := tlsparse.ServerName(payload); err == nil {
			fmt.Printf("%-8s %s -> %s  (%s:%d)\n", "TLS", src, sni, dst, dport)
		}

	case evtHTTP:
		if reqline, ok := httpRequest(payload); ok {
			fmt.Printf("%-8s %s -> %s\n", "HTTP", src, reqline)
		}
	}
}

// dnsQuestions returns the question names ("example.com (A)") from a DNS message.
func dnsQuestions(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}
	var p dnsmessage.Parser
	if _, err := p.Start(payload); err != nil {
		return nil
	}
	var out []string
	for {
		q, err := p.Question()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			break
		}
		name := strings.TrimSuffix(q.Name.String(), ".")
		out = append(out, fmt.Sprintf("%s (%s)", name, q.Type.String()))
	}
	return out
}

// httpRequest extracts "METHOD host+path" from a plaintext HTTP request.
func httpRequest(payload []byte) (string, bool) {
	nl := bytes.IndexByte(payload, '\n')
	if nl < 0 {
		return "", false
	}
	line := strings.TrimRight(string(payload[:nl]), "\r")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return "", false
	}
	method, path := parts[0], parts[1]

	host := ""
	sc := bufio.NewScanner(bytes.NewReader(payload[nl+1:]))
	for sc.Scan() {
		hl := sc.Text()
		if hl == "" {
			break // end of headers
		}
		if len(hl) >= 5 && strings.EqualFold(hl[:5], "Host:") {
			host = strings.TrimSpace(hl[5:])
			break
		}
	}
	return fmt.Sprintf("%s %s%s", method, host, path), true
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
