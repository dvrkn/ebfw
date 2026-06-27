// Package sslsnoop captures HTTPS request paths (encrypted on the wire) by
// attaching an SSL_write uprobe and reading the plaintext before encryption. It
// auto-discovers every container's libssl via /proc and attaches per library.
//
// Capture is live: once attached to a library, every SSL_write is reported with
// no sampling. Discovery runs on a short fixed cadence purely to attach to
// newly-appeared containers; a uprobe on a library inode covers all current and
// future processes that map it.
package sslsnoop

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/dvrkn/ebfw/internal/config"
	"github.com/dvrkn/ebfw/internal/l7"
)

const (
	commLen = 16
	// event header in bpf/sslsnoop.bpf.c: pid(4) + data_len(4) + comm(16) + ssl(8)
	hdrLen = 4 + 4 + commLen + 8

	// discoverInterval is how often we scan for newly-appeared container
	// libraries. It does NOT affect request capture (always live once attached).
	discoverInterval = time.Second

	// maxConns bounds the per-connection HTTP/2 state map.
	maxConns = 16384
)

// Run loads the SSL_write uprobe, auto-discovers and attaches to each container's
// libssl, and reports filtered HTTPS requests until ctx is cancelled. The caller
// owns rlimit setup and signal handling.
func Run(ctx context.Context, cfg *config.Config, filter *config.Filter) error {
	var objs sslObjects
	if err := loadSslObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load bpf objects: verifier error:\n%+v", ve)
		}
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	rd, err := ringbuf.NewReader(objs.SslEvents)
	if err != nil {
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	go discoverLoop(ctx, objs.SslWrite)
	log.Printf("ebfw sslsnoop: auto-discovering libssl across the node (live capture)")

	t := newTracker(filter, cfg.Inspect)
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("sslsnoop ringbuf read: %v", err)
			continue
		}
		t.handle(rec.RawSample)
	}
}

type connMode int

const (
	modeUnknown connMode = iota
	modeHTTP1
	modeHTTP2
	modeIgnore
)

type connState struct {
	mode connMode
	h2   *l7.H2Conn
}

// tracker decodes SSL_write events per connection (keyed by the SSL* pointer),
// handling both HTTP/1.x (line-based) and HTTP/2 (frames + HPACK, which is
// stateful across requests on a connection).
type tracker struct {
	conns   map[uint64]*connState
	filter  *config.Filter
	inspect config.Inspection
}

func newTracker(f *config.Filter, in config.Inspection) *tracker {
	return &tracker{conns: map[uint64]*connState{}, filter: f, inspect: in}
}

func (t *tracker) handle(buf []byte) {
	if len(buf) < hdrLen {
		return
	}
	pid := binary.LittleEndian.Uint32(buf[0:4])
	dlen := binary.LittleEndian.Uint32(buf[4:8])
	comm := cstr(buf[8 : 8+commLen])
	ssl := binary.LittleEndian.Uint64(buf[24:32])

	if dlen == 0 || hdrLen+int(dlen) > len(buf) {
		return
	}
	data := buf[hdrLen : hdrLen+int(dlen)]

	c := t.conns[ssl]
	if c == nil {
		if len(t.conns) >= maxConns {
			t.conns = map[uint64]*connState{} // bounded; rare, resets HPACK state
		}
		c = &connState{}
		t.conns[ssl] = c
	}

	switch c.mode {
	case modeUnknown:
		if bytes.HasPrefix(data, []byte(l7.H2Preface)) {
			c.mode = modeHTTP2
			c.h2 = l7.NewH2Conn()
			for _, r := range c.h2.Feed(data) {
				t.emit(pid, comm, r)
			}
		} else if r, ok := l7.ParseRequest(data); ok {
			c.mode = modeHTTP1
			t.emit(pid, comm, r)
		} else {
			c.mode = modeIgnore // not HTTP, or joined mid-stream
		}
	case modeHTTP1:
		if r, ok := l7.ParseRequest(data); ok {
			t.emit(pid, comm, r)
		}
	case modeHTTP2:
		for _, r := range c.h2.Feed(data) {
			t.emit(pid, comm, r)
		}
	case modeIgnore:
	}
}

func (t *tracker) emit(pid uint32, comm string, r *l7.Request) {
	if t.filter.SkipDomain(r.Host) {
		return
	}
	fmt.Printf("HTTPS  [pid=%d %s] %s %s%s\n", pid, comm, r.Method, r.Host, r.Path)
	if t.inspect.Headers {
		l7.PrintHeaders(r.Headers)
	}
}

// discoverLoop attaches an SSL_write uprobe to every unique libssl inode it has
// not yet seen, rescanning on a short fixed cadence to pick up new containers.
func discoverLoop(ctx context.Context, prog *ebpf.Program) {
	attached := map[string]link.Link{}
	failed := map[string]bool{}
	defer func() {
		for _, l := range attached {
			l.Close()
		}
	}()
	tick := time.NewTicker(discoverInterval)
	defer tick.Stop()
	for {
		for key, path := range discoverLibssl() {
			if _, ok := attached[key]; ok {
				continue
			}
			ex, err := link.OpenExecutable(path)
			if err != nil {
				if !failed[key] {
					log.Printf("ebfw sslsnoop: open %s: %v", path, err)
					failed[key] = true
				}
				continue
			}
			up, err := ex.Uprobe("SSL_write", prog, nil)
			if err != nil {
				if !failed[key] {
					log.Printf("ebfw sslsnoop: uprobe %s: %v", path, err)
					failed[key] = true
				}
				continue
			}
			delete(failed, key)
			attached[key] = up
			log.Printf("ebfw sslsnoop: attached SSL_write uprobe via %s [inode %s]", path, key)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// discoverLibssl finds the libssl shared object in every container's root
// filesystem via /proc/<pid>/root and returns "dev:inode" -> path. Dedup by
// mount namespace keeps it to one scan per container; dedup by inode means each
// physical library is attached exactly once.
func discoverLibssl() map[string]string {
	out := map[string]string{}
	seenMnt := map[string]bool{}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		mnt, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
		if err != nil {
			continue
		}
		if seenMnt[mnt] {
			continue
		}
		seenMnt[mnt] = true

		root := fmt.Sprintf("/proc/%d/root", pid)
		for _, cand := range libsslCandidates(root) {
			var st syscall.Stat_t
			if err := syscall.Stat(cand, &st); err != nil {
				continue
			}
			key := fmt.Sprintf("%d:%d", st.Dev, st.Ino)
			if _, ok := out[key]; !ok {
				out[key] = cand
			}
		}
	}
	return out
}

// libsslCandidates returns common libssl paths under a process root directory,
// covering glibc multiarch, musl (Alpine), and lib64 layouts.
func libsslCandidates(root string) []string {
	bases := []string{
		"/usr/lib", "/lib", "/usr/lib64", "/lib64",
		"/usr/lib/aarch64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
		"/lib/aarch64-linux-gnu", "/lib/x86_64-linux-gnu",
	}
	names := []string{"libssl.so.3", "libssl.so.1.1"}
	var c []string
	for _, b := range bases {
		for _, n := range names {
			c = append(c, root+b+"/"+n)
		}
	}
	return c
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
