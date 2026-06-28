package egress

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildEvent assembles a raw ringbuf sample matching struct event in
// bpf/egress.bpf.c. It mirrors the BPF side's "always 16-byte address" layout:
// the raw on-wire address bytes (4 for IPv4, 16 for IPv6) are written at the
// start of each 16-byte slot and ip_version tells the decoder how many are
// meaningful. Pass src/dst as the raw network bytes (To4() for IPv4, the 16-byte
// form for IPv6) — NOT the v4-in-v6 ::ffff: form, which the kernel never emits.
func buildEvent(evtType, ipVersion byte, src, dst net.IP, dport uint16, plen uint32, cgroupID uint64) []byte {
	raw := make([]byte, hdrLen)
	raw[0] = evtType
	raw[1] = ipVersion
	copy(raw[4:20], src)
	copy(raw[20:36], dst)
	binary.BigEndian.PutUint16(raw[38:40], dport)
	binary.LittleEndian.PutUint32(raw[40:44], plen)
	binary.LittleEndian.PutUint64(raw[48:56], cgroupID)
	return raw
}

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name      string
		ipVersion byte
		src, dst  net.IP
		wantSrc   string
		wantDst   string
	}{
		{
			name:      "ipv4",
			ipVersion: 4,
			src:       net.IPv4(10, 1, 2, 3).To4(),
			dst:       net.IPv4(93, 184, 216, 34).To4(),
			wantSrc:   "10.1.2.3",
			wantDst:   "93.184.216.34",
		},
		{
			name:      "ipv6",
			ipVersion: 6,
			src:       net.ParseIP("2001:db8::1"),
			dst:       net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
			wantSrc:   "2001:db8::1",
			wantDst:   "2606:2800:220:1:248:1893:25c8:1946",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				dport    = 443
				plen     = 128
				cgroupID = 0xdeadbeefcafe
			)
			raw := buildEvent(evtTLS, tt.ipVersion, tt.src, tt.dst, dport, plen, cgroupID)
			h, ok := parseHeader(raw)
			if !ok {
				t.Fatal("parseHeader returned ok=false for full-length event")
			}
			if h.evtType != evtTLS {
				t.Errorf("evtType = %d, want %d", h.evtType, evtTLS)
			}
			if got := h.src.String(); got != tt.wantSrc {
				t.Errorf("src = %q, want %q", got, tt.wantSrc)
			}
			if got := h.dst.String(); got != tt.wantDst {
				t.Errorf("dst = %q, want %q", got, tt.wantDst)
			}
			if h.dport != dport {
				t.Errorf("dport = %d, want %d", h.dport, dport)
			}
			if h.plen != plen {
				t.Errorf("plen = %d, want %d", h.plen, plen)
			}
			if h.cgroupID != cgroupID {
				t.Errorf("cgroupID = %#x, want %#x", h.cgroupID, cgroupID)
			}
		})
	}
}

// An IPv4 event must not leak the trailing 12 zero bytes of its 16-byte address
// slot into the parsed address (which would render as a v4-in-v6 form).
func TestParseHeaderIPv4AddressLength(t *testing.T) {
	raw := buildEvent(evtConnect, 4, net.IPv4(192, 0, 2, 9).To4(), net.IPv4(198, 51, 100, 7).To4(), 80, 0, 1)
	h, ok := parseHeader(raw)
	if !ok {
		t.Fatal("parseHeader ok=false")
	}
	if len(h.src) != 4 || len(h.dst) != 4 {
		t.Fatalf("ipv4 addresses should decode to 4 bytes, got src=%d dst=%d", len(h.src), len(h.dst))
	}
	if h.src.String() != "192.0.2.9" || h.dst.String() != "198.51.100.7" {
		t.Errorf("src=%q dst=%q, want 192.0.2.9 / 198.51.100.7", h.src, h.dst)
	}
}

func TestParseHeaderShort(t *testing.T) {
	if _, ok := parseHeader(make([]byte, hdrLen-1)); ok {
		t.Error("parseHeader should reject a sample shorter than hdrLen")
	}
}
