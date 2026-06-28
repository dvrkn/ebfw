package enforce

import (
	"net"
	"testing"
	"unsafe"

	"golang.org/x/net/dns/dnsmessage"
)

// buildDNSResponse builds a DNS response for qname. When cname is set, the A
// records are owned by the CNAME target (so the test exercises that parseAnswers
// keys off the question name, not the answer owner).
func buildDNSResponse(t *testing.T, qname, cname string, ips []string, ttl uint32) []byte {
	t.Helper()
	name := dnsmessage.MustNewName(qname + ".")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	owner := name
	if cname != "" {
		cn := dnsmessage.MustNewName(cname + ".")
		if err := b.CNAMEResource(
			dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: ttl},
			dnsmessage.CNAMEResource{CNAME: cn}); err != nil {
			t.Fatal(err)
		}
		owner = cn
	}
	for _, ip := range ips {
		var a [4]byte
		copy(a[:], net.ParseIP(ip).To4())
		if err := b.AResource(
			dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: ttl},
			dnsmessage.AResource{A: a}); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestParseAnswers(t *testing.T) {
	msg := buildDNSResponse(t, "api.github.com", "github.map.fastly.net", []string{"1.2.3.4", "5.6.7.8"}, 120)

	qname, ips, ttl := parseAnswers(msg)
	if qname != "api.github.com" {
		t.Errorf("qname = %q, want api.github.com (the question, not the CNAME target)", qname)
	}
	if len(ips) != 2 || !ips[0].Equal(net.ParseIP("1.2.3.4")) || !ips[1].Equal(net.ParseIP("5.6.7.8")) {
		t.Errorf("ips = %v, want [1.2.3.4 5.6.7.8]", ips)
	}
	if ttl != 120 {
		t.Errorf("ttl = %d, want 120", ttl)
	}
}

func TestParseAnswersNoA(t *testing.T) {
	// AAAA-only / empty answers must not yield IPs.
	msg := buildDNSResponse(t, "ipv6.example.com", "", nil, 60)
	if _, ips, _ := parseAnswers(msg); len(ips) != 0 {
		t.Errorf("expected no A records, got %v", ips)
	}
	if _, _, _ = parseAnswers([]byte{0x00, 0x01}); false {
		t.Fatal("unreachable")
	}
	// Malformed payload must not panic.
	parseAnswers([]byte{0xff, 0xff, 0xff})
}

// TestVerdictKeyLayout guards the hand-mirrored struct against drift from the
// 16-byte C verdict_key.
func TestVerdictKeyLayout(t *testing.T) {
	if got := unsafe.Sizeof(verdictKey{}); got != 16 {
		t.Fatalf("sizeof(verdictKey) = %d, want 16 (must match struct verdict_key)", got)
	}
}
