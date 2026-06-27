package l7

import "golang.org/x/net/http2/hpack"

// H2Preface is the HTTP/2 client connection preface that opens every h2 stream.
const H2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	h2FrameHeaders = 0x1  // HEADERS frame type
	h2FlagEndHdrs  = 0x4  // END_HEADERS
	h2FlagPadded   = 0x8  // PADDED
	h2FlagPriority = 0x20 // PRIORITY
)

// H2Conn decodes HTTP/2 requests from one connection's client->server byte
// stream (as seen via SSL_write). It keeps a persistent HPACK decoder because
// the dynamic table is stateful across frames, and buffers across writes since a
// frame may be split over multiple SSL_write calls.
type H2Conn struct {
	buf     []byte
	dec     *hpack.Decoder
	preface bool
}

// NewH2Conn returns an H2Conn ready to Feed.
func NewH2Conn() *H2Conn {
	return &H2Conn{dec: hpack.NewDecoder(4096, nil)}
}

// Feed appends plaintext bytes and returns any complete requests parsed from
// HEADERS frames that became available.
func (c *H2Conn) Feed(data []byte) []*Request {
	c.buf = append(c.buf, data...)

	if !c.preface {
		if len(c.buf) < len(H2Preface) {
			return nil
		}
		if string(c.buf[:len(H2Preface)]) == H2Preface {
			c.buf = c.buf[len(H2Preface):]
		}
		c.preface = true
	}

	var reqs []*Request
	for len(c.buf) >= 9 {
		length := int(c.buf[0])<<16 | int(c.buf[1])<<8 | int(c.buf[2])
		ftype := c.buf[3]
		flags := c.buf[4]
		if len(c.buf) < 9+length {
			break // wait for the rest of the frame
		}
		payload := c.buf[9 : 9+length]
		c.buf = c.buf[9+length:]

		if ftype == h2FrameHeaders && flags&h2FlagEndHdrs != 0 {
			if r := c.parseHeaders(payload, flags); r != nil {
				reqs = append(reqs, r)
			}
		}
		// Other frame types (SETTINGS, WINDOW_UPDATE, DATA, ...) are skipped;
		// the HPACK decoder only needs HEADERS blocks, fed in order.
	}
	return reqs
}

func (c *H2Conn) parseHeaders(payload []byte, flags byte) *Request {
	block := payload
	if flags&h2FlagPadded != 0 {
		if len(block) < 1 {
			return nil
		}
		pad := int(block[0])
		block = block[1:]
		if pad > len(block) {
			return nil
		}
		block = block[:len(block)-pad]
	}
	if flags&h2FlagPriority != 0 {
		if len(block) < 5 {
			return nil
		}
		block = block[5:]
	}

	fields, err := c.dec.DecodeFull(block)
	if err != nil {
		return nil
	}
	r := &Request{}
	for _, f := range fields {
		switch f.Name {
		case ":method":
			r.Method = f.Value
		case ":path":
			r.Path = f.Value
		case ":authority":
			r.Host = f.Value
		case ":scheme":
			// ignored
		default:
			if f.Name == "host" && r.Host == "" {
				r.Host = f.Value
			}
			r.Headers = append(r.Headers, Header{Name: f.Name, Value: f.Value})
		}
	}
	if r.Method == "" || r.Path == "" {
		return nil
	}
	return r
}
