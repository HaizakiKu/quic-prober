package probe

import (
	"context"
	"crypto/rand"
	"net"
	"time"

	"github.com/HaizakiKu/quic-prober/samples"
)

type MalformedProbe struct{}

func (p *MalformedProbe) Name() string { return "malformed" }

type malformedVariant struct {
	name  string
	build func() []byte
}

var malformedVariants = []malformedVariant{
	{"truncated_initial", buildTruncatedInitial},
	{"wrong_version", buildWrongVersionInitial},
	{"empty_connection_ids", buildEmptyConnectionIDs},
	{"bad_crypto_length", buildBadCryptoLength},
	{"single_byte", buildSingleByte},
}

func (p *MalformedProbe) Run(ctx context.Context, target string) Result {
	r := Result{ProbeName: "malformed", Target: target}

	for _, v := range malformedVariants {
		select {
		case <-ctx.Done():
			return r
		default:
		}

		pkt := v.build()
		if len(pkt) == 0 {
			continue
		}

		conn, err := net.Dial("udp", target)
		if err != nil {
			continue
		}

		if dl, ok := ctx.Deadline(); ok {
			conn.SetDeadline(dl)
		} else {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
		}

		conn.Write(pkt)

		resp := make([]byte, 4096)
		n, _ := conn.Read(resp)
		conn.Close()

		if n > 0 {
			r.GotAppData = true
			r.AppDataSize += n
			r.RawResponse = append(r.RawResponse, resp[:n]...)
		}

		select {
		case <-ctx.Done():
			return r
		case <-time.After(200 * time.Millisecond):
		}
	}

	return r
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func buildTruncatedInitial() []byte {
	b := []byte{0xC0, 0x00, 0x00, 0x00, 0x01}
	b = append(b, randomBytes(5)...)
	return b
}

func buildWrongVersionInitial() []byte {
	orig := samples.ChromeInitial()
	if len(orig) < 5 {
		return nil
	}
	pkt := make([]byte, len(orig))
	copy(pkt, orig)
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	pkt[4] = 0x02
	return pkt
}

func buildEmptyConnectionIDs() []byte {
	return []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}
}

func buildBadCryptoLength() []byte {
	b := []byte{
		0xC0, 0x00, 0x00, 0x00, 0x01, // long header, version 1
		0x08,                                     // DCID len = 8
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DCID
		0x00,       // SCID len = 0
		0x00,       // token len = 0
		0x40, 0x1e, // length varint = 30
		0x00, 0x00, 0x00, 0x00, // PN = 0
		0x06,       // CRYPTO frame type
		0x00,       // offset = 0
		0x00, 0x00, // length = 0 (but payload follows)
	}
	b = append(b, randomBytes(20)...)
	return b
}

func buildSingleByte() []byte {
	return []byte{0x00}
}
