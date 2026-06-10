package probe

import (
	"context"
	"crypto/rand"
	"net"
	"time"
)

var DefaultRandomSizes = []int{1, 8, 16, 32, 64, 128, 256, 512, 1024, 1400, 1500}

type RandomProbe struct {
	Sizes []int
}

func (p *RandomProbe) Name() string { return "random" }

func (p *RandomProbe) Run(ctx context.Context, target string) Result {
	r := Result{ProbeName: "random", Target: target}

	sizes := p.Sizes
	if len(sizes) == 0 {
		sizes = DefaultRandomSizes
	}

	for _, size := range sizes {
		select {
		case <-ctx.Done():
			return r
		default:
		}

		buf := make([]byte, size)
		rand.Read(buf)

		conn, err := net.Dial("udp", target)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write(buf)

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
