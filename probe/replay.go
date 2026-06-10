package probe

import (
	"context"
	"net"
	"time"

	"github.com/HaizakiKu/quic-prober/samples"
)

type ReplayProbe struct{}

func (p *ReplayProbe) Name() string { return "replay" }

func (p *ReplayProbe) Run(ctx context.Context, target string) Result {
	r := Result{ProbeName: "replay", Target: target}

	pkt := samples.ChromeInitial()
	if len(pkt) == 0 {
		r.Err = &replayErr{"no sample packet available"}
		return r
	}

	conn, err := net.Dial("udp", target)
	if err != nil {
		r.Err = err
		return r
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	start := time.Now()
	if _, err = conn.Write(pkt); err != nil {
		r.Err = err
		return r
	}

	buf := make([]byte, 4096)
	n, readErr := conn.Read(buf)
	r.ResponseTime = time.Since(start)

	if n > 0 {
		r.GotAppData = true
		r.AppDataSize = n
		r.RawResponse = append([]byte(nil), buf[:n]...)
	}

	if readErr != nil && !isTimeoutError(readErr) {
		r.Err = readErr
	}

	return r
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

type replayErr struct{ msg string }

func (e *replayErr) Error() string { return e.msg }
