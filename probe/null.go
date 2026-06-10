package probe

import (
	"context"
	"crypto/tls"
	"time"

	quic "github.com/quic-go/quic-go"
)

type NullProbe struct{}

func (p *NullProbe) Name() string { return "null" }

func (p *NullProbe) Run(ctx context.Context, target string) Result {
	r := Result{ProbeName: "null", Target: target}

	start := time.Now()
	conn, err := quic.DialAddr(ctx, target, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}, nil)
	if err != nil {
		r.Err = err
		return r
	}
	defer conn.CloseWithError(0, "")

	r.Connected = true
	r.ConnectTime = time.Since(start)

	stream, err := conn.AcceptStream(ctx)
	if err == nil {
		r.GotAppData = true
		r.ClosedBy = "server"
		stream.CancelRead(0)
		stream.Close()
		return r
	}

	if ctx.Err() != nil {
		r.ClosedBy = "timeout"
		r.CloseErrorType = "none"
	} else {
		r.ClosedBy, r.CloseErrorType, r.CloseCode, r.CloseReason = extractCloseInfo(err)
	}

	return r
}
