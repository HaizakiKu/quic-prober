package probe

import (
	"context"
	"crypto/tls"
	"time"

	quic "github.com/quic-go/quic-go"
)

type TLSProbe struct{}

func (p *TLSProbe) Name() string { return "tls" }

func (p *TLSProbe) Run(ctx context.Context, target string) Result {
	r := Result{ProbeName: "tls", Target: target}

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

	state := conn.ConnectionState().TLS
	r.TLSVersion = state.Version
	r.CipherSuite = state.CipherSuite
	r.ALPN = state.NegotiatedProtocol
	r.HasECH = state.ECHAccepted

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		r.CertSubject = cert.Subject.String()
		r.CertIssuer = cert.Issuer.String()
		r.CertExpiry = cert.NotAfter.UTC().Format(time.RFC3339)
	}

	return r
}
