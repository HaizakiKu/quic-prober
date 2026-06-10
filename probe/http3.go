package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type HTTP3Probe struct{}

func (p *HTTP3Probe) Name() string { return "http3" }

func (p *HTTP3Probe) Run(ctx context.Context, target string) Result {
	r := Result{ProbeName: "http3", Target: target}

	var (
		capturedConn quic.EarlyConnection
		connectTime  time.Duration
		connectStart time.Time
		mu           sync.Mutex
	)

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
		Dial: func(dialCtx context.Context, addr string, tc *tls.Config, qc *quic.Config) (quic.EarlyConnection, error) {
			connectStart = time.Now()
			conn, err := quic.DialAddrEarly(dialCtx, addr, tc, qc)
			if err != nil {
				return nil, err
			}
			select {
			case <-conn.HandshakeComplete():
				mu.Lock()
				capturedConn = conn
				connectTime = time.Since(connectStart)
				mu.Unlock()
			case <-dialCtx.Done():
			}
			return conn, nil
		},
	}
	defer transport.Close()

	client := &http.Client{Transport: transport}
	url := "https://" + target + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Err = err
		return r
	}

	reqStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		mu.Lock()
		cc := capturedConn
		ct := connectTime
		mu.Unlock()
		if cc != nil {
			r.Connected = true
			r.ConnectTime = ct
		}
		r.Err = err
		return r
	}
	defer resp.Body.Close()

	mu.Lock()
	r.Connected = true
	r.ConnectTime = connectTime
	mu.Unlock()

	body, _ := io.ReadAll(resp.Body)
	r.ResponseTime = time.Since(reqStart)
	r.GotAppData = true
	r.AppDataSize = len(body)
	r.HTTPStatus = resp.StatusCode

	r.HTTPHeaders = make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			r.HTTPHeaders[k] = v[0]
		}
	}

	return r
}
