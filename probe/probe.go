package probe

import (
	"context"
	"errors"
	"time"

	quic "github.com/quic-go/quic-go"
)

type Probe interface {
	Name() string
	Run(ctx context.Context, target string) Result
}

type Result struct {
	ProbeName string
	Target    string

	Connected   bool
	ConnectTime time.Duration

	GotAppData   bool
	AppDataSize  int
	ResponseTime time.Duration

	ClosedBy       string
	CloseErrorType string
	CloseCode      uint64
	CloseReason    string

	HTTPStatus  int
	HTTPHeaders map[string]string

	TLSVersion  uint16
	CipherSuite uint16
	ALPN        string
	CertSubject string
	CertIssuer  string
	CertExpiry  string
	HasECH      bool

	RawResponse []byte

	Err error
}

func RunWithTimeout(p Probe, target string, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return p.Run(ctx, target)
}

func extractCloseInfo(err error) (closedBy, errorType string, code uint64, reason string) {
	if err == nil {
		return "client", "none", 0, ""
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		if appErr.Remote {
			closedBy = "server"
		} else {
			closedBy = "client"
		}
		return closedBy, "application", uint64(appErr.ErrorCode), appErr.ErrorMessage
	}
	var transErr *quic.TransportError
	if errors.As(err, &transErr) {
		if transErr.Remote {
			closedBy = "server"
		} else {
			closedBy = "client"
		}
		return closedBy, "transport", uint64(transErr.ErrorCode), transErr.ErrorMessage
	}
	var idleErr *quic.IdleTimeoutError
	if errors.As(err, &idleErr) {
		return "timeout", "none", 0, "idle timeout"
	}
	var hsErr *quic.HandshakeTimeoutError
	if errors.As(err, &hsErr) {
		return "timeout", "none", 0, "handshake timeout"
	}
	return "timeout", "none", 0, err.Error()
}
