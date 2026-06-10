package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

func CheckConnectivity(target string, timeout time.Duration) error {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", target, err)
	}

	if _, err := net.LookupHost(host); err != nil {
		return fmt.Errorf("DNS: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, target, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}, nil)
	if err != nil {
		var tErr *quic.TransportError
		var aErr *quic.ApplicationError
		if errors.As(err, &tErr) || errors.As(err, &aErr) {
			return nil
		}
		return fmt.Errorf("%s is unreachable (timed out or no route)", target)
	}
	conn.CloseWithError(0, "")
	return nil
}
