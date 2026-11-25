package controlplane

import (
	"context"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func dialEtcd(ctx context.Context, address string) (net.Conn, error) {
	const failureTimeout = 3 * time.Second
	dialer := net.Dialer{
		Timeout:         failureTimeout,
		KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 2 * time.Second, Interval: time.Second, Count: 3},
		Control: func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			// Bound unacknowledged traffic when a peer disappears without
			// sending a TCP close or a reset, including a powered-off host.
			err := raw.Control(func(fd uintptr) {
				socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(failureTimeout.Milliseconds()))
			})
			if err != nil {
				return err
			}
			return socketErr
		},
	}
	return dialer.DialContext(ctx, "tcp", address)
}
