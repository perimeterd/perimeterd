package app

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	notifyExtendInterval   = 20 * time.Second
	notifyMaximumExtension = 60 * time.Second
)

// notifyFunc is the narrow notification boundary used by the runtime. Tests
// inject it through Options.Notify; production uses the NOTIFY_SOCKET protocol.
type notifyFunc func(string) error

// startupNotifier keeps systemd's startup deadline alive without sharing the
// serialized engine writer. A failed delivery is retained and returned by
// Stop, so notification failures cannot be mistaken for readiness.
type startupNotifier struct {
	fn       notifyFunc
	deadline time.Time
	stop     chan struct{}
	done     chan struct{}
	errMu    sync.Mutex
	err      error
	once     sync.Once
}

func newStartupNotifier(fn notifyFunc, deadline time.Time) *startupNotifier {
	if fn == nil {
		fn = func(string) error { return nil }
	}
	n := &startupNotifier{
		fn:       fn,
		deadline: deadline,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go n.run()
	return n
}

func (n *startupNotifier) run() {
	defer close(n.done)
	n.sendExtension("starting")
	ticker := time.NewTicker(notifyExtendInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.sendExtension("starting")
		case <-n.stop:
			return
		}
	}
}

func (n *startupNotifier) sendExtension(status string) {
	remaining := time.Until(n.deadline)
	if remaining <= 0 {
		return
	}
	if remaining > notifyMaximumExtension {
		remaining = notifyMaximumExtension
	}
	// EXTEND_TIMEOUT_USEC is an integer number of microseconds. Round down so
	// the advertised extension never exceeds the actual startup deadline.
	message := fmt.Sprintf("EXTEND_TIMEOUT_USEC=%d\nSTATUS=%s", remaining.Microseconds(), status)
	if err := n.fn(message); err != nil {
		n.errMu.Lock()
		if n.err == nil {
			n.err = fmt.Errorf("systemd notification: %w", err)
		}
		n.errMu.Unlock()
	}
}

// Stop ends startup extensions and returns the first notification error, if
// any. It is safe to call more than once.
func (n *startupNotifier) Stop() error {
	n.once.Do(func() { close(n.stop) })
	<-n.done
	n.errMu.Lock()
	defer n.errMu.Unlock()
	return n.err
}

// systemdNotify returns a function implementing systemd's AF_UNIX datagram
// notification protocol. An unset NOTIFY_SOCKET intentionally means direct
// foreground operation and is a successful no-op.
func systemdNotify() notifyFunc {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return func(string) error { return nil }
	}
	return func(message string) error {
		if message == "" {
			return nil
		}
		path := address
		if strings.HasPrefix(path, "@") {
			path = "\x00" + path[1:]
		}
		unixAddress := &net.UnixAddr{Name: path, Net: "unixgram"}
		conn, err := net.DialUnix("unixgram", nil, unixAddress)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, err = conn.Write([]byte(message))
		return err
	}
}
