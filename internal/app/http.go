package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	metricspkg "github.com/perimeterd/perimeterd/internal/metrics"
)

// metricsServer owns a staged metrics listener. Binding is performed before a
// firewall commit; serving and promotion happen only after that commit.
type metricsServer struct {
	listen         string
	ln             net.Listener
	server         *http.Server
	errCh          chan error
	crowdConnected func() bool
}

func bindMetrics(listen string, health func() bool, snapshotTimestamps func() sourceTimestamps) (*metricsServer, error) {
	return bindMetricsWithCollector(listen, health, snapshotTimestamps, metricspkg.New("dev", "unknown", "unknown"))
}

func bindMetricsWithCollector(listen string, health func() bool, snapshotTimestamps func() sourceTimestamps, collector *metricspkg.Collector) (*metricsServer, error) {
	if listen == "" {
		return nil, nil
	}
	if health == nil {
		return nil, fmt.Errorf("metrics health state is nil")
	}
	ln, err := net.Listen("tcp", listen) // #nosec G102 -- the endpoint is explicit operator configuration.
	if err != nil {
		return nil, fmt.Errorf("bind metrics %q: %w", listen, err)
	}
	if collector == nil {
		collector = metricspkg.New("dev", "unknown", "unknown")
	}
	var metrics *metricsServer
	var timestamps func() metricspkg.PrefixTimestamps
	if snapshotTimestamps != nil {
		timestamps = func() metricspkg.PrefixTimestamps {
			value := snapshotTimestamps()
			return metricspkg.PrefixTimestamps{RIPestat: value.ripe, IPList: value.ipList, Provider: value.provider}
		}
	}
	handler := collector.Handler(health, timestamps, func() bool {
		return metrics != nil && metrics.crowdConnected != nil && metrics.crowdConnected()
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		handler.ServeHTTP(writer, request)
	})
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		http.NotFound(writer, request)
	})
	metrics = &metricsServer{
		listen: listen,
		ln:     ln,
		errCh:  make(chan error, 1),
		server: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
		},
	}
	return metrics, nil
}

func (m *metricsServer) serve() {
	if m == nil || m.server == nil || m.ln == nil {
		return
	}
	go func() {
		err := m.server.Serve(m.ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			select {
			case m.errCh <- err:
			default:
			}
		}
	}()
}

func (m *metricsServer) close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	var shutdownErr error
	if m.server != nil {
		shutdownErr = m.server.Shutdown(ctx)
		if shutdownErr != nil {
			// A completed forced close retires the listener successfully even
			// when the graceful deadline expired. Preserve actual close errors.
			shutdownErr = m.server.Close()
		}
	}
	var closeErr error
	if m.ln != nil {
		closeErr = m.ln.Close()
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
	}
	return errors.Join(shutdownErr, closeErr)
}

func (m *metricsServer) closeImmediate() error {
	if m == nil {
		return nil
	}
	if m.server != nil {
		_ = m.server.Close()
	}
	if m.ln != nil {
		err := m.ln.Close()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	return nil
}
