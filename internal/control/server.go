package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Timeout bounds socket reads, lookup writes, and default server shutdown.
const (
	Timeout    = 5 * time.Second
	SocketPath = "/run/perimeterd/lookup.sock"
)

func routes(lookup, reload http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		bound := Timeout
		handler := lookup
		if r.URL.Path == ReloadEndpoint {
			bound = ReloadServerTimeout
			handler = reload
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(bound))
		handler.ServeHTTP(w, r)
	})
}

const runtimeDirectoryMode os.FileMode = 0o700

// Server is the private HTTP-over-Unix lookup endpoint.
type Server struct {
	path      string
	listener  net.Listener
	http      *http.Server
	cancel    context.CancelFunc
	done      chan struct{}
	errors    chan error
	closeOnce sync.Once
	inode     socketInode
}

type socketInode struct {
	dev uint64
	ino uint64
}

// Listen binds a private lookup endpoint at path. The caller owns the returned
// server and must close it. Programmatic callers may supply an isolated path;
// the production CLI uses SocketPath.
func Listen(path string, lookup, reload http.Handler) (*Server, error) {
	if lookup == nil || reload == nil {
		return nil, errors.New("lookup: nil handler")
	}
	if path == "" {
		return nil, errors.New("lookup: empty socket path")
	}
	dir := filepath.Dir(path)
	if err := ensureRuntimeDirectory(dir); err != nil {
		return nil, fmt.Errorf("lookup runtime directory: %w", err)
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	unixListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("lookup listen %q: %w", path, err)
	}
	unixListener.SetUnlinkOnClose(false)
	listener := net.Listener(unixListener)
	var inode socketInode
	cleanup := func() {
		_ = listener.Close()
		if inode.ino != 0 {
			_ = removeOwnedSocket(path, inode)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("lookup socket stat: %w", err)
	}
	inode, err = inodeOf(info)
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		cleanup()
		return nil, fmt.Errorf("lookup socket permissions: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		path:     path,
		listener: listener,
		cancel:   cancel,
		done:     make(chan struct{}),
		errors:   make(chan error, 1),
		inode:    inode,
	}
	server.http = &http.Server{
		Handler:           routes(lookup, reload),
		ReadHeaderTimeout: Timeout,
		ReadTimeout:       Timeout,
		WriteTimeout:      ReloadServerTimeout,
		IdleTimeout:       time.Second,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	go server.serve()
	return server, nil
}

func (s *Server) serve() {
	err := s.http.Serve(s.listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.errors <- err
	}
	close(s.done)
	close(s.errors)
}

// Errors reports an unexpected listener failure. Normal Close does not report
// http.ErrServerClosed.
func (s *Server) Errors() <-chan error { return s.errors }

// Close stops admission, cancels active evaluations, drains handlers up to ctx,
// and removes only the socket inode created by this server.
func (s *Server) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, Timeout)
		defer cancel()
	}
	var result error
	s.closeOnce.Do(func() {
		s.cancel()
		shutdownErr := s.http.Shutdown(ctx)
		if shutdownErr != nil {
			result = shutdownErr
			_ = s.http.Close()
		}
		select {
		case <-s.done:
		case <-ctx.Done():
			if result == nil {
				result = ctx.Err()
			}
		}
		if err := removeOwnedSocket(s.path, s.inode); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	})
	return result
}

func ensureRuntimeDirectory(path string) error {
	clean := filepath.Clean(path)
	var chain []string
	for current := clean; ; current = filepath.Dir(current) {
		chain = append(chain, current)
		if current == filepath.Dir(current) {
			break
		}
	}
	for index := len(chain) - 1; index >= 0; index-- {
		info, err := os.Lstat(chain[index])
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("%q is not a directory", chain[index])
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(clean, runtimeDirectoryMode); err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%q is not a directory", clean)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("runtime directory %q is owned by another user", clean)
	}
	if info.Mode().Perm() != runtimeDirectoryMode {
		if err := os.Chmod(clean, runtimeDirectoryMode.Perm()); err != nil {
			return err
		}
	}
	return nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lookup socket stat: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("lookup socket path %q is not a socket", path)
	}
	if err := checkSocketOwner(info); err != nil {
		return err
	}
	conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("lookup socket %q is already in use", path)
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return fmt.Errorf("lookup socket %q is unavailable: %w", path, dialErr)
	}
	before, err := inodeOf(info)
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSymlink != 0 || current.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("lookup socket path %q changed to an unsafe file", path)
	}
	now, err := inodeOf(current)
	if err != nil || now != before {
		return errors.New("lookup stale socket changed during verification")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale lookup socket: %w", err)
	}
	return nil
}

func removeOwnedSocket(path string, expected socketInode) error {
	if expected.ino == 0 {
		return nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("lookup socket path %q changed to an unsafe file", path)
	}
	if err := checkSocketOwner(info); err != nil {
		return err
	}
	actual, err := inodeOf(info)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("lookup socket inode is no longer owned by this server")
	}
	return os.Remove(path)
}

func checkSocketOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("lookup socket is owned by another user")
	}
	return nil
}

func inodeOf(info os.FileInfo) (socketInode, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return socketInode{}, errors.New("lookup socket has unavailable inode metadata")
	}
	return socketInode{dev: uint64(stat.Dev), ino: uint64(stat.Ino)}, nil
}
