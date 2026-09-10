//go:build linux

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Lock is the process-lifetime lifecycle lock. Its inode is never replaced or unlinked.
type Lock struct {
	file     *os.File
	once     sync.Once
	closeErr error
}

// AcquireLock creates (if necessary) and exclusively locks path without blocking.
func AcquireLock(path string) (*Lock, error) {
	if path == "" {
		return nil, errors.New("state lock: empty path")
	}
	parent := filepath.Dir(path)
	if err := ensureDirectory(parent, stateDirMode); err != nil {
		return nil, fmt.Errorf("state lock parent: %w", err)
	}
	if err := validateLockPath(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, recordFileMode) // #nosec G304 -- path is the operator-selected lifecycle lock; O_NOFOLLOW prevents symlink traversal.
	if err != nil {
		return nil, fmt.Errorf("state lock open %q: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("state lock stat: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errors.New("state lock is not a private regular file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		_ = file.Close()
		return nil, errors.New("state lock is owned by another user")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("state lock %q is already held", path)
		}
		return nil, fmt.Errorf("state lock acquire: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("state lock parent sync: %w", err)
	}
	return &Lock{file: file}, nil
}

// Close releases the lock without unlinking or replacing its inode.
func (lock *Lock) Close() error {
	if lock == nil {
		return nil
	}
	lock.once.Do(func() {
		if lock.file == nil {
			return
		}
		if err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN); err != nil {
			lock.closeErr = err
		}
		if err := lock.file.Close(); err != nil && lock.closeErr == nil {
			lock.closeErr = err
		}
	})
	return lock.closeErr
}

func validateLockPath(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("state lock inspect: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("state lock is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("state lock has unsafe permissions")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("state lock is owned by another user")
	}
	return nil
}
