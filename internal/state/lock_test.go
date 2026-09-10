package state

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAcquireLockRejectsConcurrentOwnerAndRetainsInode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "owner.lock")
	first, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat lifecycle lock: %v", err)
	}
	if before.Mode().Perm() != 0o600 {
		t.Fatalf("lifecycle lock mode = %o, want 600", before.Mode().Perm())
	}
	if _, err := AcquireLock(path); err == nil {
		t.Fatal("second process acquired an already-held lifecycle lock")
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close first lock: %v", err)
	}
	afterClose, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat lock after close: %v", err)
	}
	if before.Sys().(*syscall.Stat_t).Ino != afterClose.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("closing lifecycle lock replaced or removed its inode")
	}

	second, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("reacquire retained lifecycle lock: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	afterReacquire, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat lock after reacquire: %v", err)
	}
	if before.Sys().(*syscall.Stat_t).Ino != afterReacquire.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("reacquiring lifecycle lock changed its inode")
	}
}

func TestAcquireLockRejectsSymlinkWithoutTouchingTarget(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "owner.lock")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(path); err == nil {
		t.Fatal("acquired a symlink lifecycle lock")
	}
	contents, err := os.ReadFile(target) // #nosec G304 -- target is a fixture created beneath t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "sentinel" {
		t.Fatalf("symlink target changed to %q", contents)
	}
}
