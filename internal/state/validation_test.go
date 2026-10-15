package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCorruptDurableRecordIsPermanent(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.dir, "journal.json"), []byte(`{"invalid":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = store.Read()
	var invalid *ValidationError
	if !errors.As(err, &invalid) || invalid.RecoveryRetryable() {
		t.Fatalf("corrupt journal not classified as permanent: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.dir, "journal.json")); err != nil {
		t.Fatalf("validation removed journal: %v", err)
	}
}

func TestRequiredMissingRecordPreservesCause(t *testing.T) {
	_, err := readRequired(filepath.Join(t.TempDir(), "missing"))
	var invalid *ValidationError
	if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &invalid) {
		t.Fatalf("missing durable reference: %v", err)
	}
}

func TestOptionalRecordFilesystemFailureRemainsUnclassified(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "regular")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readOptional(filepath.Join(file, "record"))
	var invalid *ValidationError
	if err == nil || errors.As(err, &invalid) {
		t.Fatalf("filesystem failure misclassified as immutable validation: %v", err)
	}
}
