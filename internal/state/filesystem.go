package state

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func readOptional(path string) (data []byte, retErr error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("unsafe record %q", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("record %q has unsafe permissions", path)
	}
	file, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // #nosec G304 -- path is a state record selected by the store; O_NOFOLLOW prevents symlink traversal.
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); retErr == nil && closeErr != nil {
			data = nil
			retErr = closeErr
		}
	}()
	limited := io.LimitReader(file, maxRecordBytes+1)
	data, err = io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecordBytes {
		return nil, errors.New("state: record is oversized")
	}
	return data, nil
}

func readRequired(path string) ([]byte, error) {
	data, err := readOptional(path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func ensureDirectory(path string, mode os.FileMode) error {
	clean := filepath.Clean(path)
	var missing []string
	current := clean
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("%q is not a directory", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("cannot find parent directory for %q", current)
		}
		current = parent
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		if err := os.Mkdir(directory, mode.Perm()); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		if err := validateManagedDirectory(directory, info, mode); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(directory)); err != nil {
			return fmt.Errorf("sync parent of %q: %w", directory, err)
		}
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if err := validateManagedDirectory(clean, info, mode); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(clean)); err != nil {
		return fmt.Errorf("sync parent of %q: %w", clean, err)
	}
	return nil
}

func validateManagedDirectory(path string, info os.FileInfo, mode os.FileMode) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("directory %q is owned by another user", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("directory %q has unsafe permissions", path)
	}
	if info.Mode().Perm() != mode.Perm() {
		if err := os.Chmod(path, mode.Perm()); err != nil {
			return err
		}
	}
	return nil
}

func ensureNoPreexistingRecords(dir, revisions string) error {
	for _, name := range []string{"active.json", "journal.json"} {
		if info, err := os.Lstat(filepath.Join(dir, name)); err == nil && info != nil {
			return errors.New("state: records exist without owner identity")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	entries, err := os.ReadDir(revisions)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			return errors.New("state: revisions exist without owner identity")
		}
	}
	return nil
}

func atomicPublish(path string, data []byte, record string, checkpoint func(string) error) error {
	dir := filepath.Dir(path)
	if err := ensureDirectory(dir, stateDirMode); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if record == "owner" {
			return errors.New("owner record already exists")
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("unsafe destination %q", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(dir, ".state-tmp-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(recordFileMode); err != nil {
		_ = temp.Close()
		return err
	}
	if err := writeFull(temp, data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := checkpointCall(checkpoint, record+":before-file-sync"); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := checkpointCall(checkpoint, record+":before-rename"); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	removeTemp = false
	if err := checkpointCall(checkpoint, record+":after-rename"); err != nil {
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	return checkpointCall(checkpoint, record+":after-dir-sync")
}

func writeFull(file *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := file.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func syncRegular(path string) (err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("unsafe regular file")
	}
	file, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // #nosec G304 -- path is a state record selected by the store; O_NOFOLLOW prevents symlink traversal.
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	return file.Sync()
}

func syncDirectory(path string) (err error) {
	file, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // #nosec G304 -- path is a state directory selected by the store; O_NOFOLLOW prevents symlink traversal.
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	return file.Sync()
}

func checkpointCall(checkpoint func(string) error, name string) error {
	if checkpoint == nil {
		return nil
	}
	return checkpoint(name)
}
