package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteFileAtomic writes data to path via a same-directory temp file, fsync, and atomic replace.
// When secret is true, the file is restricted to owner-only permissions (0600 on Unix, owner DACL on Windows).
func WriteFileAtomic(path string, data []byte, secret bool) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("write file atomic: empty path")
	}

	dir := filepath.Dir(path)
	dirMode := os.FileMode(0o755)
	if secret {
		dirMode = 0o700
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create parent dir %q: %w", dir, err)
	}

	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	tmpPath := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp file %q: %w", tmpPath, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync temp file %q: %w", tmpPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file %q: %w", tmpPath, err)
	}

	if err := applyFilePermissions(tmpPath, secret); err != nil {
		return fmt.Errorf("apply permissions on %q: %w", tmpPath, err)
	}
	if err := replaceFile(tmpPath, path); err != nil {
		return fmt.Errorf("replace %q: %w", path, err)
	}
	committed = true
	return nil
}

// WithFileLock acquires an advisory file lock on lockPath (shared or exclusive),
// polling until ctx is cancelled, then runs fn with the lock held.
func WithFileLock(ctx context.Context, lockPath string, shared bool, fn func() error) error {
	if strings.TrimSpace(lockPath) == "" {
		return errors.New("with file lock: empty lock path")
	}
	if fn == nil {
		return errors.New("with file lock: nil callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := EnsurePrivateDir(filepath.Dir(lockPath)); err != nil {
		return fmt.Errorf("ensure lock dir %q: %w", filepath.Dir(lockPath), err)
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file %q: %w", lockPath, err)
	}
	defer f.Close()

	if err := acquireFileLock(ctx, f, shared); err != nil {
		return fmt.Errorf("acquire lock %q: %w", lockPath, err)
	}
	defer func() {
		_ = releaseFileLock(f)
	}()

	return fn()
}
