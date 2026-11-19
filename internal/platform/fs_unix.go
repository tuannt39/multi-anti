//go:build !windows

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const lockPollInterval = 10 * time.Millisecond

// EnsurePrivateDir creates path if absent and restricts it to owner-only access (0700).
func EnsurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func applyFilePermissions(path string, secret bool) error {
	mode := os.FileMode(0o644)
	if secret {
		mode = 0o600
	}
	return os.Chmod(path, mode)
}

func acquireFileLock(ctx context.Context, f *os.File, shared bool) error {
	how := syscall.LOCK_EX | syscall.LOCK_NB
	if shared {
		how = syscall.LOCK_SH | syscall.LOCK_NB
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(f.Fd()), how)
		if err == nil {
			return nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}

		timer := time.NewTimer(lockPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func releaseFileLock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

func replaceFile(tmpPath, dstPath string) error {
	if err := os.Rename(tmpPath, dstPath); err != nil {
		return err
	}
	if dirF, err := os.Open(filepath.Dir(dstPath)); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}

// ProjectDir makes linkPath mirror targetDir using a POSIX symlink.
func ProjectDir(targetDir, linkPath string) error {
	info, err := os.Stat(targetDir)
	if err != nil {
		return fmt.Errorf("stat target dir %q: %w", targetDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("target %q is not a directory", targetDir)
	}
	return ensureSymlink(targetDir, linkPath)
}

// ProjectFile makes linkPath mirror targetFile using a POSIX symlink.
func ProjectFile(targetFile, linkPath string) error {
	info, err := os.Stat(targetFile)
	if err != nil {
		return fmt.Errorf("stat target file %q: %w", targetFile, err)
	}
	if info.IsDir() {
		return fmt.Errorf("target %q is a directory, want file", targetFile)
	}
	return ensureSymlink(targetFile, linkPath)
}

func ensureSymlink(target, linkPath string) error {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	absTarget = filepath.Clean(absTarget)

	if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
		return err
	}

	existing, err := os.Lstat(linkPath)
	if err == nil {
		if existing.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("destination %q exists and is not a symlink", linkPath)
		}
		if cur, readErr := os.Readlink(linkPath); readErr == nil {
			if !filepath.IsAbs(cur) {
				cur = filepath.Join(filepath.Dir(linkPath), cur)
			}
			if filepath.Clean(cur) == absTarget {
				return nil
			}
		}
		if err := os.Remove(linkPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	return os.Symlink(absTarget, linkPath)
}
