package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
)

func TestResolvePaths(t *testing.T) {
	t.Run("respects MULTI_ANTI_HOME and MULTI_ANTI_AGY_HOME independently", func(t *testing.T) {
		tmp := t.TempDir()
		dataHome := filepath.Join(tmp, "custom-data")
		agyHome := filepath.Join(tmp, "custom-agy-home")
		t.Setenv("MULTI_ANTI_HOME", dataHome)
		t.Setenv("MULTI_ANTI_AGY_HOME", agyHome)

		p, err := ResolvePaths()
		if err != nil {
			t.Fatalf("ResolvePaths() error = %v", err)
		}

		if p.DataDir() != dataHome {
			t.Fatalf("DataDir() = %q, want %q", p.DataDir(), dataHome)
		}
		if p.HomeDir() != agyHome {
			t.Fatalf("HomeDir() = %q, want %q", p.HomeDir(), agyHome)
		}
		if p.StateFile() != filepath.Join(dataHome, "state.json") {
			t.Fatalf("StateFile() = %q", p.StateFile())
		}
		if p.StateLockFile() != filepath.Join(dataHome, "state.lock") {
			t.Fatalf("StateLockFile() = %q", p.StateLockFile())
		}
		if p.RefreshLockFile() != filepath.Join(dataHome, "refresh.lock") {
			t.Fatalf("RefreshLockFile() = %q", p.RefreshLockFile())
		}
		if p.SignalsDir() != filepath.Join(dataHome, "signals") {
			t.Fatalf("SignalsDir() = %q", p.SignalsDir())
		}
		if p.BackupDir() != filepath.Join(dataHome, "backups") {
			t.Fatalf("BackupDir() = %q", p.BackupDir())
		}
		if p.NativeAgyDir() != filepath.Join(agyHome, ".gemini", "antigravity-cli") {
			t.Fatalf("NativeAgyDir() = %q", p.NativeAgyDir())
		}
		if p.NativeAgyTokenPath() != filepath.Join(agyHome, ".gemini", "antigravity-cli", "antigravity-oauth-token") {
			t.Fatalf("NativeAgyTokenPath() = %q", p.NativeAgyTokenPath())
		}
		if p.NativeAgySettingsPath() != filepath.Join(agyHome, ".gemini", "antigravity-cli", "settings.json") {
			t.Fatalf("NativeAgySettingsPath() = %q", p.NativeAgySettingsPath())
		}
		if p.NativeGeminiConfigDir() != filepath.Join(agyHome, ".gemini", "config") {
			t.Fatalf("NativeGeminiConfigDir() = %q", p.NativeGeminiConfigDir())
		}
		if p.NativePluginDir() != filepath.Join(agyHome, ".gemini", "config", "plugins", "multi-anti") {
			t.Fatalf("NativePluginDir() = %q", p.NativePluginDir())
		}

		idProfile := p.ProfileDir(domain.AccountKey("id:12345"))
		if strings.Contains(filepath.Base(idProfile), ":") {
			t.Fatalf("ProfileDir basename contains ':' which is invalid on Windows: %q", idProfile)
		}
		if p.ProfileDir(domain.AccountKey("a:b")) == p.ProfileDir(domain.AccountKey("a_b")) {
			t.Fatalf("ProfileDir collided between distinct keys")
		}
	})

	t.Run("defaults from HOME when overrides unset", func(t *testing.T) {
		tmp := t.TempDir()
		t.Setenv("MULTI_ANTI_HOME", "")
		t.Setenv("MULTI_ANTI_AGY_HOME", "")
		t.Setenv("XDG_DATA_HOME", "")
		t.Setenv("LOCALAPPDATA", "")
		t.Setenv("HOME", tmp)
		t.Setenv("USERPROFILE", tmp)

		p, err := ResolvePaths()
		if err != nil {
			t.Fatalf("ResolvePaths() error = %v", err)
		}
		if p.HomeDir() != tmp {
			t.Fatalf("HomeDir() = %q, want %q", p.HomeDir(), tmp)
		}
		if runtime.GOOS != "windows" {
			wantData := filepath.Join(tmp, ".local", "share", "multi-anti")
			if p.DataDir() != wantData {
				t.Fatalf("DataDir() = %q, want %q", p.DataDir(), wantData)
			}
		}
	})
}

func TestWriteFileAtomic(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	secretPath := filepath.Join(dir, "nested", "token.json")

	if err := WriteFileAtomic(secretPath, []byte(`{"token":"v1"}`), true); err != nil {
		t.Fatalf("WriteFileAtomic(v1) error = %v", err)
	}
	if err := WriteFileAtomic(secretPath, []byte(`{"token":"v2"}`), true); err != nil {
		t.Fatalf("WriteFileAtomic(v2) error = %v", err)
	}

	got, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != `{"token":"v2"}` {
		t.Fatalf("content = %q, want v2", got)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(secretPath)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("secret file perm = %o, want 0600", mode)
		}
	}

	entries, err := os.ReadDir(filepath.Dir(secretPath))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file leaked after WriteFileAtomic: %q", e.Name())
		}
	}

	pubPath := filepath.Join(dir, "public.txt")
	if err := WriteFileAtomic(pubPath, []byte("ok"), false); err != nil {
		t.Fatalf("WriteFileAtomic(public) error = %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(pubPath)
		if err != nil {
			t.Fatalf("Stat(public) error = %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o644 {
			t.Fatalf("public file perm = %o, want 0644", mode)
		}
	}
}

func TestWithFileLock(t *testing.T) {
	t.Parallel()

	lockPath := filepath.Join(t.TempDir(), "locks", "state.lock")

	t.Run("serializes exclusive holders", func(t *testing.T) {
		t.Parallel()

		const workers = 12
		var active atomic.Int32
		var maxConcurrent atomic.Int32
		var total atomic.Int32
		var wg sync.WaitGroup

		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := WithFileLock(context.Background(), lockPath, false, func() error {
					cur := active.Add(1)
					for {
						prev := maxConcurrent.Load()
						if cur <= prev || maxConcurrent.CompareAndSwap(prev, cur) {
							break
						}
					}
					time.Sleep(5 * time.Millisecond)
					total.Add(1)
					active.Add(-1)
					return nil
				})
				if err != nil {
					t.Errorf("WithFileLock() error = %v", err)
				}
			}()
		}
		wg.Wait()

		if maxConcurrent.Load() != 1 {
			t.Fatalf("max concurrent exclusive lock holders = %d, want 1", maxConcurrent.Load())
		}
		if total.Load() != workers {
			t.Fatalf("completed callbacks = %d, want %d", total.Load(), workers)
		}
	})

	t.Run("respects context cancellation while waiting", func(t *testing.T) {
		t.Parallel()

		held := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)

		go func() {
			done <- WithFileLock(context.Background(), lockPath, false, func() error {
				close(held)
				<-release
				return nil
			})
		}()

		<-held
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		entered := false
		err := WithFileLock(ctx, lockPath, false, func() error {
			entered = true
			return nil
		})
		close(release)

		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("contended WithFileLock err = %v, want context.DeadlineExceeded", err)
		}
		if entered {
			t.Fatalf("callback ran despite failing to acquire lock")
		}
		if holderErr := <-done; holderErr != nil {
			t.Fatalf("lock holder error = %v", holderErr)
		}
	})
}

func TestProjectDirAndFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	targetDir1 := filepath.Join(root, "target-dir-1")
	targetDir2 := filepath.Join(root, "target-dir-2")
	if err := os.MkdirAll(targetDir1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(targetDir2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetDir1, "marker.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetDir2, "marker.txt"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkDir := filepath.Join(root, "profile", ".gemini", "config")
	if err := ProjectDir(targetDir1, linkDir); err != nil {
		t.Fatalf("ProjectDir(1) error = %v", err)
	}
	if err := ProjectDir(targetDir1, linkDir); err != nil {
		t.Fatalf("ProjectDir(1 idempotent) error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(linkDir, "marker.txt"))
	if err != nil || string(got) != "one" {
		t.Fatalf("read via projected dir = (%q, %v), want one", got, err)
	}

	if err := ProjectDir(targetDir2, linkDir); err != nil {
		t.Fatalf("ProjectDir(2 re-point) error = %v", err)
	}
	got, err = os.ReadFile(filepath.Join(linkDir, "marker.txt"))
	if err != nil || string(got) != "two" {
		t.Fatalf("read via repointed dir = (%q, %v), want two", got, err)
	}

	targetFile1 := filepath.Join(root, "settings-1.json")
	targetFile2 := filepath.Join(root, "settings-2.json")
	if err := os.WriteFile(targetFile1, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetFile2, []byte(`{"a":2}`), 0o600); err != nil {
		t.Fatal(err)
	}

	linkFile := filepath.Join(root, "profile", ".gemini", "antigravity-cli", "settings.json")
	if err := ProjectFile(targetFile1, linkFile); err != nil {
		t.Fatalf("ProjectFile(1) error = %v", err)
	}
	if err := ProjectFile(targetFile1, linkFile); err != nil {
		t.Fatalf("ProjectFile(1 idempotent) error = %v", err)
	}
	gotFile, err := os.ReadFile(linkFile)
	if err != nil || string(gotFile) != `{"a":1}` {
		t.Fatalf("read via projected file = (%q, %v), want {\"a\":1}", gotFile, err)
	}

	if err := ProjectFile(targetFile2, linkFile); err != nil {
		t.Fatalf("ProjectFile(2 re-point) error = %v", err)
	}
	gotFile, err = os.ReadFile(linkFile)
	if err != nil || string(gotFile) != `{"a":2}` {
		t.Fatalf("read via repointed file = (%q, %v), want {\"a\":2}", gotFile, err)
	}
}
