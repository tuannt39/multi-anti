package platform

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tuannt/multi-anti/internal/domain"
)

// Paths resolves multi-anti data directories and native Antigravity CLI paths.
type Paths struct {
	dataDir string
	homeDir string
}

// ResolvePaths computes multi-anti and native agy paths from the environment.
// MULTI_ANTI_HOME overrides DataDir; MULTI_ANTI_AGY_HOME overrides HomeDir (otherwise os.UserHomeDir).
func ResolvePaths() (Paths, error) {
	userHome, homeErr := os.UserHomeDir()
	if homeErr == nil {
		userHome = filepath.Clean(userHome)
	}

	homeDir, err := resolveHomeDir(userHome, homeErr)
	if err != nil {
		return Paths{}, err
	}

	dataDir, err := resolveDataDir(userHome, homeErr)
	if err != nil {
		return Paths{}, err
	}

	return Paths{
		dataDir: dataDir,
		homeDir: homeDir,
	}, nil
}

func resolveHomeDir(userHome string, homeErr error) (string, error) {
	if override := strings.TrimSpace(os.Getenv("MULTI_ANTI_AGY_HOME")); override != "" {
		abs, err := filepath.Abs(override)
		if err != nil {
			return "", fmt.Errorf("resolve MULTI_ANTI_AGY_HOME: %w", err)
		}
		return filepath.Clean(abs), nil
	}
	if homeErr != nil {
		return "", fmt.Errorf("resolve user home directory: %w", homeErr)
	}
	return userHome, nil
}

func resolveDataDir(userHome string, homeErr error) (string, error) {
	if override := strings.TrimSpace(os.Getenv("MULTI_ANTI_HOME")); override != "" {
		abs, err := filepath.Abs(override)
		if err != nil {
			return "", fmt.Errorf("resolve MULTI_ANTI_HOME: %w", err)
		}
		return filepath.Clean(abs), nil
	}
	if runtime.GOOS == "windows" {
		if localApp := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); localApp != "" {
			return filepath.Join(filepath.Clean(localApp), "multi-anti"), nil
		}
		if homeErr != nil {
			return "", fmt.Errorf("resolve user data directory: %w", homeErr)
		}
		return filepath.Join(userHome, "AppData", "Local", "multi-anti"), nil
	}
	if xdgData := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); xdgData != "" {
		return filepath.Join(filepath.Clean(xdgData), "multi-anti"), nil
	}
	if homeErr != nil {
		return "", fmt.Errorf("resolve user data directory: %w", homeErr)
	}
	return filepath.Join(userHome, ".local", "share", "multi-anti"), nil
}

// DataDir returns the root directory for multi-anti state, backups, and profiles.
func (p Paths) DataDir() string { return p.dataDir }

// HomeDir returns the target user home directory hosting native .gemini paths.
func (p Paths) HomeDir() string { return p.homeDir }

// StateFile returns the path to multi-anti's persisted state.json.
func (p Paths) StateFile() string { return filepath.Join(p.dataDir, "state.json") }

// StateLockFile returns the advisory lock file path serializing state.json updates.
func (p Paths) StateLockFile() string { return filepath.Join(p.dataDir, "state.lock") }

// RefreshLockFile returns the lock file path serializing token refresh operations.
func (p Paths) RefreshLockFile() string { return filepath.Join(p.dataDir, "refresh.lock") }

// SignalsDir returns the directory storing Stop-hook to launcher handoff signals.
func (p Paths) SignalsDir() string { return filepath.Join(p.dataDir, "signals") }

// BackupDir returns the directory storing the original native token backup.
func (p Paths) BackupDir() string { return filepath.Join(p.dataDir, "backups") }

// ProfileDir returns the isolated HOME directory for key.
func (p Paths) ProfileDir(key domain.AccountKey) string {
	return filepath.Join(p.dataDir, "profiles", profileSlug(key))
}

// NativeAgyDir returns the native Antigravity CLI state directory.
func (p Paths) NativeAgyDir() string {
	return filepath.Join(p.homeDir, ".gemini", "antigravity-cli")
}

// NativeAgyTokenPath returns the native Antigravity CLI SSH_TTY OAuth token file path.
func (p Paths) NativeAgyTokenPath() string {
	return filepath.Join(p.NativeAgyDir(), "antigravity-oauth-token")
}

// NativeAgySettingsPath returns the native Antigravity CLI settings.json path.
func (p Paths) NativeAgySettingsPath() string {
	return filepath.Join(p.NativeAgyDir(), "settings.json")
}

// NativeGeminiConfigDir returns the native ~/.gemini/config directory.
func (p Paths) NativeGeminiConfigDir() string {
	return filepath.Join(p.homeDir, ".gemini", "config")
}

// NativePluginDir returns the native multi-anti plugin directory inside ~/.gemini/config/plugins.
func (p Paths) NativePluginDir() string {
	return filepath.Join(p.NativeGeminiConfigDir(), "plugins", "multi-anti")
}

func profileSlug(key domain.AccountKey) string {
	raw := string(key)
	sum := sha256.Sum256([]byte(raw))
	suffix := fmt.Sprintf("%x", sum[:4])

	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '@' || c == '-' {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	prefix := strings.Trim(b.String(), "._-")
	if len(prefix) > 48 {
		prefix = strings.TrimRight(prefix[:48], "._-")
	}
	if prefix == "" {
		prefix = "account"
	}
	return prefix + "-" + suffix
}
