package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/platform"
)

const nativeBackupFilename = "native-antigravity-oauth-token.bak"

// EnsureNativeBackup captures the pre-existing native agy OAuth token file once,
// or records HadFile=false if none existed. Subsequent calls are idempotent.
func (s *FileStore) EnsureNativeBackup(ctx context.Context) (domain.NativeBackupRecord, error) {
	var record domain.NativeBackupRecord
	err := platform.WithFileLock(ctx, s.paths.StateLockFile(), false, func() error {
		state, readErr := s.readStateLocked()
		if readErr != nil {
			return readErr
		}
		if state.NativeBackup != nil {
			rec := *state.NativeBackup
			if rec.HadFile {
				if _, statErr := os.Stat(rec.BackupPath); statErr != nil {
					return fmt.Errorf("recorded native backup missing at %q: %w", rec.BackupPath, statErr)
				}
			}
			record = rec
			return nil
		}

		srcPath := s.paths.NativeAgyTokenPath()
		data, err := os.ReadFile(srcPath)
		if err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("read native token %q: %w", srcPath, err)
			}
			record = domain.NativeBackupRecord{
				CapturedAt: time.Now().UTC(),
				SourcePath: srcPath,
				HadFile:    false,
			}
		} else {
			if err := platform.EnsurePrivateDir(s.paths.BackupDir()); err != nil {
				return fmt.Errorf("ensure backup dir %q: %w", s.paths.BackupDir(), err)
			}
			bakPath := filepath.Join(s.paths.BackupDir(), nativeBackupFilename)
			if err := platform.WriteFileAtomic(bakPath, data, true); err != nil {
				return fmt.Errorf("write backup file %q: %w", bakPath, err)
			}
			sum := sha256.Sum256(data)
			record = domain.NativeBackupRecord{
				CapturedAt: time.Now().UTC(),
				SourcePath: srcPath,
				BackupPath: bakPath,
				SHA256:     fmt.Sprintf("%x", sum),
				HadFile:    true,
			}
		}

		state.NativeBackup = &record
		state.Generation++
		if err := validateState(&state); err != nil {
			return err
		}
		return s.writeStateLocked(state)
	})
	if err != nil {
		return domain.NativeBackupRecord{}, err
	}
	return record, nil
}

// RestoreNativeBackup restores the original native agy token file from the recorded backup,
// or removes NativeAgyTokenPath() if the original capture recorded HadFile=false.
func (s *FileStore) RestoreNativeBackup(ctx context.Context) (domain.NativeBackupRecord, error) {
	var record domain.NativeBackupRecord
	err := platform.WithFileLock(ctx, s.paths.StateLockFile(), false, func() error {
		state, readErr := s.readStateLocked()
		if readErr != nil {
			return readErr
		}
		if state.NativeBackup == nil {
			return ErrNoNativeBackup
		}

		rec := *state.NativeBackup
		dstPath := s.paths.NativeAgyTokenPath()
		if !rec.HadFile {
			if err := os.Remove(dstPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove native token %q: %w", dstPath, err)
			}
			state.NativeBackup = nil
			state.Generation++
			if err := s.writeStateLocked(state); err != nil {
				return err
			}
			record = rec
			return nil
		}

		data, err := os.ReadFile(rec.BackupPath)
		if err != nil {
			return fmt.Errorf("read backup file %q: %w", rec.BackupPath, err)
		}
		sum := sha256.Sum256(data)
		gotSHA := fmt.Sprintf("%x", sum)
		if rec.SHA256 != "" && gotSHA != rec.SHA256 {
			return fmt.Errorf("native backup %q sha256 mismatch: got %s, want %s", rec.BackupPath, gotSHA, rec.SHA256)
		}

		if err := platform.WriteFileAtomic(dstPath, data, true); err != nil {
			return fmt.Errorf("restore native token %q: %w", dstPath, err)
		}
		state.NativeBackup = nil
		state.Generation++
		if err := s.writeStateLocked(state); err != nil {
			return err
		}
		record = rec
		return nil
	})
	if err != nil {
		return domain.NativeBackupRecord{}, err
	}
	return record, nil
}
