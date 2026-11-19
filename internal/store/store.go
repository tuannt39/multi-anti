package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/platform"
)

// ErrNoNativeBackup is returned by RestoreNativeBackup when no native backup has been captured.
var ErrNoNativeBackup = errors.New("no native backup recorded")

// Store manages serialized persistent state and native token backups.
type Store interface {
	Paths() platform.Paths
	Load(ctx context.Context) (domain.StoreState, error)
	Update(ctx context.Context, fn func(*domain.StoreState) error) (domain.StoreState, error)
	EnsureNativeBackup(ctx context.Context) (domain.NativeBackupRecord, error)
	RestoreNativeBackup(ctx context.Context) (domain.NativeBackupRecord, error)
}

// FileStore persists StoreState as JSON in Paths.StateFile(), serialized via Paths.StateLockFile().
type FileStore struct {
	paths platform.Paths
}

// NewFileStore constructs a FileStore bound to paths.
func NewFileStore(paths platform.Paths) *FileStore {
	return &FileStore{paths: paths}
}

// Paths returns the resolved filesystem paths used by this store.
func (s *FileStore) Paths() platform.Paths {
	return s.paths
}

// Load reads and validates the persisted StoreState under a shared file lock.
// If state.json does not exist yet, it returns an initialized default StoreState.
func (s *FileStore) Load(ctx context.Context) (domain.StoreState, error) {
	var state domain.StoreState
	err := platform.WithFileLock(ctx, s.paths.StateLockFile(), true, func() error {
		loaded, readErr := s.readStateLocked()
		if readErr != nil {
			return readErr
		}
		state = loaded
		return nil
	})
	if err != nil {
		return domain.StoreState{}, err
	}
	return state, nil
}

// Update runs fn against the latest StoreState under an exclusive file lock,
// increments Generation, validates invariants, and writes state.json atomically.
func (s *FileStore) Update(ctx context.Context, fn func(*domain.StoreState) error) (domain.StoreState, error) {
	if fn == nil {
		return domain.StoreState{}, errors.New("store update: nil callback")
	}

	var updated domain.StoreState
	err := platform.WithFileLock(ctx, s.paths.StateLockFile(), false, func() error {
		state, readErr := s.readStateLocked()
		if readErr != nil {
			return readErr
		}
		prevGen := state.Generation

		if err := fn(&state); err != nil {
			return err
		}

		normalizeState(&state)
		state.Generation = prevGen + 1
		if err := validateState(&state); err != nil {
			return err
		}
		if err := s.writeStateLocked(state); err != nil {
			return err
		}
		updated = state
		return nil
	})
	if err != nil {
		return domain.StoreState{}, err
	}
	return updated, nil
}

func (s *FileStore) readStateLocked() (domain.StoreState, error) {
	raw, err := os.ReadFile(s.paths.StateFile())
	if err != nil {
		if os.IsNotExist(err) {
			return domain.StoreState{
				SchemaVersion: domain.CurrentSchemaVersion,
				Policy:        domain.DefaultSelectionPolicy(),
				Accounts:      make(map[domain.AccountKey]domain.Account),
			}, nil
		}
		return domain.StoreState{}, fmt.Errorf("read state file %q: %w", s.paths.StateFile(), err)
	}

	if len(bytes.TrimSpace(raw)) == 0 {
		return domain.StoreState{}, fmt.Errorf("parse state file %q: empty file", s.paths.StateFile())
	}

	var state domain.StoreState
	if err := json.Unmarshal(raw, &state); err != nil {
		return domain.StoreState{}, fmt.Errorf("parse state file %q: %w", s.paths.StateFile(), err)
	}

	normalizeState(&state)
	if err := validateState(&state); err != nil {
		return domain.StoreState{}, fmt.Errorf("invalid state file %q: %w", s.paths.StateFile(), err)
	}
	return state, nil
}

func (s *FileStore) writeStateLocked(state domain.StoreState) error {
	if err := platform.EnsurePrivateDir(s.paths.DataDir()); err != nil {
		return fmt.Errorf("ensure data dir %q: %w", s.paths.DataDir(), err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data = append(data, '\n')
	return platform.WriteFileAtomic(s.paths.StateFile(), data, true)
}

func normalizeState(state *domain.StoreState) {
	if state.Accounts == nil {
		state.Accounts = make(map[domain.AccountKey]domain.Account)
	}
	state.Policy = backfillPolicy(state.Policy)
}

func backfillPolicy(p domain.SelectionPolicy) domain.SelectionPolicy {
	def := domain.DefaultSelectionPolicy()
	if p == (domain.SelectionPolicy{}) {
		return def
	}
	if p.Mode == "" {
		p.Mode = def.Mode
	}
	if p.CooldownDefault <= 0 {
		p.CooldownDefault = def.CooldownDefault
	}
	if p.RefreshSkew <= 0 {
		p.RefreshSkew = def.RefreshSkew
	}
	return p
}

func validateState(state *domain.StoreState) error {
	if state.SchemaVersion != domain.CurrentSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", state.SchemaVersion)
	}
	if !state.Policy.Mode.IsValid() {
		return fmt.Errorf("invalid selection mode %q", state.Policy.Mode)
	}
	if state.Policy.TargetPool != "" && !state.Policy.TargetPool.IsValid() {
		return fmt.Errorf("invalid target pool %q", state.Policy.TargetPool)
	}
	if math.IsNaN(state.Policy.MinRemainingThreshold) || state.Policy.MinRemainingThreshold < 0 || state.Policy.MinRemainingThreshold > 1 {
		return fmt.Errorf("invalid min_remaining_threshold %v", state.Policy.MinRemainingThreshold)
	}
	if state.ActiveKey != "" {
		if _, ok := state.Accounts[state.ActiveKey]; !ok {
			return fmt.Errorf("active_key %q missing from accounts", state.ActiveKey)
		}
	}
	for k, acc := range state.Accounts {
		if strings.TrimSpace(string(k)) == "" {
			return errors.New("accounts contains empty key")
		}
		if acc.Key != k {
			return fmt.Errorf("account key mismatch: map key %q != account.key %q", k, acc.Key)
		}
		if !acc.Health.Status.IsValid() {
			return fmt.Errorf("account %q has invalid health status %q", k, acc.Health.Status)
		}
	}
	if state.NativeBackup != nil && state.NativeBackup.HadFile && strings.TrimSpace(state.NativeBackup.BackupPath) == "" {
		return errors.New("native_backup has had_file=true with empty backup_path")
	}
	return nil
}
