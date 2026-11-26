package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/platform"
)

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("MULTI_ANTI_HOME", filepath.Join(tmp, "data"))
	t.Setenv("MULTI_ANTI_AGY_HOME", filepath.Join(tmp, "agy-home"))
	paths, err := platform.ResolvePaths()
	if err != nil {
		t.Fatalf("ResolvePaths() error = %v", err)
	}
	return NewFileStore(paths)
}

func TestLoadInitialAndBackfill(t *testing.T) {
	t.Run("fresh store initializes schema, accounts map, and default policy", func(t *testing.T) {
		s := newTestStore(t)
		got, err := s.Load(context.Background())
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if got.SchemaVersion != domain.CurrentSchemaVersion {
			t.Fatalf("SchemaVersion = %d, want %d", got.SchemaVersion, domain.CurrentSchemaVersion)
		}
		if got.Accounts == nil {
			t.Fatalf("Accounts map is nil")
		}
		if got.Policy != domain.DefaultSelectionPolicy() {
			t.Fatalf("Policy = %+v, want %+v", got.Policy, domain.DefaultSelectionPolicy())
		}
	})

	t.Run("backfills missing policy and nil accounts map from minimal JSON", func(t *testing.T) {
		s := newTestStore(t)
		if err := platform.WriteFileAtomic(s.Paths().StateFile(), []byte(`{"schema_version":1}`), true); err != nil {
			t.Fatal(err)
		}
		got, err := s.Load(context.Background())
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if got.Accounts == nil {
			t.Fatalf("Accounts map is nil after backfill")
		}
		if got.Policy != domain.DefaultSelectionPolicy() {
			t.Fatalf("Policy = %+v, want %+v", got.Policy, domain.DefaultSelectionPolicy())
		}
	})
}

func TestLoadAndUpdateValidation(t *testing.T) {
	t.Run("corrupt JSON returns error", func(t *testing.T) {
		s := newTestStore(t)
		if err := platform.WriteFileAtomic(s.Paths().StateFile(), []byte(`{not-valid-json`), true); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(context.Background()); err == nil {
			t.Fatalf("expected error loading corrupt JSON, got nil")
		}
	})

	t.Run("unsupported schema version returns error", func(t *testing.T) {
		s := newTestStore(t)
		if err := platform.WriteFileAtomic(s.Paths().StateFile(), []byte(`{"schema_version":99}`), true); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(context.Background()); err == nil {
			t.Fatalf("expected error loading unsupported schema_version, got nil")
		}
	})

	t.Run("rejects dangling active_key and invalid health status", func(t *testing.T) {
		s := newTestStore(t)
		if _, err := s.Update(context.Background(), func(st *domain.StoreState) error {
			st.ActiveKey = "missing@example.com"
			return nil
		}); err == nil {
			t.Fatalf("expected error for dangling active_key")
		}

		if _, err := s.Update(context.Background(), func(st *domain.StoreState) error {
			st.Accounts["a@example.com"] = domain.Account{Key: "a@example.com"}
			return nil
		}); err == nil {
			t.Fatalf("expected error for empty account health status")
		}
	})
}

func TestConcurrentUpdateNoLostUpdates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const workers = 20
	const perWorker = 3
	var wg sync.WaitGroup

	for w := range workers {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := range perWorker {
				key := domain.AccountKey(fmt.Sprintf("user-%d-%d@example.com", workerID, i))
				_, err := s.Update(ctx, func(st *domain.StoreState) error {
					st.Accounts[key] = domain.Account{
						Key:     key,
						Email:   string(key),
						Health:  domain.AccountHealth{Status: domain.HealthReady},
						AddedAt: time.Now().UTC(),
					}
					return nil
				})
				if err != nil {
					t.Errorf("Update(%s) error = %v", key, err)
				}
			}
		}(w)
	}
	wg.Wait()

	finalState, err := s.Load(ctx)
	if err != nil {
		t.Fatalf("final Load() error = %v", err)
	}
	wantCount := workers * perWorker
	if len(finalState.Accounts) != wantCount {
		t.Fatalf("accounts count = %d, want %d (lost updates)", len(finalState.Accounts), wantCount)
	}
	if finalState.Generation != uint64(wantCount) {
		t.Fatalf("Generation = %d, want %d", finalState.Generation, wantCount)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(s.Paths().StateFile())
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("state.json mode = %o, want 0600", mode)
		}
	}
}

func TestNativeBackupAndRestore(t *testing.T) {
	t.Run("restore fails before capture", func(t *testing.T) {
		s := newTestStore(t)
		_, err := s.RestoreNativeBackup(context.Background())
		if !errors.Is(err, ErrNoNativeBackup) {
			t.Fatalf("RestoreNativeBackup() err = %v, want ErrNoNativeBackup", err)
		}
	})

	t.Run("HadFile=true captures once idempotently and restores original bytes", func(t *testing.T) {
		s := newTestStore(t)
		ctx := context.Background()
		origToken := []byte(`{"access_token":"original-native-token"}`)
		if err := platform.WriteFileAtomic(s.Paths().NativeAgyTokenPath(), origToken, true); err != nil {
			t.Fatal(err)
		}

		rec1, err := s.EnsureNativeBackup(ctx)
		if err != nil {
			t.Fatalf("EnsureNativeBackup(1) error = %v", err)
		}
		wantSum := fmt.Sprintf("%x", sha256.Sum256(origToken))
		if !rec1.HadFile || rec1.SHA256 != wantSum {
			t.Fatalf("rec1 = %+v, want HadFile=true SHA256=%s", rec1, wantSum)
		}
		wantBak := filepath.Join(s.Paths().BackupDir(), nativeBackupFilename)
		if rec1.BackupPath != wantBak {
			t.Fatalf("BackupPath = %q, want %q", rec1.BackupPath, wantBak)
		}

		if err := platform.WriteFileAtomic(s.Paths().NativeAgyTokenPath(), []byte(`{"access_token":"switched"}`), true); err != nil {
			t.Fatal(err)
		}

		rec2, err := s.EnsureNativeBackup(ctx)
		if err != nil {
			t.Fatalf("EnsureNativeBackup(2) error = %v", err)
		}
		if rec2.SHA256 != rec1.SHA256 || !rec2.CapturedAt.Equal(rec1.CapturedAt) {
			t.Fatalf("EnsureNativeBackup(2) mutated backup record: %+v vs %+v", rec2, rec1)
		}

		if err := platform.WriteFileAtomic(rec1.BackupPath, []byte(`tampered`), true); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RestoreNativeBackup(ctx); err == nil {
			t.Fatalf("expected SHA-256 mismatch error when backup is tampered")
		}

		if err := platform.WriteFileAtomic(rec1.BackupPath, origToken, true); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RestoreNativeBackup(ctx); err != nil {
			t.Fatalf("RestoreNativeBackup() error = %v", err)
		}
		restored, err := os.ReadFile(s.Paths().NativeAgyTokenPath())
		if err != nil {
			t.Fatal(err)
		}
		if string(restored) != string(origToken) {
			t.Fatalf("restored token = %q, want %q", restored, origToken)
		}
		if _, err := s.RestoreNativeBackup(ctx); !errors.Is(err, ErrNoNativeBackup) {
			t.Fatalf("second RestoreNativeBackup() err = %v, want ErrNoNativeBackup", err)
		}
	})

	t.Run("HadFile=false stays false idempotently and removes switched token on restore", func(t *testing.T) {
		s := newTestStore(t)
		ctx := context.Background()

		rec1, err := s.EnsureNativeBackup(ctx)
		if err != nil {
			t.Fatalf("EnsureNativeBackup(1) error = %v", err)
		}
		if rec1.HadFile || rec1.BackupPath != "" {
			t.Fatalf("rec1 = %+v, want HadFile=false and empty BackupPath", rec1)
		}

		if err := platform.WriteFileAtomic(s.Paths().NativeAgyTokenPath(), []byte(`{"access_token":"active"}`), true); err != nil {
			t.Fatal(err)
		}

		rec2, err := s.EnsureNativeBackup(ctx)
		if err != nil {
			t.Fatalf("EnsureNativeBackup(2) error = %v", err)
		}
		if rec2.HadFile {
			t.Fatalf("EnsureNativeBackup(2) flipped HadFile to true")
		}

		if _, err := s.RestoreNativeBackup(ctx); err != nil {
			t.Fatalf("RestoreNativeBackup(1) error = %v", err)
		}
		if _, err := os.Stat(s.Paths().NativeAgyTokenPath()); !os.IsNotExist(err) {
			t.Fatalf("expected native token file to be removed, stat err = %v", err)
		}
		if _, err := s.RestoreNativeBackup(ctx); !errors.Is(err, ErrNoNativeBackup) {
			t.Fatalf("RestoreNativeBackup(2) err = %v, want ErrNoNativeBackup", err)
		}
		rec3, err := s.EnsureNativeBackup(ctx)
		if err != nil || rec3.HadFile {
			t.Fatalf("EnsureNativeBackup(after restore) = (%+v, %v), want HadFile=false", rec3, err)
		}
	})
}

func TestLoadNormalizesLegacyGeminiArgonState(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	legacyJSON := `{
  "schema_version": 1,
  "generation": 4,
  "active_key": "alice@example.com",
  "policy": {
    "mode": "highest_remaining",
    "target_pool": "gemini-argon",
    "min_remaining_threshold": 0.05,
    "cooldown_default": 300000000000,
    "refresh_skew": 300000000000
  },
  "accounts": {
    "alice@example.com": {
      "key": "alice@example.com",
      "email": "alice@example.com",
      "health": {"status": "ready", "updated_at": "2026-11-25T12:00:00Z"},
      "creds": {"access_token": "at-a", "refresh_token": "rt-a"},
      "quota": {
        "fetched_at": "2026-11-21T17:00:00Z",
        "source": "retrieveUserQuotaSummary",
        "tier": "pro",
        "buckets": [
          {"group_id": "gemini-5h", "pool": "gemini", "window": "5h", "remaining_fraction": 0.80},
          {"group_id": "gemini-weekly", "pool": "gemini", "window": "weekly", "remaining_fraction": 0.90},
          {"group_id": "3p-5h", "pool": "3p", "window": "5h", "remaining_fraction": 1.0},
          {"group_id": "3p-weekly", "pool": "3p", "window": "weekly", "remaining_fraction": 1.0},
          {"group_id": "gemini-argon-wtu-weekly", "pool": "gemini-argon", "window": "weekly", "remaining_fraction": 1.0}
        ]
      }
    }
  },
  "last_switch": {
    "at": "2026-11-21T17:00:00Z",
    "outcome": "switched",
    "from_key": "bob@example.com",
    "to_key": "alice@example.com",
    "reason": "quota_low",
    "pool": "gemini-argon",
    "trigger": "cli"
  }
}`
	if err := platform.WriteFileAtomic(s.Paths().StateFile(), []byte(legacyJSON), true); err != nil {
		t.Fatal(err)
	}

	got, err := s.Load(ctx)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Policy.TargetPool != domain.PoolGemini {
		t.Fatalf("Policy.TargetPool = %q, want %q", got.Policy.TargetPool, domain.PoolGemini)
	}
	if got.LastSwitch == nil || got.LastSwitch.Pool != domain.PoolGemini {
		t.Fatalf("LastSwitch.Pool = %+v, want %q", got.LastSwitch, domain.PoolGemini)
	}
	buckets := got.Accounts["alice@example.com"].Quota.Buckets
	if len(buckets) != 4 {
		t.Fatalf("len(Buckets) = %d, want 4 after stripping gemini-argon: %+v", len(buckets), buckets)
	}
	for _, b := range buckets {
		if b.Pool == "gemini-argon" || b.GroupID == "gemini-argon-wtu-weekly" {
			t.Fatalf("legacy gemini-argon bucket survived Load(): %+v", b)
		}
	}
}
