package quota

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/oauth"
	"github.com/tuannt/multi-anti/internal/platform"
	"github.com/tuannt/multi-anti/internal/store"
)

func TestTransportDefaults(t *testing.T) {
	t.Parallel()

	ua := DefaultUserAgent()
	want := fmt.Sprintf("antigravity/cli/1.5.10 (aidev_client; os_type=%s; arch=%s; auth_method=consumer)", runtime.GOOS, runtime.GOARCH)
	if ua != want {
		t.Fatalf("DefaultUserAgent() = %q, want %q", ua, want)
	}

	client := NewCloudCodeHTTPClient(15 * time.Second)
	if client.Timeout != 15*time.Second {
		t.Fatalf("Timeout = %v, want 15s", client.Timeout)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", client.Transport)
	}
	if tr.ForceAttemptHTTP2 {
		t.Fatalf("ForceAttemptHTTP2 = true, want false")
	}
	if tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 {
		t.Fatalf("TLSNextProto = %v, want non-nil empty map", tr.TLSNextProto)
	}
}

func TestCloudCodeFetcher(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 18, 15, 0, 0, 0, time.UTC)

	t.Run("Pro RUQS fixture parses pools, paidTier override, credits, and skips disabled buckets", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "antigravity/cli/1.5.10 ") {
				t.Errorf("User-Agent = %q", got)
			}
			if r.Header.Get("Authorization") != "Bearer ya29.pro" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			body, _ := io.ReadAll(r.Body)

			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1internal:loadCodeAssist":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"cloudaicompanionProject": map[string]any{"id": "proj-pro-1"},
					"currentTier":             map[string]any{"id": "free-tier"},
					"paidTier":                map[string]any{"id": "g1-pro-tier"},
					"availableCredits": []map[string]any{
						{"creditType": "GOOGLE_ONE_AI", "creditAmount": "250"},
					},
				})
			case "/v1internal:retrieveUserQuotaSummary":
				if !strings.Contains(string(body), `"project":"proj-pro-1"`) {
					t.Errorf("retrieveUserQuotaSummary missing project in body: %s", body)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"buckets": []map[string]any{
						{
							"groupId":           "gemini-5h",
							"displayName":       "Gemini 5-Hour",
							"remainingFraction": 0.72,
							"resetTime":         "2026-11-18T19:00:00Z",
						},
						{
							"groupId":           "gemini-weekly",
							"displayName":       "Gemini Weekly",
							"remainingFraction": 0.90,
							"resetTime":         "2026-11-24T00:00:00Z",
						},
						{
							"groupId":           "3p-5h",
							"displayName":       "3P 5-Hour",
							"remainingFraction": 0.45,
							"resetTime":         "2026-11-18T18:00:00Z",
						},
						{
							"groupId":     "3p-weekly",
							"displayName": "3P Weekly",
							"resetTime":   "2026-11-24T00:00:00Z",
						},
						{
							"groupId":           "gemini-argon-wtu-weekly",
							"displayName":       "Gemini Argon",
							"remainingFraction": 0.85,
							"resetTime":         "2026-11-25T00:00:00Z",
						},
						{
							"groupId":           "legacy-disabled",
							"remainingFraction": 0.0,
							"disabled":          true,
						},
					},
				})
			default:
				t.Errorf("unexpected endpoint call: %s", r.URL.Path)
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		fetcher := NewCloudCodeFetcher(FetcherConfig{
			Endpoints:  []string{srv.URL},
			HTTPClient: srv.Client(),
		})

		snap, err := fetcher.Fetch(context.Background(), "ya29.pro", FetchOptions{Now: now})
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		if snap.Source != domain.QuotaSourceSummary {
			t.Fatalf("Source = %q, want %q", snap.Source, domain.QuotaSourceSummary)
		}
		if snap.Tier != domain.TierPro || snap.RawCurrentTier != "free-tier" || snap.RawPaidTier != "g1-pro-tier" {
			t.Fatalf("tier fields = (%q, %q, %q)", snap.Tier, snap.RawCurrentTier, snap.RawPaidTier)
		}
		if snap.ProjectID != "proj-pro-1" {
			t.Fatalf("ProjectID = %q, want proj-pro-1", snap.ProjectID)
		}
		if len(snap.Credits) != 1 || snap.Credits[0].Provider != "GOOGLE_ONE_AI" || snap.Credits[0].Remaining != 250 {
			t.Fatalf("Credits = %+v", snap.Credits)
		}
		if snap.SummaryForbidden {
			t.Fatalf("SummaryForbidden = true, want false")
		}
		if len(snap.Buckets) != 5 {
			t.Fatalf("len(Buckets) = %d, want 5 (disabled bucket excluded)", len(snap.Buckets))
		}
		if rem, _, ok := snap.PoolRemaining(domain.PoolGemini); !ok || rem != 0.72 {
			t.Fatalf("PoolGemini = (%v, %v), want (0.72, true)", rem, ok)
		}
		if rem, _, ok := snap.PoolRemaining(domain.Pool3P); !ok || rem != 0.0 {
			t.Fatalf("Pool3P = (%v, %v), want (0.0, true)", rem, ok)
		}
		if rem, _, ok := snap.PoolRemaining(domain.PoolGeminiArgon); !ok || rem != 0.85 {
			t.Fatalf("PoolGeminiArgon = (%v, %v), want (0.85, true)", rem, ok)
		}
	})

	t.Run("Free tier 403 #3501 falls back to fetchAvailableModels and skips internal/chat models", func(t *testing.T) {
		t.Parallel()

		var summaryCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1internal:loadCodeAssist":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"cloudaicompanionProject": "proj-free-string",
					"currentTier":             map[string]any{"id": "free-tier"},
				})
			case "/v1internal:retrieveUserQuotaSummary":
				summaryCalls.Add(1)
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"code":403,"message":"#3501 permission denied"}}`))
			case "/v1internal:fetchAvailableModels":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"models": map[string]any{
						"gemini-2.5-pro": map[string]any{
							"displayName":      "Gemini 2.5 Pro",
							"supportsThinking": true,
							"quotaInfo": map[string]any{
								"remainingFraction": 0.60,
								"resetTime":         "2026-11-18T18:00:00Z",
							},
						},
						"claude-sonnet-4-6": map[string]any{
							"displayName": "Claude Sonnet 4.6",
							"quotaInfo": map[string]any{
								"resetTime": "2026-11-18T20:00:00Z",
							},
						},
						"chat_20706": map[string]any{
							"displayName": "Chat Hidden",
							"quotaInfo":   map[string]any{"remainingFraction": 0.1},
						},
						"internal-eval-model": map[string]any{
							"isInternal": true,
							"quotaInfo":  map[string]any{"remainingFraction": 0.1},
						},
					},
				})
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		fetcher := NewCloudCodeFetcher(FetcherConfig{
			Endpoints:  []string{srv.URL},
			HTTPClient: srv.Client(),
		})

		snap, err := fetcher.Fetch(context.Background(), "ya29.free", FetchOptions{Now: now})
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		if summaryCalls.Load() != 2 {
			t.Fatalf("expected initial project call + empty {} retry on 403, got %d calls", summaryCalls.Load())
		}
		if !snap.SummaryForbidden {
			t.Fatalf("SummaryForbidden = false, want true")
		}
		if snap.Source != domain.QuotaSourceModels {
			t.Fatalf("Source = %q, want %q", snap.Source, domain.QuotaSourceModels)
		}
		if snap.Tier != domain.TierFree || snap.ProjectID != "proj-free-string" {
			t.Fatalf("tier=%q project=%q", snap.Tier, snap.ProjectID)
		}
		if len(snap.Models) != 2 {
			t.Fatalf("len(Models) = %d, want 2: %+v", len(snap.Models), snap.Models)
		}
		if snap.Models[0].ModelID != "claude-sonnet-4-6" || snap.Models[0].RemainingFraction != 0.0 {
			t.Fatalf("Models[0] = %+v, want claude-sonnet-4-6 exhausted at 0.0", snap.Models[0])
		}
		if snap.Models[1].ModelID != "gemini-2.5-pro" || snap.Models[1].RemainingFraction != 0.60 || !snap.Models[1].SupportsThinking {
			t.Fatalf("Models[1] = %+v", snap.Models[1])
		}
	})

	t.Run("falls back from daily 502 to prod 200 and retries {} on project 403", func(t *testing.T) {
		t.Parallel()

		dailySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		}))
		defer dailySrv.Close()

		prodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1internal:loadCodeAssist":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"cloudaicompanionProject": "bad-proj",
					"currentTier":             map[string]any{"id": "g1-ultra-tier"},
				})
			case "/v1internal:retrieveUserQuotaSummary":
				if strings.Contains(string(body), "bad-proj") {
					http.Error(w, "project mismatch", http.StatusForbidden)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"buckets": []map[string]any{
						{"groupId": "gemini-5h", "remainingFraction": 0.95},
					},
				})
			default:
				http.NotFound(w, r)
			}
		}))
		defer prodSrv.Close()

		prodURL, _ := url.Parse(prodSrv.URL)
		fetcher := NewCloudCodeFetcher(FetcherConfig{
			Endpoints:  []string{dailySrv.URL, prodSrv.URL},
			HTTPClient: prodSrv.Client(),
		})

		snap, err := fetcher.Fetch(context.Background(), "ya29.ok", FetchOptions{Now: now})
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		if snap.EndpointHost != prodURL.Host {
			t.Fatalf("EndpointHost = %q, want %q", snap.EndpointHost, prodURL.Host)
		}
		if snap.Tier != domain.TierUltra {
			t.Fatalf("Tier = %q, want %q", snap.Tier, domain.TierUltra)
		}
		if snap.SummaryForbidden || len(snap.Buckets) != 1 || snap.Buckets[0].RemainingFraction != 0.95 {
			t.Fatalf("unexpected snapshot: %+v", snap)
		}
	})

	t.Run("parses nested groups[].buckets[] response with bucketId and window", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1internal:loadCodeAssist":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"cloudaicompanionProject": "aicode-consumers",
					"paidTier":                map[string]any{"id": "g1-pro-tier"},
				})
			case "/v1internal:retrieveUserQuotaSummary":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"groups": []map[string]any{
						{
							"displayName": "Gemini Models",
							"buckets": []map[string]any{
								{
									"bucketId":          "gemini-weekly",
									"displayName":       "Weekly Limit Remaining",
									"window":            "weekly",
									"resetTime":         "2026-11-25T15:00:38Z",
									"remainingFraction": 0.615504,
								},
								{
									"bucketId":          "gemini-5h",
									"displayName":       "Five Hour Limit Remaining",
									"window":            "5h",
									"resetTime":         "2026-11-19T21:48:40Z",
									"remainingFraction": 0.19897467,
								},
							},
						},
						{
							"displayName": "Claude and GPT models",
							"buckets": []map[string]any{
								{
									"bucketId":          "3p-weekly",
									"displayName":       "Weekly Limit Remaining",
									"window":            "weekly",
									"resetTime":         "2026-11-26T07:14:52Z",
									"remainingFraction": 0,
								},
								{
									"bucketId":          "3p-5h",
									"displayName":       "Five Hour Limit Remaining",
									"window":            "5h",
									"resetTime":         "2026-11-19T22:01:19Z",
									"disabled":          true,
									"remainingFraction": 0.2796072,
								},
							},
						},
						{
							"displayName": "Gemini 4 Argon",
							"buckets": []map[string]any{
								{
									"bucketId":          "gemini-argon-wtu-weekly",
									"displayName":       "Gemini 4 Argon Weekly Limit",
									"window":            "weekly",
									"resetTime":         "2026-11-26T17:45:16Z",
									"remainingFraction": 1,
								},
							},
						},
					},
				})
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		fetcher := NewCloudCodeFetcher(FetcherConfig{
			Endpoints:  []string{srv.URL},
			HTTPClient: srv.Client(),
		})

		snap, err := fetcher.Fetch(context.Background(), "ya29.nested", FetchOptions{Now: now})
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		if len(snap.Buckets) != 4 {
			t.Fatalf("len(Buckets) = %d, want 4 (disabled 3p-5h excluded): %+v", len(snap.Buckets), snap.Buckets)
		}

		byID := make(map[string]domain.QuotaBucket, len(snap.Buckets))
		for _, b := range snap.Buckets {
			byID[b.GroupID] = b
		}
		if b := byID["gemini-weekly"]; b.Pool != domain.PoolGemini || b.Window != domain.WindowWeekly || b.RemainingFraction != 0.615504 {
			t.Fatalf("gemini-weekly = %+v", b)
		}
		if b := byID["gemini-5h"]; b.Pool != domain.PoolGemini || b.Window != domain.Window5h || b.RemainingFraction != 0.19897467 {
			t.Fatalf("gemini-5h = %+v", b)
		}
		if b := byID["3p-weekly"]; b.Pool != domain.Pool3P || b.Window != domain.WindowWeekly || b.RemainingFraction != 0 || b.ResetAt == nil {
			t.Fatalf("3p-weekly = %+v", b)
		}
		if _, hasDisabled := byID["3p-5h"]; hasDisabled {
			t.Fatalf("expected disabled 3p-5h bucket to be skipped")
		}
		if b := byID["gemini-argon-wtu-weekly"]; b.Pool != domain.PoolGeminiArgon || b.Window != domain.WindowWeekly || b.RemainingFraction != 1 {
			t.Fatalf("gemini-argon-wtu-weekly = %+v", b)
		}
	})
}

type stubOAuthClient struct {
	mu          sync.Mutex
	refreshFn   func(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, now time.Time) (domain.AccountCredentials, bool, error)
	refreshHits int
}

func (s *stubOAuthClient) Login(context.Context, oauth.LoginOptions) (domain.AccountIdentity, domain.AccountCredentials, error) {
	return domain.AccountIdentity{}, domain.AccountCredentials{}, errors.New("not implemented")
}

func (s *stubOAuthClient) Refresh(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, now time.Time) (domain.AccountCredentials, bool, error) {
	s.mu.Lock()
	s.refreshHits++
	s.mu.Unlock()
	return s.refreshFn(ctx, creds, skew, now)
}

func (s *stubOAuthClient) ImportNativeToken(context.Context, string) (domain.AccountIdentity, domain.AccountCredentials, error) {
	return domain.AccountIdentity{}, domain.AccountCredentials{}, errors.New("not implemented")
}

type stubFetcher struct {
	active        atomic.Int32
	maxConcurrent atomic.Int32
	fetchFn       func(ctx context.Context, token string, opts FetchOptions) (domain.QuotaSnapshot, error)
}

func (f *stubFetcher) Fetch(ctx context.Context, token string, opts FetchOptions) (domain.QuotaSnapshot, error) {
	cur := f.active.Add(1)
	for {
		prev := f.maxConcurrent.Load()
		if cur <= prev || f.maxConcurrent.CompareAndSwap(prev, cur) {
			break
		}
	}
	defer f.active.Add(-1)
	return f.fetchFn(ctx, token, opts)
}

func newQuotaTestStore(t *testing.T) *store.FileStore {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("MULTI_ANTI_HOME", filepath.Join(tmp, "data"))
	t.Setenv("MULTI_ANTI_AGY_HOME", filepath.Join(tmp, "agy"))
	paths, err := platform.ResolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	return store.NewFileStore(paths)
}

func TestRefreshAndFetchAll(t *testing.T) {
	now := time.Date(2026, 11, 18, 16, 0, 0, 0, time.UTC)

	t.Run("bounds workers to 4, refreshes expiring tokens, promotes expired cooldowns, and marks revoked", func(t *testing.T) {
		st := newQuotaTestStore(t)
		ctx := context.Background()

		pastCooldown := now.Add(-1 * time.Minute)
		keys := []domain.AccountKey{
			"a1@example.com",
			"a2@example.com",
			"a3@example.com",
			"a4@example.com",
			"a5@example.com",
			"revoked@example.com",
		}

		_, err := st.Update(ctx, func(s *domain.StoreState) error {
			for i, k := range keys {
				health := domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now.Add(-time.Hour)}
				expiry := now.Add(time.Hour)
				if i == 0 {
					health = domain.AccountHealth{
						Status:        domain.HealthCooldown,
						Reason:        "429",
						CooldownUntil: &pastCooldown,
						UpdatedAt:     now.Add(-10 * time.Minute),
					}
				}
				if i%2 == 1 {
					expiry = now.Add(1 * time.Minute)
				}
				s.Accounts[k] = domain.Account{
					Key:    k,
					Email:  string(k),
					Health: health,
					Creds: domain.AccountCredentials{
						AccessToken:  "old-" + string(k),
						RefreshToken: "ref-" + string(k),
						Expiry:       expiry,
					},
					AddedAt: now.Add(-24 * time.Hour),
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		oauthClient := &stubOAuthClient{
			refreshFn: func(_ context.Context, creds domain.AccountCredentials, _ time.Duration, ts time.Time) (domain.AccountCredentials, bool, error) {
				if creds.RefreshToken == "ref-revoked@example.com" {
					return domain.AccountCredentials{}, false, fmt.Errorf("%w: invalid_grant", oauth.ErrRefreshRevoked)
				}
				creds.AccessToken = "fresh-" + creds.RefreshToken
				creds.Expiry = ts.Add(time.Hour)
				return creds, true, nil
			},
		}

		fetcher := &stubFetcher{
			fetchFn: func(_ context.Context, token string, opts FetchOptions) (domain.QuotaSnapshot, error) {
				time.Sleep(25 * time.Millisecond)
				return domain.QuotaSnapshot{
					FetchedAt: opts.Now,
					Source:    domain.QuotaSourceSummary,
					Tier:      domain.TierPro,
					Buckets: []domain.QuotaBucket{
						{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.88},
					},
					FetchError: token,
				}, nil
			},
		}

		results, err := RefreshAndFetchAll(ctx, st, oauthClient, fetcher, nil, FetchOptions{Now: now})
		if err != nil {
			t.Fatalf("RefreshAndFetchAll() error = %v", err)
		}
		if len(results) != len(keys) {
			t.Fatalf("len(results) = %d, want %d", len(results), len(keys))
		}
		if maxC := fetcher.maxConcurrent.Load(); maxC > maxConcurrentFetches || maxC < 2 {
			t.Fatalf("maxConcurrent fetches = %d, want between 2 and %d", maxC, maxConcurrentFetches)
		}

		updated, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if updated.Accounts["a1@example.com"].Health.Status != domain.HealthReady {
			t.Fatalf("a1 health = %+v, want promoted HealthReady", updated.Accounts["a1@example.com"].Health)
		}
		if updated.Accounts["a2@example.com"].Creds.AccessToken != "fresh-ref-a2@example.com" {
			t.Fatalf("a2 creds not refreshed: %+v", updated.Accounts["a2@example.com"].Creds)
		}
		if updated.Accounts["a2@example.com"].Quota == nil || updated.Accounts["a2@example.com"].Quota.Tier != domain.TierPro {
			t.Fatalf("a2 quota not saved: %+v", updated.Accounts["a2@example.com"].Quota)
		}
		if updated.Accounts["revoked@example.com"].Health.Status != domain.HealthNeedsReauth {
			t.Fatalf("revoked health = %+v, want HealthNeedsReauth", updated.Accounts["revoked@example.com"].Health)
		}
	})

	t.Run("serializes concurrent refreshes via RefreshLockFile and recovers 401 via forced refresh", func(t *testing.T) {
		st := newQuotaTestStore(t)
		ctx := context.Background()

		_, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts["expiring@example.com"] = domain.Account{
				Key:    "expiring@example.com",
				Email:  "expiring@example.com",
				Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now},
				Creds: domain.AccountCredentials{
					AccessToken:  "stale",
					RefreshToken: "ref-1",
					Expiry:       now.Add(-time.Minute),
				},
				AddedAt: now,
			}
			s.Accounts["stale401@example.com"] = domain.Account{
				Key:    "stale401@example.com",
				Email:  "stale401@example.com",
				Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now},
				Creds: domain.AccountCredentials{
					AccessToken:  "revoked-access",
					RefreshToken: "ref-401",
					Expiry:       now.Add(time.Hour),
				},
				AddedAt: now,
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		var refreshExpiringCalls atomic.Int32
		oauthClient := &stubOAuthClient{
			refreshFn: func(_ context.Context, creds domain.AccountCredentials, skew time.Duration, ts time.Time) (domain.AccountCredentials, bool, error) {
				if creds.AccessToken != "" && !creds.Expiry.IsZero() && creds.Expiry.After(ts.Add(skew)) {
					return creds, false, nil
				}
				if creds.RefreshToken == "ref-1" {
					refreshExpiringCalls.Add(1)
					time.Sleep(20 * time.Millisecond)
					creds.AccessToken = "rotated-access"
					creds.Expiry = ts.Add(time.Hour)
					return creds, true, nil
				}
				creds.AccessToken = "recovered-access"
				creds.Expiry = ts.Add(time.Hour)
				return creds, true, nil
			},
		}

		fetcher := &stubFetcher{
			fetchFn: func(_ context.Context, token string, opts FetchOptions) (domain.QuotaSnapshot, error) {
				if token == "revoked-access" {
					return domain.QuotaSnapshot{}, ErrUnauthorized
				}
				return domain.QuotaSnapshot{
					FetchedAt: opts.Now,
					Source:    domain.QuotaSourceSummary,
					Tier:      domain.TierPro,
				}, nil
			},
		}

		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := RefreshAndFetchAll(ctx, st, oauthClient, fetcher, []domain.AccountKey{"expiring@example.com"}, FetchOptions{Now: now}); err != nil {
					t.Errorf("concurrent RefreshAndFetchAll error = %v", err)
				}
			}()
		}
		wg.Wait()

		if refreshExpiringCalls.Load() != 1 {
			t.Fatalf("refreshExpiringCalls = %d, want 1 (RefreshLockFile should prevent duplicate refresh)", refreshExpiringCalls.Load())
		}

		res, err := RefreshAndFetchAll(ctx, st, oauthClient, fetcher, []domain.AccountKey{"stale401@example.com"}, FetchOptions{Now: now})
		if err != nil || len(res) != 1 || res[0].Err != nil || !res[0].RefreshedAuth {
			t.Fatalf("401 recovery result = (%+v, %v)", res, err)
		}
		updated, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if updated.Accounts["stale401@example.com"].Creds.AccessToken != "recovered-access" {
			t.Fatalf("stale401 AccessToken = %q, want recovered-access", updated.Accounts["stale401@example.com"].Creds.AccessToken)
		}

		_, err = st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts["norefresh@example.com"] = domain.Account{
				Key:    "norefresh@example.com",
				Email:  "norefresh@example.com",
				Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now},
				Creds: domain.AccountCredentials{
					AccessToken: "revoked-access",
					Expiry:      now.Add(time.Hour),
				},
				AddedAt: now,
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = RefreshAndFetchAll(ctx, st, oauthClient, fetcher, []domain.AccountKey{"norefresh@example.com"}, FetchOptions{Now: now})
		if err != nil {
			t.Fatal(err)
		}
		updated, err = st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if updated.Accounts["norefresh@example.com"].Health.Status != domain.HealthNeedsReauth {
			t.Fatalf("norefresh health = %+v, want HealthNeedsReauth", updated.Accounts["norefresh@example.com"].Health)
		}
	})

	t.Run("ErrMissingClientID preserves HealthReady and cached Buckets/Models while recording FetchError", func(t *testing.T) {
		st := newQuotaTestStore(t)
		ctx := context.Background()

		cachedReset := now.Add(2 * time.Hour)
		cachedBuckets := []domain.QuotaBucket{
			{
				GroupID:           "gemini-5h",
				DisplayName:       "Gemini 5-Hour",
				Pool:              domain.PoolGemini,
				Window:            domain.Window5h,
				RemainingFraction: 0.72,
				ResetAt:           &cachedReset,
			},
		}
		cachedModels := []domain.ModelQuota{
			{
				ModelID:           "gemini-2.5-pro",
				DisplayName:       "Gemini 2.5 Pro",
				RemainingFraction: 0.72,
				ResetAt:           &cachedReset,
			},
		}

		_, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts["missing-cid@example.com"] = domain.Account{
				Key:    "missing-cid@example.com",
				Email:  "missing-cid@example.com",
				Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now.Add(-time.Hour)},
				Creds: domain.AccountCredentials{
					RefreshToken: "ref-only",
				},
				Quota: &domain.QuotaSnapshot{
					FetchedAt: now.Add(-10 * time.Minute),
					Source:    domain.QuotaSourceSummary,
					Tier:      domain.TierPro,
					Buckets:   cachedBuckets,
					Models:    cachedModels,
				},
				AddedAt: now.Add(-24 * time.Hour),
			}
			s.Accounts["forced401-missing-cid@example.com"] = domain.Account{
				Key:    "forced401-missing-cid@example.com",
				Email:  "forced401-missing-cid@example.com",
				Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now.Add(-time.Hour)},
				Creds: domain.AccountCredentials{
					AccessToken:  "stale-access",
					RefreshToken: "ref-401",
					Expiry:       now.Add(time.Hour),
				},
				Quota: &domain.QuotaSnapshot{
					FetchedAt: now.Add(-10 * time.Minute),
					Source:    domain.QuotaSourceSummary,
					Tier:      domain.TierPro,
					Buckets:   cachedBuckets,
				},
				AddedAt: now.Add(-24 * time.Hour),
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		oauthClient := &stubOAuthClient{
			refreshFn: func(_ context.Context, creds domain.AccountCredentials, _ time.Duration, _ time.Time) (domain.AccountCredentials, bool, error) {
				return creds, false, oauth.ErrMissingClientID
			},
		}
		fetcher := &stubFetcher{
			fetchFn: func(_ context.Context, token string, _ FetchOptions) (domain.QuotaSnapshot, error) {
				if token == "stale-access" {
					return domain.QuotaSnapshot{}, ErrUnauthorized
				}
				return domain.QuotaSnapshot{}, errors.New("unexpected fetch without access token")
			},
		}

		results, err := RefreshAndFetchAll(ctx, st, oauthClient, fetcher, nil, FetchOptions{Now: now})
		if err != nil {
			t.Fatalf("RefreshAndFetchAll() error = %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("len(results) = %d, want 2", len(results))
		}
		for _, r := range results {
			if !errors.Is(r.Err, oauth.ErrMissingClientID) {
				t.Fatalf("result[%q].Err = %v, want ErrMissingClientID", r.Key, r.Err)
			}
			if r.Health.Status != domain.HealthReady {
				t.Fatalf("result[%q].Health = %+v, want HealthReady", r.Key, r.Health)
			}
		}

		updated, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []domain.AccountKey{"missing-cid@example.com", "forced401-missing-cid@example.com"} {
			acc := updated.Accounts[key]
			if acc.Health.Status != domain.HealthReady {
				t.Fatalf("%s Health = %+v, want HealthReady", key, acc.Health)
			}
			if acc.Quota == nil {
				t.Fatalf("%s Quota is nil, want cached snapshot preserved", key)
			}
			if len(acc.Quota.Buckets) != 1 || acc.Quota.Buckets[0].GroupID != "gemini-5h" || acc.Quota.Buckets[0].RemainingFraction != 0.72 {
				t.Fatalf("%s Buckets = %+v, want cached buckets preserved", key, acc.Quota.Buckets)
			}
			if !strings.Contains(acc.Quota.FetchError, oauth.ErrMissingClientID.Error()) {
				t.Fatalf("%s FetchError = %q, want substring %q", key, acc.Quota.FetchError, oauth.ErrMissingClientID.Error())
			}
		}
		if len(updated.Accounts["missing-cid@example.com"].Quota.Models) != 1 ||
			updated.Accounts["missing-cid@example.com"].Quota.Models[0].ModelID != "gemini-2.5-pro" {
			t.Fatalf("missing-cid Models = %+v, want cached models preserved", updated.Accounts["missing-cid@example.com"].Quota.Models)
		}
	})
}

func TestCanStageWithoutRefresh(t *testing.T) {
	t.Parallel()

	transientErr := errors.New("temporary network failure")
	wrappedMissingClientID := fmt.Errorf("refresh failed: %w", oauth.ErrMissingClientID)
	wrappedRevoked := fmt.Errorf("refresh failed: %w", oauth.ErrRefreshRevoked)

	tests := []struct {
		name       string
		creds      domain.AccountCredentials
		refreshErr error
		want       bool
	}{
		{
			name:       "nil error always allows staging",
			creds:      domain.AccountCredentials{},
			refreshErr: nil,
			want:       true,
		},
		{
			name: "revoked error blocks staging even with tokens present",
			creds: domain.AccountCredentials{
				AccessToken:  "ya29.access",
				RefreshToken: "1//refresh",
			},
			refreshErr: oauth.ErrRefreshRevoked,
			want:       false,
		},
		{
			name: "wrapped revoked error blocks staging",
			creds: domain.AccountCredentials{
				AccessToken:  "ya29.access",
				RefreshToken: "1//refresh",
			},
			refreshErr: wrappedRevoked,
			want:       false,
		},
		{
			name: "non-revoked error allows staging when access token exists",
			creds: domain.AccountCredentials{
				AccessToken: "ya29.stale",
			},
			refreshErr: transientErr,
			want:       true,
		},
		{
			name: "transient error blocks staging when access token is blank",
			creds: domain.AccountCredentials{
				AccessToken:  "   ",
				RefreshToken: "1//refresh",
			},
			refreshErr: transientErr,
			want:       false,
		},
		{
			name: "ErrMissingClientID allows staging when refresh token exists",
			creds: domain.AccountCredentials{
				RefreshToken: "1//refresh",
			},
			refreshErr: oauth.ErrMissingClientID,
			want:       true,
		},
		{
			name: "wrapped ErrMissingClientID allows staging when refresh token exists",
			creds: domain.AccountCredentials{
				AccessToken:  "  ",
				RefreshToken: "1//refresh",
			},
			refreshErr: wrappedMissingClientID,
			want:       true,
		},
		{
			name: "ErrMissingClientID allows staging when access token exists without refresh token",
			creds: domain.AccountCredentials{
				AccessToken: "ya29.stale",
			},
			refreshErr: oauth.ErrMissingClientID,
			want:       true,
		},
		{
			name: "ErrMissingClientID blocks staging when both tokens are empty or whitespace",
			creds: domain.AccountCredentials{
				AccessToken:  " ",
				RefreshToken: "\t",
			},
			refreshErr: oauth.ErrMissingClientID,
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := CanStageWithoutRefresh(tc.creds, tc.refreshErr); got != tc.want {
				t.Fatalf("CanStageWithoutRefresh(%+v, %v) = %v, want %v", tc.creds, tc.refreshErr, got, tc.want)
			}
		})
	}
}

func TestSyncNativeTokenIfFresher(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	t.Run("syncs fresher native token, clears reauth and stale FetchError", func(t *testing.T) {
		st := newQuotaTestStore(t)
		_, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts["alice@example.com"] = domain.Account{
				Key:   "alice@example.com",
				Email: "alice@example.com",
				Health: domain.AccountHealth{
					Status:    domain.HealthNeedsReauth,
					Reason:    "stale reauth",
					UpdatedAt: now.Add(-time.Hour),
				},
				Creds: domain.AccountCredentials{
					AccessToken:  "old-at",
					RefreshToken: "old-rt",
					IDToken:      "existing-id-tok",
					ClientID:     "existing-cid",
					Expiry:       now.Add(-10 * time.Minute),
				},
				Quota: &domain.QuotaSnapshot{
					FetchedAt:  now.Add(-10 * time.Minute),
					Tier:       domain.TierPro,
					FetchError: "missing OAuth client_id",
				},
				AddedAt: now.Add(-24 * time.Hour),
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		raw, err := oauth.EncodeAgyTokenFile("alice@example.com", domain.AccountCredentials{
			AccessToken: "fresh-at",
			Expiry:      now.Add(50 * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := platform.WriteFileAtomic(st.Paths().NativeAgyTokenPath(), raw, true); err != nil {
			t.Fatal(err)
		}

		changed, err := SyncNativeTokenIfFresher(ctx, st, now)
		if err != nil {
			t.Fatalf("SyncNativeTokenIfFresher() error = %v", err)
		}
		if !changed {
			t.Fatalf("changed = false, want true")
		}

		after, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		alice := after.Accounts["alice@example.com"]
		if alice.Creds.AccessToken != "fresh-at" || alice.Creds.RefreshToken != "old-rt" || alice.Creds.ClientID != "existing-cid" || alice.Creds.IDToken != "existing-id-tok" {
			t.Fatalf("unexpected merged creds: %+v", alice.Creds)
		}
		if alice.Health.Status != domain.HealthReady {
			t.Fatalf("Health = %+v, want HealthReady", alice.Health)
		}
		if alice.Quota.FetchError != "" {
			t.Fatalf("FetchError = %q, want cleared", alice.Quota.FetchError)
		}
	})

	t.Run("ignores older native token and unmanaged accounts", func(t *testing.T) {
		st := newQuotaTestStore(t)
		_, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts["alice@example.com"] = domain.Account{
				Key:   "alice@example.com",
				Email: "alice@example.com",
				Health: domain.AccountHealth{
					Status:    domain.HealthReady,
					UpdatedAt: now,
				},
				Creds: domain.AccountCredentials{
					AccessToken:  "current-at",
					RefreshToken: "current-rt",
					Expiry:       now.Add(time.Hour),
				},
				AddedAt: now.Add(-24 * time.Hour),
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		olderRaw, err := oauth.EncodeAgyTokenFile("alice@example.com", domain.AccountCredentials{
			AccessToken:  "older-at",
			RefreshToken: "older-rt",
			Expiry:       now.Add(10 * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := platform.WriteFileAtomic(st.Paths().NativeAgyTokenPath(), olderRaw, true); err != nil {
			t.Fatal(err)
		}

		changed, err := SyncNativeTokenIfFresher(ctx, st, now)
		if err != nil {
			t.Fatalf("SyncNativeTokenIfFresher(older) error = %v", err)
		}
		if changed {
			t.Fatalf("changed = true for older token, want false")
		}
		afterOlder, _ := st.Load(ctx)
		if afterOlder.Accounts["alice@example.com"].Creds.AccessToken != "current-at" {
			t.Fatalf("older native token overwrote fresher stored token: %+v", afterOlder.Accounts["alice@example.com"].Creds)
		}

		unmanagedRaw, err := oauth.EncodeAgyTokenFile("stranger@example.com", domain.AccountCredentials{
			AccessToken:  "stranger-at",
			RefreshToken: "stranger-rt",
			Expiry:       now.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := platform.WriteFileAtomic(st.Paths().NativeAgyTokenPath(), unmanagedRaw, true); err != nil {
			t.Fatal(err)
		}

		changed, err = SyncNativeTokenIfFresher(ctx, st, now)
		if err != nil {
			t.Fatalf("SyncNativeTokenIfFresher(unmanaged) error = %v", err)
		}
		if changed {
			t.Fatalf("changed = true for unmanaged account, want false")
		}
		afterUnmanaged, _ := st.Load(ctx)
		if _, exists := afterUnmanaged.Accounts["stranger@example.com"]; exists || len(afterUnmanaged.Accounts) != 1 {
			t.Fatalf("unmanaged account auto-imported unexpectedly: %+v", afterUnmanaged.Accounts)
		}
	})
}

func TestRefreshAndFetchAllUsesValidTokenWithinSkewWhenClientIDMissing(t *testing.T) {
	st := newQuotaTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	_, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.Accounts["skew@example.com"] = domain.Account{
			Key:    "skew@example.com",
			Email:  "skew@example.com",
			Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now.Add(-time.Hour)},
			Creds: domain.AccountCredentials{
				AccessToken:  "still-valid-at",
				RefreshToken: "rt-skew",
				Expiry:       now.Add(2 * time.Minute),
			},
			AddedAt: now.Add(-24 * time.Hour),
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	oauthClient := &stubOAuthClient{
		refreshFn: func(_ context.Context, creds domain.AccountCredentials, _ time.Duration, _ time.Time) (domain.AccountCredentials, bool, error) {
			return creds, false, oauth.ErrMissingClientID
		},
	}
	fetcher := &stubFetcher{
		fetchFn: func(_ context.Context, token string, opts FetchOptions) (domain.QuotaSnapshot, error) {
			if token != "still-valid-at" {
				return domain.QuotaSnapshot{}, fmt.Errorf("unexpected token %q", token)
			}
			return domain.QuotaSnapshot{
				FetchedAt: opts.Now,
				Source:    domain.QuotaSourceSummary,
				Tier:      domain.TierPro,
				Buckets: []domain.QuotaBucket{
					{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.55},
				},
			}, nil
		},
	}

	results, err := RefreshAndFetchAll(ctx, st, oauthClient, fetcher, nil, FetchOptions{Now: now})
	if err != nil {
		t.Fatalf("RefreshAndFetchAll() error = %v", err)
	}
	if len(results) != 1 || results[0].Err != nil || results[0].Snapshot == nil {
		t.Fatalf("unexpected results for token valid within skew: %+v", results)
	}
	if got := results[0].Snapshot.Buckets[0].RemainingFraction; got != 0.55 {
		t.Fatalf("remaining = %v, want 0.55", got)
	}
}
