package quota

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/oauth"
	"github.com/tuannt/multi-anti/internal/platform"
	"github.com/tuannt/multi-anti/internal/store"
)

const maxConcurrentFetches = 4

// ErrUnauthorized indicates the CloudCode PA endpoint rejected the bearer access token (HTTP 401).
var ErrUnauthorized = errors.New("cloudcode unauthorized")

// FetchOptions configures a single quota fetch operation.
type FetchOptions struct {
	IncludeModels bool
	Now           time.Time
}

// QuotaFetcher fetches a normalized QuotaSnapshot for a single account access token.
type QuotaFetcher interface {
	Fetch(ctx context.Context, accessToken string, opts FetchOptions) (domain.QuotaSnapshot, error)
}

// FetcherConfig overrides CloudCodeFetcher endpoints, HTTP client, or User-Agent.
type FetcherConfig struct {
	Endpoints  []string
	HTTPClient *http.Client
	UserAgent  string
}

// CloudCodeFetcher implements QuotaFetcher against Google's CloudCode PA v1internal APIs.
type CloudCodeFetcher struct {
	endpoints  []string
	httpClient *http.Client
	userAgent  string
}

// NewCloudCodeFetcher returns a CloudCodeFetcher with defaults applied for omitted config fields.
func NewCloudCodeFetcher(cfg FetcherConfig) *CloudCodeFetcher {
	endpoints := slices.Clone(cfg.Endpoints)
	if len(endpoints) == 0 {
		endpoints = slices.Clone(DefaultEndpoints)
	}
	for i, ep := range endpoints {
		endpoints[i] = strings.TrimRight(strings.TrimSpace(ep), "/")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = NewCloudCodeHTTPClient(30 * time.Second)
	}
	ua := strings.TrimSpace(cfg.UserAgent)
	if ua == "" {
		ua = DefaultUserAgent()
	}
	return &CloudCodeFetcher{
		endpoints:  endpoints,
		httpClient: client,
		userAgent:  ua,
	}
}

// Fetch queries loadCodeAssist, retrieveUserQuotaSummary, and (when needed) fetchAvailableModels.
func (f *CloudCodeFetcher) Fetch(ctx context.Context, accessToken string, opts FetchOptions) (domain.QuotaSnapshot, error) {
	token := strings.TrimSpace(accessToken)
	if token == "" {
		return domain.QuotaSnapshot{}, fmt.Errorf("%w: empty access token", ErrUnauthorized)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	assistBody, usedEndpoint, err := f.loadCodeAssist(ctx, token)
	if err != nil {
		return domain.QuotaSnapshot{}, err
	}

	snap := domain.QuotaSnapshot{
		FetchedAt:      now,
		EndpointHost:   endpointHost(usedEndpoint),
		Tier:           assistBody.tier,
		RawCurrentTier: assistBody.rawCurrentTier,
		RawPaidTier:    assistBody.rawPaidTier,
		ProjectID:      assistBody.projectID,
		Credits:        assistBody.credits,
	}

	orderedEndpoints := prioritizeEndpoint(f.endpoints, usedEndpoint)

	buckets, forbidden, summaryEndpoint, err := f.retrieveUserQuotaSummary(ctx, orderedEndpoints, token, assistBody.projectID)
	if err != nil {
		return domain.QuotaSnapshot{}, err
	}
	if summaryEndpoint != "" {
		snap.EndpointHost = endpointHost(summaryEndpoint)
		orderedEndpoints = prioritizeEndpoint(orderedEndpoints, summaryEndpoint)
	}
	snap.SummaryForbidden = forbidden
	snap.Buckets = buckets

	if forbidden || len(buckets) == 0 || opts.IncludeModels {
		models, modelsEndpoint, err := f.fetchAvailableModels(ctx, orderedEndpoints, token, assistBody.projectID)
		if err != nil {
			return domain.QuotaSnapshot{}, err
		}
		if modelsEndpoint != "" && snap.EndpointHost == "" {
			snap.EndpointHost = endpointHost(modelsEndpoint)
		}
		snap.Models = models
	}

	if len(snap.Buckets) > 0 {
		snap.Source = domain.QuotaSourceSummary
	} else {
		snap.Source = domain.QuotaSourceModels
	}
	return snap, nil
}

type parsedLoadCodeAssist struct {
	projectID      string
	rawCurrentTier string
	rawPaidTier    string
	tier           domain.SubscriptionTier
	credits        []domain.CreditInfo
}

func (f *CloudCodeFetcher) loadCodeAssist(ctx context.Context, token string) (parsedLoadCodeAssist, string, error) {
	payload := map[string]any{
		"metadata": map[string]string{
			"ideType": "ANTIGRAVITY",
		},
	}
	status, body, usedEP, err := f.postWithFallback(ctx, f.endpoints, "/v1internal:loadCodeAssist", token, payload)
	if err != nil {
		return parsedLoadCodeAssist{}, "", fmt.Errorf("loadCodeAssist: %w", err)
	}
	if status != http.StatusOK {
		return parsedLoadCodeAssist{}, "", httpStatusError("loadCodeAssist", status, body)
	}

	var resp struct {
		Project          json.RawMessage `json:"cloudaicompanionProject"`
		CurrentTier      json.RawMessage `json:"currentTier"`
		PaidTier         json.RawMessage `json:"paidTier"`
		AvailableCredits []struct {
			CreditType   string          `json:"creditType"`
			CreditAmount json.RawMessage `json:"creditAmount"`
			Amount       json.RawMessage `json:"amount"`
			Remaining    json.RawMessage `json:"remaining"`
			Provider     string          `json:"provider"`
			Unit         string          `json:"unit"`
		} `json:"availableCredits"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return parsedLoadCodeAssist{}, "", fmt.Errorf("parse loadCodeAssist response: %w", err)
	}

	rawCurrent := extractIDField(resp.CurrentTier)
	rawPaid := extractIDField(resp.PaidTier)

	var credits []domain.CreditInfo
	for _, c := range resp.AvailableCredits {
		provider := strings.TrimSpace(c.CreditType)
		if provider == "" {
			provider = strings.TrimSpace(c.Provider)
		}
		remaining := parseFlexibleFloat(c.CreditAmount, c.Remaining, c.Amount)
		credits = append(credits, domain.CreditInfo{
			Provider:  provider,
			Remaining: remaining,
			Unit:      strings.TrimSpace(c.Unit),
		})
	}

	return parsedLoadCodeAssist{
		projectID:      extractIDField(resp.Project),
		rawCurrentTier: rawCurrent,
		rawPaidTier:    rawPaid,
		tier:           resolveSubscriptionTier(rawPaid, rawCurrent),
		credits:        credits,
	}, usedEP, nil
}

func (f *CloudCodeFetcher) retrieveUserQuotaSummary(
	ctx context.Context,
	endpoints []string,
	token string,
	projectID string,
) (buckets []domain.QuotaBucket, forbidden bool, usedEndpoint string, err error) {
	status, body, usedEP, err := f.postWithProjectRetry(ctx, endpoints, "/v1internal:retrieveUserQuotaSummary", token, projectID)
	if err != nil {
		return nil, false, "", fmt.Errorf("retrieveUserQuotaSummary: %w", err)
	}
	if status == http.StatusForbidden {
		return nil, true, usedEP, nil
	}
	if status != http.StatusOK {
		return nil, false, usedEP, httpStatusError("retrieveUserQuotaSummary", status, body)
	}

	var resp struct {
		Buckets      []rawSummaryBucket `json:"buckets"`
		QuotaBuckets []rawSummaryBucket `json:"quotaBuckets"`
		Groups       []rawSummaryGroup  `json:"groups"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, false, usedEP, fmt.Errorf("parse retrieveUserQuotaSummary response: %w", err)
	}

	entries := flattenSummaryBuckets(resp.Buckets, resp.QuotaBuckets, resp.Groups)
	for _, entry := range entries {
		b := entry.bucket
		if b.Disabled {
			continue
		}
		groupID := firstNonEmptyStr(b.BucketID, b.BucketIDSnake, b.GroupID, b.GroupIDSnake, b.QuotaGroupID, b.ModelGroup, b.ID, entry.parentID)
		displayName := firstNonEmptyStr(b.DisplayName, b.DisplayNameSnake, entry.parentLabel)
		resetTimeStr := firstNonEmptyStr(b.ResetTime, b.ResetTimeSnake)
		resetAt, parseErr := parseOptionalTime(resetTimeStr)
		if parseErr != nil {
			return nil, false, usedEP, fmt.Errorf("parse bucket %q resetTime: %w", groupID, parseErr)
		}

		remPtr := b.RemainingFraction
		if remPtr == nil {
			remPtr = b.RemainingFractionSnake
		}
		remaining := resolveRemainingFraction(remPtr, resetTimeStr)

		pool := mapGroupToPool(groupID, displayName)
		if pool == domain.PoolOther {
			pool = mapGroupToPool(entry.parentID, entry.parentLabel)
		}

		buckets = append(buckets, domain.QuotaBucket{
			GroupID:           groupID,
			DisplayName:       displayName,
			Pool:              pool,
			Window:            mapGroupToWindow(b.Window, groupID, displayName),
			RemainingFraction: remaining,
			ResetAt:           resetAt,
		})
	}
	return buckets, false, usedEP, nil
}

type summaryBucketEntry struct {
	bucket      rawSummaryBucket
	parentID    string
	parentLabel string
}

func flattenSummaryBuckets(buckets, quotaBuckets []rawSummaryBucket, groups []rawSummaryGroup) []summaryBucketEntry {
	flat := buckets
	if len(flat) == 0 {
		flat = quotaBuckets
	}
	if len(flat) > 0 {
		entries := make([]summaryBucketEntry, 0, len(flat))
		for _, b := range flat {
			entries = append(entries, summaryBucketEntry{bucket: b})
		}
		return entries
	}

	var entries []summaryBucketEntry
	for _, g := range groups {
		nested := g.Buckets
		if len(nested) == 0 {
			nested = g.QuotaBuckets
		}
		if len(nested) == 0 {
			entries = append(entries, summaryBucketEntry{bucket: g.rawSummaryBucket})
			continue
		}
		if g.Disabled {
			continue
		}
		parentID := firstNonEmptyStr(g.BucketID, g.BucketIDSnake, g.GroupID, g.GroupIDSnake, g.QuotaGroupID, g.ModelGroup, g.ID)
		parentLabel := firstNonEmptyStr(g.DisplayName, g.DisplayNameSnake)
		for _, b := range nested {
			entries = append(entries, summaryBucketEntry{
				bucket:      b,
				parentID:    parentID,
				parentLabel: parentLabel,
			})
		}
	}
	return entries
}

type rawSummaryGroup struct {
	rawSummaryBucket
	Buckets      []rawSummaryBucket `json:"buckets"`
	QuotaBuckets []rawSummaryBucket `json:"quotaBuckets"`
}

type rawSummaryBucket struct {
	BucketID               string   `json:"bucketId"`
	BucketIDSnake          string   `json:"bucket_id"`
	GroupID                string   `json:"groupId"`
	GroupIDSnake           string   `json:"group_id"`
	QuotaGroupID           string   `json:"quotaGroupId"`
	ModelGroup             string   `json:"modelGroup"`
	ID                     string   `json:"id"`
	DisplayName            string   `json:"displayName"`
	DisplayNameSnake       string   `json:"display_name"`
	Window                 string   `json:"window"`
	RemainingFraction      *float64 `json:"remainingFraction"`
	RemainingFractionSnake *float64 `json:"remaining_fraction"`
	ResetTime              string   `json:"resetTime"`
	ResetTimeSnake         string   `json:"reset_time"`
	Disabled               bool     `json:"disabled"`
}

func (f *CloudCodeFetcher) fetchAvailableModels(
	ctx context.Context,
	endpoints []string,
	token string,
	projectID string,
) (models []domain.ModelQuota, usedEndpoint string, err error) {
	status, body, usedEP, err := f.postWithProjectRetry(ctx, endpoints, "/v1internal:fetchAvailableModels", token, projectID)
	if err != nil {
		return nil, "", fmt.Errorf("fetchAvailableModels: %w", err)
	}
	if status != http.StatusOK {
		return nil, usedEP, httpStatusError("fetchAvailableModels", status, body)
	}

	var resp struct {
		Models map[string]struct {
			DisplayName      string `json:"displayName"`
			IsInternal       bool   `json:"isInternal"`
			SupportsThinking bool   `json:"supportsThinking"`
			QuotaInfo        *struct {
				RemainingFraction *float64 `json:"remainingFraction"`
				ResetTime         string   `json:"resetTime"`
			} `json:"quotaInfo"`
			RemainingFraction *float64 `json:"remainingFraction"`
			ResetTime         string   `json:"resetTime"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, usedEP, fmt.Errorf("parse fetchAvailableModels response: %w", err)
	}

	for modelID, entry := range resp.Models {
		if entry.IsInternal || strings.HasPrefix(strings.ToLower(modelID), "chat_") {
			continue
		}

		var remPtr *float64
		var resetStr string
		hasQuotaBlock := entry.QuotaInfo != nil
		if entry.QuotaInfo != nil {
			remPtr = entry.QuotaInfo.RemainingFraction
			resetStr = entry.QuotaInfo.ResetTime
		} else if entry.RemainingFraction != nil || strings.TrimSpace(entry.ResetTime) != "" {
			hasQuotaBlock = true
			remPtr = entry.RemainingFraction
			resetStr = entry.ResetTime
		}
		if !hasQuotaBlock {
			continue
		}

		resetAt, parseErr := parseOptionalTime(resetStr)
		if parseErr != nil {
			return nil, usedEP, fmt.Errorf("parse model %q resetTime: %w", modelID, parseErr)
		}

		models = append(models, domain.ModelQuota{
			ModelID:           modelID,
			DisplayName:       strings.TrimSpace(entry.DisplayName),
			RemainingFraction: resolveRemainingFraction(remPtr, resetStr),
			ResetAt:           resetAt,
			SupportsThinking:  entry.SupportsThinking,
		})
	}

	slices.SortFunc(models, func(a, b domain.ModelQuota) int {
		return strings.Compare(a.ModelID, b.ModelID)
	})
	return models, usedEP, nil
}

func (f *CloudCodeFetcher) postWithProjectRetry(
	ctx context.Context,
	endpoints []string,
	path string,
	token string,
	projectID string,
) (int, []byte, string, error) {
	payload := map[string]any{}
	if strings.TrimSpace(projectID) != "" {
		payload["project"] = projectID
	}
	status, body, usedEP, err := f.postWithFallback(ctx, endpoints, path, token, payload)
	if err != nil {
		return 0, nil, usedEP, err
	}
	if status == http.StatusForbidden && strings.TrimSpace(projectID) != "" {
		return f.postWithFallback(ctx, prioritizeEndpoint(endpoints, usedEP), path, token, map[string]any{})
	}
	return status, body, usedEP, nil
}

func (f *CloudCodeFetcher) postWithFallback(
	ctx context.Context,
	endpoints []string,
	path string,
	token string,
	payload any,
) (status int, body []byte, usedEndpoint string, err error) {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, "", err
	}

	var lastErr error
	for i, base := range endpoints {
		reqURL := base + path
		status, body, reqErr := f.doJSONPost(ctx, reqURL, token, rawPayload)
		if reqErr != nil {
			if ctx.Err() != nil {
				return 0, nil, base, ctx.Err()
			}
			lastErr = reqErr
			if i < len(endpoints)-1 {
				continue
			}
			return 0, nil, base, reqErr
		}

		if shouldFallbackStatus(status) && i < len(endpoints)-1 {
			lastErr = httpStatusError(path, status, body)
			continue
		}
		return status, body, base, nil
	}
	if lastErr != nil {
		return 0, nil, "", lastErr
	}
	return 0, nil, "", errors.New("no CloudCode endpoints configured")
}

func (f *CloudCodeFetcher) doJSONPost(ctx context.Context, reqURL, token string, rawPayload []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(rawPayload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

func shouldFallbackStatus(status int) bool {
	return status == http.StatusTooManyRequests ||
		status == http.StatusNotFound ||
		(status >= 500 && status <= 599)
}

func httpStatusError(op string, status int, body []byte) error {
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 256 {
		snippet = snippet[:256]
	}
	if status == http.StatusUnauthorized {
		return fmt.Errorf("%s %w (HTTP 401): %s", op, ErrUnauthorized, snippet)
	}
	return fmt.Errorf("%s HTTP %d: %s", op, status, snippet)
}

// AccountRefreshResult captures the outcome for one account processed by RefreshAndFetchAll.
type AccountRefreshResult struct {
	Key           domain.AccountKey
	RefreshedAuth bool
	Snapshot      *domain.QuotaSnapshot
	Health        domain.AccountHealth
	Err           error
}

// RefreshAndFetchAll refreshes expiring credentials under RefreshLockFile, fetches quotas with
// up to 4 concurrent workers, and persists updated credentials, QuotaSnapshots, and health transitions.
func RefreshAndFetchAll(
	ctx context.Context,
	st store.Store,
	oauthClient oauth.OAuthClient,
	fetcher QuotaFetcher,
	keys []domain.AccountKey,
	opts FetchOptions,
) ([]AccountRefreshResult, error) {
	if st == nil {
		return nil, errors.New("refresh and fetch: nil store")
	}
	if fetcher == nil {
		return nil, errors.New("refresh and fetch: nil fetcher")
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	_, _ = SyncNativeTokenIfFresher(ctx, st, now)

	initialState, err := st.Load(ctx)
	if err != nil {
		return nil, err
	}

	targetKeys := selectTargetKeys(initialState, keys)
	if len(targetKeys) == 0 {
		return nil, nil
	}

	skew := initialState.Policy.RefreshSkew
	results := make([]AccountRefreshResult, len(targetKeys))
	type job struct {
		idx int
		key domain.AccountKey
	}

	jobs := make(chan job, len(targetKeys))
	for i, k := range targetKeys {
		jobs <- job{idx: i, key: k}
	}
	close(jobs)

	workers := min(maxConcurrentFetches, len(targetKeys))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results[j.idx] = processSingleAccount(ctx, st, oauthClient, fetcher, initialState, j.key, skew, now, opts)
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		return results, ctx.Err()
	}

	finalState, err := st.Update(ctx, func(s *domain.StoreState) error {
		for i := range results {
			res := &results[i]
			acc, ok := s.Accounts[res.Key]
			if !ok {
				continue
			}

			if acc.Health.Status == domain.HealthCooldown && acc.Health.EffectiveStatus(now) == domain.HealthReady {
				acc.Health = domain.AccountHealth{
					Status:    domain.HealthReady,
					UpdatedAt: now,
				}
			}

			if errors.Is(res.Err, oauth.ErrRefreshRevoked) || errors.Is(res.Err, ErrUnauthorized) {
				acc.Health = domain.AccountHealth{
					Status:    domain.HealthNeedsReauth,
					Reason:    res.Err.Error(),
					UpdatedAt: now,
				}
			} else if res.Snapshot != nil {
				snapCopy := *res.Snapshot
				snapCopy.FetchError = ""
				acc.Quota = &snapCopy
				if acc.Health.Status == domain.HealthNeedsReauth {
					acc.Health = domain.AccountHealth{
						Status:    domain.HealthReady,
						UpdatedAt: now,
					}
				}
			} else if res.Err != nil {
				if acc.Quota != nil {
					qCopy := *acc.Quota
					qCopy.FetchError = res.Err.Error()
					acc.Quota = &qCopy
				} else {
					acc.Quota = &domain.QuotaSnapshot{
						FetchedAt:  now,
						Tier:       domain.TierUnknown,
						FetchError: res.Err.Error(),
					}
				}
			}

			res.Health = acc.Health
			s.Accounts[res.Key] = acc
		}
		return nil
	})
	if err != nil {
		return results, err
	}

	for i := range results {
		if acc, ok := finalState.Accounts[results[i].Key]; ok {
			results[i].Health = acc.Health
		}
	}
	return results, nil
}

func processSingleAccount(
	ctx context.Context,
	st store.Store,
	oauthClient oauth.OAuthClient,
	fetcher QuotaFetcher,
	initialState domain.StoreState,
	key domain.AccountKey,
	skew time.Duration,
	now time.Time,
	opts FetchOptions,
) AccountRefreshResult {
	res := AccountRefreshResult{Key: key}
	acc, ok := initialState.Accounts[key]
	if !ok {
		res.Err = fmt.Errorf("account %q not found", key)
		return res
	}
	res.Health = acc.Health

	creds := acc.Creds
	if oauth.NeedsRefresh(creds, skew, now) {
		if oauthClient == nil {
			res.Err = errors.New("oauth client required to refresh expired token")
			return res
		}
		refreshedCreds, didRefresh, _, err := RefreshAccountToken(ctx, st, oauthClient, key, skew, now, RefreshIfExpiring)
		if err != nil {
			if errors.Is(err, oauth.ErrMissingClientID) && strings.TrimSpace(creds.AccessToken) != "" && creds.Expiry.After(now) {
				// Access token is still valid within refresh_skew; proceed to fetch live quota with it.
			} else {
				res.Err = err
				return res
			}
		} else {
			creds = refreshedCreds
			res.RefreshedAuth = didRefresh
		}
	}

	snap, err := fetcher.Fetch(ctx, creds.AccessToken, opts)
	if err != nil && errors.Is(err, ErrUnauthorized) && oauthClient != nil && strings.TrimSpace(creds.RefreshToken) != "" {
		refreshedCreds, didRefresh, _, refreshErr := RefreshAccountToken(ctx, st, oauthClient, key, skew, now, RefreshForced)
		if refreshErr != nil {
			res.Err = refreshErr
			return res
		}
		if didRefresh {
			res.RefreshedAuth = true
			creds = refreshedCreds
			snap, err = fetcher.Fetch(ctx, creds.AccessToken, opts)
		}
	}
	if err != nil {
		res.Err = err
		return res
	}

	res.Snapshot = &snap
	return res
}

// RefreshMode controls whether RefreshAccountToken refreshes only expiring tokens or forces a refresh.
type RefreshMode int

const (
	RefreshIfExpiring RefreshMode = iota
	RefreshForced
)

// RefreshAccountToken serializes OAuth refresh under RefreshLockFile, persists updated credentials
// or HealthNeedsReauth transitions in st, and returns the resulting credentials.
func RefreshAccountToken(
	ctx context.Context,
	st store.Store,
	oauthClient oauth.OAuthClient,
	key domain.AccountKey,
	skew time.Duration,
	now time.Time,
	mode RefreshMode,
) (creds domain.AccountCredentials, didRefresh bool, revoked bool, err error) {
	err = platform.WithFileLock(ctx, st.Paths().RefreshLockFile(), false, func() error {
		latest, loadErr := st.Load(ctx)
		if loadErr != nil {
			return loadErr
		}
		acc, ok := latest.Accounts[key]
		if !ok {
			return fmt.Errorf("account %q not found", key)
		}

		credsToRefresh := acc.Creds
		if mode == RefreshForced {
			credsToRefresh.Expiry = time.Time{}
		}

		updatedCreds, refreshed, refreshErr := oauthClient.Refresh(ctx, credsToRefresh, skew, now)
		if refreshErr != nil {
			if errors.Is(refreshErr, oauth.ErrRefreshRevoked) {
				revoked = true
				_, _ = st.Update(ctx, func(s *domain.StoreState) error {
					if a, exists := s.Accounts[key]; exists {
						a.Health = domain.AccountHealth{
							Status:    domain.HealthNeedsReauth,
							Reason:    refreshErr.Error(),
							UpdatedAt: now,
						}
						s.Accounts[key] = a
					}
					return nil
				})
			}
			return refreshErr
		}

		creds = updatedCreds
		didRefresh = refreshed
		if !refreshed {
			return nil
		}

		_, updErr := st.Update(ctx, func(s *domain.StoreState) error {
			a, exists := s.Accounts[key]
			if !exists {
				return nil
			}
			a.Creds = updatedCreds
			if a.Health.Status == domain.HealthNeedsReauth {
				a.Health = domain.AccountHealth{
					Status:    domain.HealthReady,
					UpdatedAt: now,
				}
			}
			s.Accounts[key] = a
			return nil
		})
		return updErr
	})
	return creds, didRefresh, revoked, err
}

var errNativeTokenNotFresher = errors.New("native token not fresher")

// TokenSyncOptions controls how a token file written by agy is synchronized into the store.
type TokenSyncOptions struct {
	ExpectedEmail string
	SetActive     bool
	RecordUsed    bool
	Now           time.Time
}

// UpsertTokenFromFile enrolls a new account or updates fresher credentials from tokenPath into st.
func UpsertTokenFromFile(ctx context.Context, st store.Store, tokenPath string, opts TokenSyncOptions) (domain.AccountKey, bool, error) {
	if st == nil || strings.TrimSpace(tokenPath) == "" {
		return "", false, nil
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", false, nil
	}
	decodedID, decodedCreds, err := oauth.DecodeAgyTokenFile(raw)
	if err != nil {
		return "", false, nil
	}
	if !tokenIdentityMatchesExpectedEmail(decodedID, opts.ExpectedEmail) {
		return "", false, nil
	}

	state, err := st.Load(ctx)
	if err != nil {
		return "", false, err
	}
	if targetKey, cur, exists := findManagedAccountByIdentity(state, decodedID); exists {
		if !accountNeedsTokenSync(cur, decodedID, decodedCreds, state.ActiveKey, opts, now) {
			return targetKey, false, nil
		}
	}

	var resultKey domain.AccountKey
	changed := false
	_, updErr := st.Update(ctx, func(s *domain.StoreState) error {
		k, acc, exists := findManagedAccountByIdentity(*s, decodedID)
		if !exists {
			resultKey = decodedID.Key
			newAcc := domain.Account{
				Key:         decodedID.Key,
				Email:       strings.TrimSpace(decodedID.Email),
				AccountID:   strings.TrimSpace(decodedID.AccountID),
				DisplayName: strings.TrimSpace(decodedID.DisplayName),
				Health: domain.AccountHealth{
					Status:    domain.HealthReady,
					UpdatedAt: now,
				},
				Creds:   decodedCreds,
				AddedAt: now,
			}
			if opts.RecordUsed {
				usedAt := now
				newAcc.LastUsedAt = &usedAt
			}
			if s.Accounts == nil {
				s.Accounts = make(map[domain.AccountKey]domain.Account)
			}
			s.Accounts[decodedID.Key] = newAcc
			if opts.SetActive || s.ActiveKey == "" {
				s.ActiveKey = decodedID.Key
			}
			changed = true
			return nil
		}

		resultKey = k
		if !accountNeedsTokenSync(acc, decodedID, decodedCreds, s.ActiveKey, opts, now) {
			return errNativeTokenNotFresher
		}
		if isNativeCredsFresher(acc.Creds, decodedCreds) {
			mergeNativeCreds(&acc, decodedCreds, now)
		} else if acc.Health.Status == domain.HealthNeedsReauth && !oauth.NeedsRefresh(decodedCreds, 0, now) {
			acc.Health = domain.AccountHealth{
				Status:    domain.HealthReady,
				UpdatedAt: now,
			}
			if acc.Quota != nil && acc.Quota.FetchError != "" {
				qCopy := *acc.Quota
				qCopy.FetchError = ""
				acc.Quota = &qCopy
			}
		}
		if acc.Email == "" && strings.TrimSpace(decodedID.Email) != "" {
			acc.Email = strings.TrimSpace(decodedID.Email)
		}
		if acc.AccountID == "" && strings.TrimSpace(decodedID.AccountID) != "" {
			acc.AccountID = strings.TrimSpace(decodedID.AccountID)
		}
		if acc.DisplayName == "" && strings.TrimSpace(decodedID.DisplayName) != "" {
			acc.DisplayName = strings.TrimSpace(decodedID.DisplayName)
		}
		if opts.RecordUsed && (acc.LastUsedAt == nil || !acc.LastUsedAt.Equal(now)) {
			usedAt := now
			acc.LastUsedAt = &usedAt
		}
		s.Accounts[k] = acc
		if opts.SetActive {
			s.ActiveKey = k
		}
		changed = true
		return nil
	})
	if errors.Is(updErr, errNativeTokenNotFresher) {
		return resultKey, false, nil
	}
	if updErr != nil {
		return "", false, updErr
	}
	return resultKey, changed, nil
}

// ClearActiveKeyIfLoggedOut clears ActiveKey while preserving all stored accounts
// when the native token file has been deleted (for example by agy /logout).
func ClearActiveKeyIfLoggedOut(ctx context.Context, st store.Store, tokenPath string, onlyIfActiveKey domain.AccountKey) (bool, error) {
	if st == nil || strings.TrimSpace(tokenPath) == "" {
		return false, nil
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		return false, nil
	}

	state, err := st.Load(ctx)
	if err != nil {
		return false, err
	}
	if state.ActiveKey == "" || (onlyIfActiveKey != "" && state.ActiveKey != onlyIfActiveKey) {
		return false, nil
	}

	cleared := false
	_, updErr := st.Update(ctx, func(s *domain.StoreState) error {
		if _, statErr := os.Stat(tokenPath); !os.IsNotExist(statErr) {
			return errNativeTokenNotFresher
		}
		if s.ActiveKey == "" || (onlyIfActiveKey != "" && s.ActiveKey != onlyIfActiveKey) {
			return errNativeTokenNotFresher
		}
		s.ActiveKey = ""
		cleared = true
		return nil
	})
	if errors.Is(updErr, errNativeTokenNotFresher) {
		return false, nil
	}
	if updErr != nil {
		return false, updErr
	}
	return cleared, nil
}

// SyncNativeTokenIfFresher imports fresher credentials written by agy into NativeAgyTokenPath()
// for an already managed account before multi-anti overwrites the staged token or renders state.
func SyncNativeTokenIfFresher(ctx context.Context, st store.Store, now time.Time) (bool, error) {
	if st == nil {
		return false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	raw, err := os.ReadFile(st.Paths().NativeAgyTokenPath())
	if err != nil {
		return false, nil
	}
	decodedID, decodedCreds, err := oauth.DecodeAgyTokenFile(raw)
	if err != nil {
		return false, nil
	}

	state, err := st.Load(ctx)
	if err != nil || len(state.Accounts) == 0 {
		return false, err
	}
	targetKey, cur, ok := findManagedAccountByIdentity(state, decodedID)
	if !ok || !isNativeCredsFresher(cur.Creds, decodedCreds) {
		return false, nil
	}

	changed := false
	_, updErr := st.Update(ctx, func(s *domain.StoreState) error {
		k, acc, exists := findManagedAccountByIdentity(*s, decodedID)
		if !exists {
			return errNativeTokenNotFresher
		}
		targetKey = k
		if !isNativeCredsFresher(acc.Creds, decodedCreds) {
			return errNativeTokenNotFresher
		}

		mergeNativeCreds(&acc, decodedCreds, now)
		s.Accounts[targetKey] = acc
		changed = true
		return nil
	})
	if errors.Is(updErr, errNativeTokenNotFresher) {
		return false, nil
	}
	if updErr != nil {
		return false, updErr
	}
	return changed, nil
}

func tokenIdentityMatchesExpectedEmail(id domain.AccountIdentity, expectedEmail string) bool {
	wantEmail := strings.TrimSpace(expectedEmail)
	if wantEmail == "" {
		return true
	}
	if e := strings.TrimSpace(id.Email); e != "" && strings.EqualFold(e, wantEmail) {
		return true
	}
	wantKey, err := domain.NormalizeAccountKey(wantEmail, "")
	return err == nil && id.Key == wantKey
}

func accountNeedsTokenSync(
	acc domain.Account,
	decodedID domain.AccountIdentity,
	decodedCreds domain.AccountCredentials,
	activeKey domain.AccountKey,
	opts TokenSyncOptions,
	now time.Time,
) bool {
	if isNativeCredsFresher(acc.Creds, decodedCreds) {
		return true
	}
	if acc.Health.Status == domain.HealthNeedsReauth && !oauth.NeedsRefresh(decodedCreds, 0, now) {
		return true
	}
	if (acc.Email == "" && strings.TrimSpace(decodedID.Email) != "") ||
		(acc.AccountID == "" && strings.TrimSpace(decodedID.AccountID) != "") ||
		(acc.DisplayName == "" && strings.TrimSpace(decodedID.DisplayName) != "") {
		return true
	}
	if opts.SetActive && activeKey != acc.Key {
		return true
	}
	if opts.RecordUsed && (acc.LastUsedAt == nil || !acc.LastUsedAt.Equal(now)) {
		return true
	}
	return false
}

func mergeNativeCreds(acc *domain.Account, decodedCreds domain.AccountCredentials, now time.Time) {
	merged := decodedCreds
	if strings.TrimSpace(merged.ClientID) == "" {
		merged.ClientID = acc.Creds.ClientID
	}
	if strings.TrimSpace(merged.RefreshToken) == "" {
		merged.RefreshToken = acc.Creds.RefreshToken
	}
	if strings.TrimSpace(merged.IDToken) == "" {
		merged.IDToken = acc.Creds.IDToken
	}
	acc.Creds = merged
	if acc.Health.Status == domain.HealthNeedsReauth {
		acc.Health = domain.AccountHealth{
			Status:    domain.HealthReady,
			UpdatedAt: now,
		}
	}
	if acc.Quota != nil && acc.Quota.FetchError != "" && !oauth.NeedsRefresh(merged, 0, now) {
		qCopy := *acc.Quota
		qCopy.FetchError = ""
		acc.Quota = &qCopy
	}
}

func findManagedAccountByIdentity(state domain.StoreState, id domain.AccountIdentity) (domain.AccountKey, domain.Account, bool) {
	if acc, ok := state.Accounts[id.Key]; ok {
		return id.Key, acc, true
	}
	if email := strings.TrimSpace(id.Email); email != "" {
		for k, acc := range state.Accounts {
			if strings.EqualFold(strings.TrimSpace(acc.Email), email) {
				return k, acc, true
			}
		}
	}
	return "", domain.Account{}, false
}

func isNativeCredsFresher(cur, candidate domain.AccountCredentials) bool {
	candAT := strings.TrimSpace(candidate.AccessToken)
	curAT := strings.TrimSpace(cur.AccessToken)
	if candAT != "" && curAT == "" {
		return true
	}
	if candAT != "" && candidate.Expiry.After(cur.Expiry) {
		return true
	}
	candRT := strings.TrimSpace(candidate.RefreshToken)
	curRT := strings.TrimSpace(cur.RefreshToken)
	if candRT != "" && candRT != curRT && !candidate.Expiry.Before(cur.Expiry) {
		return true
	}
	return false
}

// CanStageWithoutRefresh reports whether creds can be staged for agy when OAuth refresh fails or is omitted.
func CanStageWithoutRefresh(creds domain.AccountCredentials, refreshErr error) bool {
	if refreshErr == nil {
		return true
	}
	if errors.Is(refreshErr, oauth.ErrRefreshRevoked) {
		return false
	}
	if strings.TrimSpace(creds.AccessToken) != "" {
		return true
	}
	if errors.Is(refreshErr, oauth.ErrMissingClientID) && strings.TrimSpace(creds.RefreshToken) != "" {
		return true
	}
	return false
}

func selectTargetKeys(state domain.StoreState, keys []domain.AccountKey) []domain.AccountKey {
	if len(keys) > 0 {
		seen := make(map[domain.AccountKey]bool, len(keys))
		out := make([]domain.AccountKey, 0, len(keys))
		for _, k := range keys {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
		return out
	}

	out := make([]domain.AccountKey, 0, len(state.Accounts))
	for k, acc := range state.Accounts {
		if acc.Health.Status == domain.HealthDisabled {
			continue
		}
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func resolveSubscriptionTier(rawPaidTier, rawCurrentTier string) domain.SubscriptionTier {
	// Google often reports currentTier="free-tier" alongside paidTier="g1-pro-tier".
	if t := classifyTierString(rawPaidTier); t != domain.TierUnknown {
		return t
	}
	return classifyTierString(rawCurrentTier)
}

func classifyTierString(raw string) domain.SubscriptionTier {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return domain.TierUnknown
	}
	switch {
	case strings.Contains(lower, "ultra"):
		return domain.TierUltra
	case strings.Contains(lower, "pro"):
		return domain.TierPro
	case strings.Contains(lower, "enterprise") || strings.Contains(lower, "standard"):
		return domain.TierEnterprise
	case strings.Contains(lower, "free") || strings.Contains(lower, "legacy"):
		return domain.TierFree
	default:
		return domain.TierUnknown
	}
}

func mapGroupToPool(groupID, displayName string) domain.QuotaPool {
	for _, s := range []string{groupID, displayName} {
		if pool := domain.ClassifyPool(s); pool != domain.PoolOther {
			return pool
		}
	}
	return domain.PoolOther
}

func mapGroupToWindow(candidates ...string) domain.QuotaWindow {
	for _, s := range candidates {
		if w := domain.ClassifyWindow(s); w != domain.WindowUnknown {
			return w
		}
	}
	return domain.WindowUnknown
}

func resolveRemainingFraction(remPtr *float64, resetTime string) float64 {
	if remPtr != nil {
		return *remPtr
	}
	// Protobuf-JSON omits 0.0 float defaults while keeping resetTime when a bucket or model is exhausted.
	if strings.TrimSpace(resetTime) != "" {
		return 0.0
	}
	return 1.0
}

func parseOptionalTime(raw string) (*time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
		utc := t.UTC()
		return &utc, nil
	}
	if t, err := time.Parse(time.RFC3339, trimmed); err == nil {
		utc := t.UTC()
		return &utc, nil
	}
	return nil, fmt.Errorf("invalid RFC3339 timestamp %q", trimmed)
}

func extractIDField(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return strings.TrimSpace(obj.ID)
	}
	return ""
}

func parseFlexibleFloat(candidates ...json.RawMessage) float64 {
	for _, raw := range candidates {
		trimmed := strings.TrimSpace(string(raw))
		if trimmed == "" || trimmed == "null" {
			continue
		}
		var f float64
		if err := json.Unmarshal(raw, &f); err == nil {
			return f
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func endpointHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.Host != "" {
		return u.Host
	}
	return rawURL
}

func prioritizeEndpoint(endpoints []string, preferred string) []string {
	if preferred == "" {
		return slices.Clone(endpoints)
	}
	out := make([]string, 0, len(endpoints))
	out = append(out, preferred)
	for _, ep := range endpoints {
		if ep != preferred {
			out = append(out, ep)
		}
	}
	return out
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
