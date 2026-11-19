package domain

import (
	"errors"
	"strings"
	"time"
)

// CurrentSchemaVersion is the persisted state.json schema version.
const CurrentSchemaVersion = 1

// ErrMissingIdentity indicates neither an email nor an account ID was supplied.
var ErrMissingIdentity = errors.New("missing account identity: email or account_id required")

// AccountKey uniquely identifies a managed Antigravity account.
type AccountKey string

// NormalizeAccountKey derives a canonical AccountKey from email or accountID.
func NormalizeAccountKey(email, accountID string) (AccountKey, error) {
	if cleanEmail := strings.ToLower(strings.TrimSpace(email)); cleanEmail != "" {
		return AccountKey(cleanEmail), nil
	}
	if cleanID := strings.TrimSpace(accountID); cleanID != "" {
		return AccountKey("id:" + cleanID), nil
	}
	return "", ErrMissingIdentity
}

// AccountIdentity holds the identifying metadata for an account.
type AccountIdentity struct {
	Key         AccountKey `json:"key"`
	Email       string     `json:"email,omitempty"`
	AccountID   string     `json:"account_id,omitempty"`
	DisplayName string     `json:"display_name,omitempty"`
}

// HealthStatus represents the operational state of an account.
type HealthStatus string

const (
	HealthReady       HealthStatus = "ready"
	HealthCooldown    HealthStatus = "cooldown"
	HealthNeedsReauth HealthStatus = "needs_reauth"
	HealthDisabled    HealthStatus = "disabled"
)

// IsValid reports whether s is a recognized HealthStatus value.
func (s HealthStatus) IsValid() bool {
	switch s {
	case HealthReady, HealthCooldown, HealthNeedsReauth, HealthDisabled:
		return true
	default:
		return false
	}
}

// AccountHealth tracks account availability and active cooldown deadlines.
type AccountHealth struct {
	Status        HealthStatus `json:"status"`
	Reason        string       `json:"reason,omitempty"`
	CooldownUntil *time.Time   `json:"cooldown_until,omitempty"`
	UpdatedAt     time.Time    `json:"updated_at,omitzero"`
}

// EffectiveStatus resolves the account status at now, promoting expired cooldowns to ready.
func (h AccountHealth) EffectiveStatus(now time.Time) HealthStatus {
	if h.Status == HealthCooldown && h.CooldownUntil != nil && !now.Before(*h.CooldownUntil) {
		return HealthReady
	}
	return h.Status
}

// CanSelect reports whether the account is eligible for selection at now.
func (h AccountHealth) CanSelect(now time.Time) bool {
	return h.EffectiveStatus(now) == HealthReady
}

// AccountCredentials stores OAuth tokens and client metadata for an account.
type AccountCredentials struct {
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Expiry       time.Time `json:"expiry,omitzero"`
	IDToken      string    `json:"id_token,omitempty"`
	ClientID     string    `json:"client_id,omitempty"`
}

// Account represents a managed Antigravity account and its persisted state.
type Account struct {
	Key         AccountKey         `json:"key"`
	Email       string             `json:"email,omitempty"`
	AccountID   string             `json:"account_id,omitempty"`
	DisplayName string             `json:"display_name,omitempty"`
	Priority    int                `json:"priority,omitempty"`
	Health      AccountHealth      `json:"health"`
	Creds       AccountCredentials `json:"creds"`
	Quota       *QuotaSnapshot     `json:"quota,omitempty"`
	AddedAt     time.Time          `json:"added_at"`
	LastUsedAt  *time.Time         `json:"last_used_at,omitempty"`
}

// NativeBackupRecord captures the original native agy token file state before multi-anti modifies it.
type NativeBackupRecord struct {
	CapturedAt time.Time `json:"captured_at"`
	SourcePath string    `json:"source_path"`
	BackupPath string    `json:"backup_path,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	HadFile    bool      `json:"had_file"`
}

// HookSwitchSignal coordinates an account switch triggered by a Stop hook with the wrapper launcher.
type HookSwitchSignal struct {
	ConversationID string     `json:"conversation_id,omitempty"`
	FromKey        AccountKey `json:"from_key,omitempty"`
	ToKey          AccountKey `json:"to_key"`
	Reason         string     `json:"reason,omitempty"`
	At             time.Time  `json:"at"`
}

// StoreState is the root persistent state saved in state.json.
type StoreState struct {
	SchemaVersion int                    `json:"schema_version"`
	Generation    uint64                 `json:"generation"`
	ActiveKey     AccountKey             `json:"active_key,omitempty"`
	Policy        SelectionPolicy        `json:"policy"`
	Accounts      map[AccountKey]Account `json:"accounts"`
	NativeBackup  *NativeBackupRecord    `json:"native_backup,omitempty"`
	LastSwitch    *SwitchAuditEntry      `json:"last_switch,omitempty"`
}
