package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tuannt/multi-anti/internal/platform"
	"github.com/tuannt/multi-anti/plugin"
)

const (
	pluginName               = "multi-anti"
	statusLineBackupFilename = "statusline.json"
)

var embeddedPluginFiles = []string{
	"plugin.json",
	"hooks.json",
	"assets/logo.svg",
	"skills/multi-anti/SKILL.md",
}

// InstallOptions controls plugin installation behavior.
type InstallOptions struct {
	BinaryCommand string
}

// PluginStatus summarizes the on-disk installation state of the multi-anti plugin and statusLine.
type PluginStatus struct {
	PluginDir         string   `json:"plugin_dir"`
	Installed         bool     `json:"installed"`
	DisabledInConfig  bool     `json:"disabled_in_config"`
	ManifestFile      string   `json:"manifest_file,omitempty"`
	HooksFile         string   `json:"hooks_file,omitempty"`
	StatusLineEnabled bool     `json:"status_line_enabled"`
	StatusLineCommand string   `json:"status_line_command,omitempty"`
	MissingFiles      []string `json:"missing_files,omitempty"`
}

type hookCommandHandler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

type hookPluginSpec struct {
	Enabled      bool                 `json:"enabled"`
	SessionStart []hookCommandHandler `json:"SessionStart,omitempty"`
	Stop         []hookCommandHandler `json:"Stop,omitempty"`
}

type statusLineConfig struct {
	Type             string `json:"type"`
	Command          string `json:"command"`
	StackWithDefault bool   `json:"stack_with_default"`
}

// InstallPlugin writes the embedded plugin bundle into paths.NativePluginDir()
// and ensures config.json does not keep the plugin disabled.
func InstallPlugin(ctx context.Context, paths platform.Paths, opts InstallOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	pluginDir := paths.NativePluginDir()
	for _, rel := range embeddedPluginFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := fs.ReadFile(plugin.FS, rel)
		if err != nil {
			return fmt.Errorf("read embedded plugin file %q: %w", rel, err)
		}
		if rel == "hooks.json" && strings.TrimSpace(opts.BinaryCommand) != "" {
			data, err = rewriteHooksCommands(data, opts.BinaryCommand)
			if err != nil {
				return fmt.Errorf("rewrite plugin hooks.json: %w", err)
			}
		}
		dst := filepath.Join(pluginDir, filepath.FromSlash(rel))
		if err := platform.WriteFileAtomic(dst, data, false); err != nil {
			return fmt.Errorf("write plugin file %q: %w", dst, err)
		}
	}

	return enablePluginInGeminiConfig(paths)
}

// UninstallPlugin removes the installed plugin directory and clears any multi-anti plugin entry in config.json.
func UninstallPlugin(paths platform.Paths) error {
	if err := os.RemoveAll(paths.NativePluginDir()); err != nil {
		return fmt.Errorf("remove plugin dir %q: %w", paths.NativePluginDir(), err)
	}
	return removePluginFromGeminiConfig(paths)
}

// InspectPlugin reports the current installation status of the plugin bundle and statusLine configuration.
func InspectPlugin(paths platform.Paths) (PluginStatus, error) {
	pluginDir := paths.NativePluginDir()
	status := PluginStatus{
		PluginDir: pluginDir,
	}

	for _, rel := range embeddedPluginFiles {
		p := filepath.Join(pluginDir, filepath.FromSlash(rel))
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				status.MissingFiles = append(status.MissingFiles, rel)
				continue
			}
			return PluginStatus{}, fmt.Errorf("stat plugin file %q: %w", p, err)
		}
		switch rel {
		case "plugin.json":
			status.ManifestFile = p
		case "hooks.json":
			status.HooksFile = p
		}
	}
	status.Installed = len(status.MissingFiles) == 0

	disabled, err := isPluginDisabledInConfig(paths)
	if err != nil {
		return PluginStatus{}, err
	}
	status.DisabledInConfig = disabled

	cmdStr, enabled, err := inspectStatusLineSetting(paths)
	if err != nil {
		return PluginStatus{}, err
	}
	status.StatusLineCommand = cmdStr
	status.StatusLineEnabled = enabled

	return status, nil
}

// InstallStatusLine configures agy's settings.json statusLine command, backing up any prior
// non-multi-anti statusLine object once so UninstallStatusLine can restore it.
func InstallStatusLine(paths platform.Paths, binaryCmd string) error {
	settingsPath := paths.NativeAgySettingsPath()
	doc, _, err := readJSONObjectIfExists(settingsPath)
	if err != nil {
		return fmt.Errorf("read settings %q: %w", settingsPath, err)
	}

	if existingRaw, hasExisting := doc["statusLine"]; hasExisting && !isJSONNull(existingRaw) {
		if !isMultiAntiStatusLine(existingRaw) {
			bakPath := filepath.Join(paths.BackupDir(), statusLineBackupFilename)
			if _, statErr := os.Stat(bakPath); os.IsNotExist(statErr) {
				if err := platform.EnsurePrivateDir(paths.BackupDir()); err != nil {
					return fmt.Errorf("ensure backup dir %q: %w", paths.BackupDir(), err)
				}
				bakBytes := append(bytes.TrimSpace(existingRaw), '\n')
				if err := platform.WriteFileAtomic(bakPath, bakBytes, false); err != nil {
					return fmt.Errorf("backup existing statusLine to %q: %w", bakPath, err)
				}
			} else if statErr != nil {
				return fmt.Errorf("check statusLine backup %q: %w", bakPath, statErr)
			}
		}
	}

	bin := strings.TrimSpace(binaryCmd)
	if bin == "" {
		bin = pluginName
	}
	sl := statusLineConfig{
		Type:             "command",
		Command:          quoteCommand(bin, "statusline"),
		StackWithDefault: true,
	}
	slBytes, err := json.Marshal(sl)
	if err != nil {
		return err
	}
	doc["statusLine"] = slBytes
	return writeJSONObjectAtomic(settingsPath, doc)
}

// UninstallStatusLine restores any backed-up prior statusLine or removes multi-anti's statusLine from settings.json.
func UninstallStatusLine(paths platform.Paths) error {
	settingsPath := paths.NativeAgySettingsPath()
	doc, exists, err := readJSONObjectIfExists(settingsPath)
	if err != nil {
		return fmt.Errorf("read settings %q: %w", settingsPath, err)
	}

	bakPath := filepath.Join(paths.BackupDir(), statusLineBackupFilename)
	bakData, bakErr := os.ReadFile(bakPath)
	switch {
	case bakErr == nil:
		trimmed := bytes.TrimSpace(bakData)
		if !json.Valid(trimmed) {
			return fmt.Errorf("corrupt statusLine backup at %q", bakPath)
		}
		doc["statusLine"] = json.RawMessage(trimmed)
		if err := writeJSONObjectAtomic(settingsPath, doc); err != nil {
			return err
		}
		if err := os.Remove(bakPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove statusLine backup %q: %w", bakPath, err)
		}
		return nil
	case !os.IsNotExist(bakErr):
		return fmt.Errorf("read statusLine backup %q: %w", bakPath, bakErr)
	}

	if !exists {
		return nil
	}
	existingRaw, hasExisting := doc["statusLine"]
	if !hasExisting || !isMultiAntiStatusLine(existingRaw) {
		return nil
	}
	delete(doc, "statusLine")
	return writeJSONObjectAtomic(settingsPath, doc)
}

func rewriteHooksCommands(raw []byte, binaryCmd string) ([]byte, error) {
	var parsed map[string]hookPluginSpec
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	spec, ok := parsed[pluginName]
	if !ok {
		return nil, fmt.Errorf("missing %q key in hooks.json", pluginName)
	}
	for i := range spec.SessionStart {
		spec.SessionStart[i].Command = rewriteHookCommand(spec.SessionStart[i].Command, binaryCmd)
	}
	for i := range spec.Stop {
		spec.Stop[i].Command = rewriteHookCommand(spec.Stop[i].Command, binaryCmd)
	}
	parsed[pluginName] = spec

	out, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func rewriteHookCommand(orig, binaryCmd string) string {
	trimmed := strings.TrimSpace(orig)
	if suffix, ok := strings.CutPrefix(trimmed, pluginName+" "); ok {
		return quoteCommand(binaryCmd, strings.TrimSpace(suffix))
	}
	return quoteCommand(binaryCmd, trimmed)
}

func quoteCommand(bin, subArgs string) string {
	return quoteCommandForOS(runtime.GOOS, bin, subArgs)
}

func quoteCommandForOS(goos, bin, subArgs string) string {
	quotedBin := quoteArgForOS(goos, strings.TrimSpace(bin))
	if sub := strings.TrimSpace(subArgs); sub != "" {
		return quotedBin + " " + sub
	}
	return quotedBin
}

func quoteArgForOS(goos, arg string) string {
	if arg == "" {
		if goos == "windows" {
			return `""`
		}
		return `''`
	}
	if goos == "windows" {
		if !strings.ContainsAny(arg, " \t\"&|<>^()%!") {
			return arg
		}
		escaped := strings.ReplaceAll(arg, `"`, `\"`)
		return `"` + escaped + `"`
	}
	if isSafeBareShellToken(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

func isSafeBareShellToken(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '/' && c != '.' && c != '_' && c != '-' && c != '@' && c != ':' {
			return false
		}
	}
	return true
}

func geminiConfigPath(paths platform.Paths) string {
	return filepath.Join(paths.NativeGeminiConfigDir(), "config.json")
}

func enablePluginInGeminiConfig(paths platform.Paths) error {
	cfgPath := geminiConfigPath(paths)
	doc, exists, err := readJSONObjectIfExists(cfgPath)
	if err != nil {
		return fmt.Errorf("read gemini config %q: %w", cfgPath, err)
	}
	if !exists {
		return nil
	}

	rawPlugins, hasPlugins := doc["plugins"]
	if !hasPlugins || isJSONNull(rawPlugins) {
		return nil
	}
	var plugins map[string]json.RawMessage
	if err := json.Unmarshal(rawPlugins, &plugins); err != nil {
		return fmt.Errorf("parse plugins in %q: %w", cfgPath, err)
	}
	rawEntry, hasEntry := plugins[pluginName]
	if !hasEntry || isJSONNull(rawEntry) {
		return nil
	}

	var entry map[string]json.RawMessage
	if err := json.Unmarshal(rawEntry, &entry); err != nil {
		return fmt.Errorf("parse plugin %q entry in %q: %w", pluginName, cfgPath, err)
	}
	rawEnabled, hasEnabled := entry["enabled"]
	if !hasEnabled {
		return nil
	}
	var enabled bool
	if err := json.Unmarshal(rawEnabled, &enabled); err != nil || enabled {
		return nil
	}

	entry["enabled"] = json.RawMessage("true")
	updatedEntry, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	plugins[pluginName] = updatedEntry
	updatedPlugins, err := json.Marshal(plugins)
	if err != nil {
		return err
	}
	doc["plugins"] = updatedPlugins
	return writeJSONObjectAtomic(cfgPath, doc)
}

func removePluginFromGeminiConfig(paths platform.Paths) error {
	cfgPath := geminiConfigPath(paths)
	doc, exists, err := readJSONObjectIfExists(cfgPath)
	if err != nil || !exists {
		return err
	}
	rawPlugins, hasPlugins := doc["plugins"]
	if !hasPlugins || isJSONNull(rawPlugins) {
		return nil
	}
	var plugins map[string]json.RawMessage
	if err := json.Unmarshal(rawPlugins, &plugins); err != nil {
		return fmt.Errorf("parse plugins in %q: %w", cfgPath, err)
	}
	if _, hasEntry := plugins[pluginName]; !hasEntry {
		return nil
	}
	delete(plugins, pluginName)
	if len(plugins) == 0 {
		delete(doc, "plugins")
	} else {
		updatedPlugins, err := json.Marshal(plugins)
		if err != nil {
			return err
		}
		doc["plugins"] = updatedPlugins
	}
	return writeJSONObjectAtomic(cfgPath, doc)
}

func isPluginDisabledInConfig(paths platform.Paths) (bool, error) {
	cfgPath := geminiConfigPath(paths)
	doc, exists, err := readJSONObjectIfExists(cfgPath)
	if err != nil {
		return false, fmt.Errorf("read gemini config %q: %w", cfgPath, err)
	}
	if !exists {
		return false, nil
	}
	rawPlugins, hasPlugins := doc["plugins"]
	if !hasPlugins || isJSONNull(rawPlugins) {
		return false, nil
	}
	var plugins map[string]struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal(rawPlugins, &plugins); err != nil {
		return false, nil
	}
	entry, ok := plugins[pluginName]
	return ok && entry.Enabled != nil && !*entry.Enabled, nil
}

func inspectStatusLineSetting(paths platform.Paths) (cmd string, enabled bool, err error) {
	settingsPath := paths.NativeAgySettingsPath()
	doc, exists, err := readJSONObjectIfExists(settingsPath)
	if err != nil {
		return "", false, fmt.Errorf("read settings %q: %w", settingsPath, err)
	}
	if !exists {
		return "", false, nil
	}
	raw, ok := doc["statusLine"]
	if !ok || isJSONNull(raw) {
		return "", false, nil
	}
	var cfg statusLineConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", false, nil
	}
	return cfg.Command, isMultiAntiStatusLine(raw), nil
}

func isMultiAntiStatusLine(raw json.RawMessage) bool {
	var cfg statusLineConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return false
	}
	lowerCmd := strings.ToLower(cfg.Command)
	return strings.EqualFold(strings.TrimSpace(cfg.Type), "command") &&
		strings.Contains(lowerCmd, pluginName) &&
		strings.Contains(lowerCmd, "statusline")
}

func readJSONObjectIfExists(path string) (map[string]json.RawMessage, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]json.RawMessage{}, false, nil
		}
		return nil, false, err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return map[string]json.RawMessage{}, true, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return nil, true, err
	}
	if doc == nil {
		return nil, true, errors.New("expected JSON object, got null")
	}
	return doc, true, nil
}

func writeJSONObjectAtomic(path string, doc map[string]json.RawMessage) error {
	if doc == nil {
		doc = map[string]json.RawMessage{}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return platform.WriteFileAtomic(path, out, false)
}

func isJSONNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}
