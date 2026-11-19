package plugin

import "embed"

// FS embeds the multi-anti agy plugin files for installation into ~/.gemini/config/plugins/multi-anti.
//
//go:embed plugin.json hooks.json assets/logo.svg skills/multi-anti/SKILL.md
var FS embed.FS
