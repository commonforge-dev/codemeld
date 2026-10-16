// Package toolactivity formats tool-activity display lines.
package toolactivity

import (
	"encoding/json"
	"unicode/utf8"
)

const maxBashActivityRunes = 120

const maxWebActivityRunes = 120

const (
	webSearchToolName = "web_search"
	webFetchToolName  = "web_fetch"
)

func Format(name, arguments string) string {
	switch name {
	case "bash":
		if cmd := stringArg(arguments, "command"); cmd != "" {
			return "Run: " + truncateRunes(cmd, maxBashActivityRunes)
		}
	case webSearchToolName:
		if query := stringArg(arguments, "query"); query != "" {
			return "WebSearch " + truncateRunes(query, maxWebActivityRunes)
		}
	case webFetchToolName:
		if url := stringArg(arguments, "url"); url != "" {
			return "WebFetch " + truncateRunes(url, maxWebActivityRunes)
		}
	case "read", "edit", "create", "list", "tree":
		if path := stringArg(arguments, "path"); path != "" {
			return activityLabel(name) + " " + path
		}
	case "grep", "glob":
		if pattern := stringArg(arguments, "pattern"); pattern != "" {
			return activityLabel(name) + " " + pattern
		}
	case "move":
		if source, destination := stringArg(arguments, "source"), stringArg(arguments, "destination"); source != "" && destination != "" {
			return activityLabel(name) + " " + source + " -> " + destination
		}
	}
	return name
}

func WebLine(name, arguments string) (string, bool) {
	if name != webSearchToolName && name != webFetchToolName {
		return "", false
	}
	return Format(name, arguments), true
}

func activityLabel(name string) string {
	switch name {
	case "read":
		return "Read"
	case "edit":
		return "Edit"
	case "create":
		return "Create"
	case "list":
		return "List"
	case "tree":
		return "Tree"
	case "grep":
		return "Grep"
	case "glob":
		return "Glob"
	case "move":
		return "Move"
	}
	return name
}

func stringArg(arguments, key string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(arguments), &m); err != nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "…"
}
