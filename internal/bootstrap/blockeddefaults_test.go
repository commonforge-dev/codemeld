package bootstrap

import (
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/securitystate"
)

func TestBigBlockedEntryWarnings(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	global := SettingsPath(home)
	project := projectSettingsPath(t.TempDir())
	homeFolder := "your home folder (" + home + ")"
	line := func(entry, source, folders string) string {
		return "warning: blocked_paths entry " + entry + " in " + source + " covers " + folders +
			"; programs need these to start, so most commands will fail"
	}

	for _, tc := range []struct {
		name   string
		layer  securitystate.LayerSnapshot
		want   string
		prefix bool
	}{
		{name: "root", layer: globalBlockedLayer(global, "/"), want: line("/", global, "/, /usr, /lib, /etc, "+homeFolder)},
		{name: "usr", layer: globalBlockedLayer(global, "/usr"), want: "warning: blocked_paths entry /usr in " + global + " covers /usr", prefix: true},
		{name: "etc", layer: globalBlockedLayer(global, "/etc"), want: line("/etc", global, "/etc")},
		{name: "home folder", layer: globalBlockedLayer(global, home), want: line(home, global, homeFolder)},
		{name: "home folder's parent", layer: globalBlockedLayer(global, filepath.Dir(home)), want: line(filepath.Dir(home), global, homeFolder)},
		{name: "usr subfolder", layer: globalBlockedLayer(global, "/usr/share")},
		{name: "ssh", layer: globalBlockedLayer(global, "~/.ssh")},
		{name: "outside all five", layer: globalBlockedLayer(global, outside)},
		{name: "project layer", layer: securitystate.LayerSnapshot{Kind: securitystate.LayerProject, Path: project, Present: true, Raw: map[string]any{"blocked_paths": []any{"/etc"}}}, want: line("/etc", project, "/etc")},
		{name: "ignored project layer", layer: securitystate.LayerSnapshot{Kind: securitystate.LayerProject, Path: project, Present: true, Ignored: true, Raw: map[string]any{"blocked_paths": []any{"/etc"}}}},
		{name: "control characters collapse", layer: globalBlockedLayer("/x\ny/settings.yaml", "/etc"), want: line("/etc", "/x y/settings.yaml", "/etc")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := blockedEntriesFromLayers(home, []securitystate.LayerSnapshot{tc.layer})
			if err != nil {
				t.Fatalf("blockedEntriesFromLayers: %v", err)
			}
			got := bigBlockedEntryWarnings(home, entries, permissions.NewBlockedPaths(home, nil).FoldCase())
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("warnings = %q, want none", got)
				}
				return
			}
			if len(got) != 1 || (tc.prefix && !strings.HasPrefix(got[0], tc.want)) || (!tc.prefix && got[0] != tc.want) {
				t.Fatalf("warnings = %q, want one line %q", got, tc.want)
			}
		})
	}
}

func globalBlockedLayer(path, entry string) securitystate.LayerSnapshot {
	return securitystate.LayerSnapshot{Kind: securitystate.LayerGlobal, Path: path, Present: true, Raw: map[string]any{"blocked_paths": []any{entry}}}
}
