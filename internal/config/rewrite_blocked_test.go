package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/permissions"
)

const blockedHome = "/home/u"

const blockedHead = "model: {}\n\n# intro one\n# intro two\n"

const blockedTail = "\nsessions:\n  retention_days: 30\n"

const blockedGrouped = blockedHead + `blocked_paths:
  # Keys and passwords
  - "~/.ssh"
  - "~/.gnupg"
  - "~/.password-store"
  # Cloud and cluster logins
  - "~/.aws"
` + blockedTail

const blockedFlowGrouped = `blocked_paths: [
  # Keys and passwords
  "~/.ssh",
  # Cloud and cluster logins
  "~/.aws",
  # Shell history
  "~/.bash_history"
]
`

func TestRewriteKey_BlockedPaths(t *testing.T) {
	tests := []struct {
		name    string
		seed    *string
		payload any
		want    *string
		wantErr bool
	}{
		{
			name:    "remove first item of a group",
			seed:    ptr(blockedGrouped),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want: ptr(blockedHead + `blocked_paths:
  # Keys and passwords
  - "~/.gnupg"
  - "~/.password-store"
  # Cloud and cluster logins
  - "~/.aws"
` + blockedTail),
		},
		{
			name:    "remove middle item of a group",
			seed:    ptr(blockedGrouped),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.gnupg", 0),
			want: ptr(blockedHead + `blocked_paths:
  # Keys and passwords
  - "~/.ssh"
  - "~/.password-store"
  # Cloud and cluster logins
  - "~/.aws"
` + blockedTail),
		},
		{
			name:    "remove last item of a group",
			seed:    ptr(blockedGrouped),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.password-store", 0),
			want: ptr(blockedHead + `blocked_paths:
  # Keys and passwords
  - "~/.ssh"
  - "~/.gnupg"
  # Cloud and cluster logins
  - "~/.aws"
` + blockedTail),
		},
		{
			name: "remove second spelling by occurrence",
			seed: ptr(blockedHead + `blocked_paths:
  - "~/.ssh"
  - /home/u/.ssh/
  - "~/.aws"
` + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 1),
			want: ptr(blockedHead + `blocked_paths:
  - "~/.ssh"
  - "~/.aws"
` + blockedTail),
		},
		{
			name: "remove the only item leaves an empty list and the comments",
			seed: ptr(blockedHead + `blocked_paths:
  # Keys and passwords
  - "~/.ssh"
` + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want: ptr(blockedHead + `blocked_paths: []
  # Keys and passwords
` + blockedTail),
		},
		{
			name:    "remove first flow item",
			seed:    ptr(blockedHead + `blocked_paths: [ "~/.ssh", ~/.gnupg, "~/.aws" ]` + "\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want:    ptr(blockedHead + `blocked_paths: [ ~/.gnupg, "~/.aws" ]` + "\n" + blockedTail),
		},
		{
			name:    "remove middle flow item",
			seed:    ptr(blockedHead + `blocked_paths: [ "~/.ssh", ~/.gnupg, "~/.aws" ]` + "\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.gnupg", 0),
			want:    ptr(blockedHead + `blocked_paths: [ "~/.ssh", "~/.aws" ]` + "\n" + blockedTail),
		},
		{
			name:    "remove last flow item",
			seed:    ptr(blockedHead + `blocked_paths: [ "~/.ssh", ~/.gnupg, "~/.aws" ]` + "\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.aws", 0),
			want:    ptr(blockedHead + `blocked_paths: [ "~/.ssh", ~/.gnupg ]` + "\n" + blockedTail),
		},
		{
			name:    "remove the only flow item",
			seed:    ptr(blockedHead + `blocked_paths: [ "~/.ssh" ] # mine` + "\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want:    ptr(blockedHead + `blocked_paths: [] # mine` + "\n" + blockedTail),
		},
		{
			name:    "remove the sole multiline flow item keeps its heading comment",
			seed:    ptr(blockedHead + "blocked_paths: [\n  # Keys and passwords\n  \"~/.ssh\"\n]\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want:    ptr(blockedHead + "blocked_paths: []\n  # Keys and passwords\n" + blockedTail),
		},
		{
			name:    "remove first multiline flow item keeps the comments",
			seed:    ptr(blockedHead + blockedFlowGrouped + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want: ptr(blockedHead + `blocked_paths: [
  # Keys and passwords
  # Cloud and cluster logins
  "~/.aws",
  # Shell history
  "~/.bash_history"
]
` + blockedTail),
		},
		{
			name:    "remove middle multiline flow item keeps the comments",
			seed:    ptr(blockedHead + blockedFlowGrouped + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.aws", 0),
			want: ptr(blockedHead + `blocked_paths: [
  # Keys and passwords
  "~/.ssh",
  # Cloud and cluster logins
  # Shell history
  "~/.bash_history"
]
` + blockedTail),
		},
		{
			name:    "remove last multiline flow item keeps the comments",
			seed:    ptr(blockedHead + blockedFlowGrouped + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.bash_history", 0),
			want: ptr(blockedHead + `blocked_paths: [
  # Keys and passwords
  "~/.ssh",
  # Cloud and cluster logins
  "~/.aws"]
  # Shell history
` + blockedTail),
		},
		{
			name:    "remove the sole multiline flow item with a trailing comma",
			seed:    ptr(blockedHead + "blocked_paths: [\n  # Keys and passwords\n  \"~/.ssh\",\n]\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want:    ptr(blockedHead + "blocked_paths: []\n  # Keys and passwords\n" + blockedTail),
		},
		{
			name:    "remove last multiline flow item with a trailing comma",
			seed:    ptr(blockedHead + strings.Replace(blockedFlowGrouped, `"~/.bash_history"`, `"~/.bash_history",`, 1) + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.bash_history", 0),
			want: ptr(blockedHead + `blocked_paths: [
  # Keys and passwords
  "~/.ssh",
  # Cloud and cluster logins
  "~/.aws"]
  # Shell history
` + blockedTail),
		},
		{
			name:    "remove first flow item with a comment before its comma",
			seed:    ptr(blockedHead + "blocked_paths: [\"/one\" # keep\n, \"/two\"]\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/one", 0),
			want:    ptr(blockedHead + "blocked_paths: [# keep\n\"/two\"]\n" + blockedTail),
		},
		{
			name:    "remove middle flow item with a comment before its comma",
			seed:    ptr(blockedHead + "blocked_paths: [\"/zero\", \"/one\" # keep\n, \"/two\"]\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/one", 0),
			want:    ptr(blockedHead + "blocked_paths: [\"/zero\", # keep\n\"/two\"]\n" + blockedTail),
		},
		{
			name:    "remove last flow item with a comment before its comma",
			seed:    ptr(blockedHead + "blocked_paths: [\"/one\" # keep\n, \"/two\"]\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/two", 0),
			want:    ptr(blockedHead + "blocked_paths: [\"/one\" # keep\n]\n" + blockedTail),
		},
		{
			name:    "remove last multiline flow item with a leading comma after a comment",
			seed:    ptr(blockedHead + "blocked_paths: [\n  \"/one\" # keep\n  , \"/two\"\n]\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/two", 0),
			want:    ptr(blockedHead + "blocked_paths: [\n  \"/one\" # keep\n]\n" + blockedTail),
		},
		{
			name:    "remove flow item after a multibyte item",
			seed:    ptr(blockedHead + "blocked_paths: [\"/é\", \"/two\"]\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/two", 0),
			want:    ptr(blockedHead + "blocked_paths: [\"/é\"]\n" + blockedTail),
		},
		{
			name:    "remove from a block list with bare CR line breaks",
			seed:    ptr("model: {}\rblocked_paths:\r  - \"/one\"\r  - \"/two\"\r"),
			payload: config.BlockedPathRemove(blockedHome, "/one", 0),
			want:    ptr("model: {}\rblocked_paths:\r  - \"/two\"\r"),
		},
		{
			name:    "remove an item keeps a deeper indented comment after it",
			seed:    ptr(blockedHead + "blocked_paths:\n  - \"~/.ssh\"\n    # deeper\n  - \"~/.aws\"\n" + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want:    ptr(blockedHead + "blocked_paths:\n    # deeper\n  - \"~/.aws\"\n" + blockedTail),
		},
		{
			name:    "remove from an empty file",
			seed:    ptr(""),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want:    ptr(""),
		},
		{
			name:    "remove from a comment-only file",
			seed:    ptr("# only a comment\n"),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want:    ptr("# only a comment\n"),
		},
		{
			name:    "remove an absent item",
			seed:    ptr(blockedGrouped),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.kube", 0),
			want:    ptr(blockedGrouped),
		},
		{
			name:    "remove an occurrence past the matches",
			seed:    ptr(blockedGrouped),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 1),
			want:    ptr(blockedGrouped),
		},
		{
			name:    "remove without the key",
			seed:    ptr(blockedHead + blockedTail),
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
			want:    ptr(blockedHead + blockedTail),
		},
		{
			name:    "remove without the file",
			payload: config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
		},
		{
			name:    "add under an existing group heading",
			seed:    ptr(blockedGrouped),
			payload: config.BlockedPathAdd(blockedHome, "~/Library/Keychains", "Keys and passwords"),
			want: ptr(blockedHead + `blocked_paths:
  # Keys and passwords
  - "~/.ssh"
  - "~/.gnupg"
  - "~/.password-store"
  - "~/Library/Keychains"
  # Cloud and cluster logins
  - "~/.aws"
` + blockedTail),
		},
		{
			name: "add under a trailing heading with no items",
			seed: ptr(blockedHead + `blocked_paths:
  # Keys and passwords
  - "~/.ssh"
  # Cloud and cluster logins
` + blockedTail),
			payload: config.BlockedPathAdd(blockedHome, "~/.aws", "Cloud and cluster logins"),
			want: ptr(blockedHead + `blocked_paths:
  # Keys and passwords
  - "~/.ssh"
  # Cloud and cluster logins
  - "~/.aws"
` + blockedTail),
		},
		{
			name:    "add with a heading not in the file",
			seed:    ptr(blockedGrouped),
			payload: config.BlockedPathAdd(blockedHome, "~/.bash_history", "Shell history"),
			want: ptr(blockedHead + `blocked_paths:
  # Keys and passwords
  - "~/.ssh"
  - "~/.gnupg"
  - "~/.password-store"
  # Cloud and cluster logins
  - "~/.aws"
  - "~/.bash_history"
` + blockedTail),
		},
		{
			name:    "add to an empty list",
			seed:    ptr(blockedHead + "blocked_paths: []\n" + blockedTail),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr(blockedHead + "blocked_paths:\n  - \"~/.ssh\"\n" + blockedTail),
		},
		{
			name:    "add to an empty list under its heading comment",
			seed:    ptr(blockedHead + "blocked_paths: []\n  # Other\n  # Keys and passwords\n  # Shell history\n" + blockedTail),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr(blockedHead + "blocked_paths:\n  # Other\n  # Keys and passwords\n  - \"~/.ssh\"\n  # Shell history\n" + blockedTail),
		},
		{
			name:    "add to a multiline empty flow list",
			seed:    ptr(blockedHead + "blocked_paths: [\n]\n" + blockedTail),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr(blockedHead + "blocked_paths:\n  - \"~/.ssh\"\n" + blockedTail),
		},
		{
			name:    "add ignores a heading after a blank line below the last item",
			seed:    ptr(blockedHead + "blocked_paths:\n  - \"~/.ssh\"\n\n  # Shell history\n" + blockedTail),
			payload: config.BlockedPathAdd(blockedHome, "~/.bash_history", "Shell history"),
			want:    ptr(blockedHead + "blocked_paths:\n  - \"~/.ssh\"\n  - \"~/.bash_history\"\n\n  # Shell history\n" + blockedTail),
		},
		{
			name:    "add to an empty file",
			seed:    ptr(""),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr("blocked_paths:\n  - \"~/.ssh\"\n"),
		},
		{
			name:    "add to a comment-only file",
			seed:    ptr("# only a comment\n"),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr("# only a comment\nblocked_paths:\n  - \"~/.ssh\"\n"),
		},
		{
			name:    "add to an empty flow root mapping",
			seed:    ptr("{}\n"),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr("{blocked_paths: [\"~/.ssh\"]}\n"),
		},
		{
			name:    "add to a non-empty flow root mapping",
			seed:    ptr("{sessions: {retention_days: 30}}\n"),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr("{sessions: {retention_days: 30}, blocked_paths: [\"~/.ssh\"]}\n"),
		},
		{
			name:    "add to an empty flow list in a flow root mapping",
			seed:    ptr("{blocked_paths: []}\n"),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr("{blocked_paths: [\"~/.ssh\"]}\n"),
		},
		{
			name:    "add to a flow root mapping with a trailing comma",
			seed:    ptr("{sessions: {retention_days: 30},}\n"),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr("{sessions: {retention_days: 30}, blocked_paths: [\"~/.ssh\"]}\n"),
		},
		{
			name:    "add to a flow root mapping with a trailing comment",
			seed:    ptr("{\n  sessions: {retention_days: 30} # keep\n}\n"),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr("{\n  sessions: {retention_days: 30}, blocked_paths: [\"~/.ssh\"] # keep\n}\n"),
		},
		{
			name:    "add to a file without the key",
			seed:    ptr(blockedHead + blockedTail),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr(blockedHead + blockedTail + "blocked_paths:\n  - \"~/.ssh\"\n"),
		},
		{
			name:    "add to a file without the key that ends with a document end marker",
			seed:    ptr("model: {}\n...\n"),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr("model: {}\nblocked_paths:\n  - \"~/.ssh\"\n...\n"),
		},
		{
			name:    "add without the file",
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr("blocked_paths:\n  - \"~/.ssh\"\n"),
		},
		{
			name:    "add to a flow list",
			seed:    ptr(blockedHead + `blocked_paths: [ "~/.ssh" ]` + "\n" + blockedTail),
			payload: config.BlockedPathAdd(blockedHome, "~/.aws", "Cloud and cluster logins"),
			want:    ptr(blockedHead + `blocked_paths: [ "~/.ssh", "~/.aws" ]` + "\n" + blockedTail),
		},
		{
			name:    "add to a flow list after a multibyte item",
			seed:    ptr(blockedHead + "blocked_paths: [\"/é\", \"/two\"]\n" + blockedTail),
			payload: config.BlockedPathAdd(blockedHome, "/three", ""),
			want:    ptr(blockedHead + "blocked_paths: [\"/é\", \"/two\", \"/three\"]\n" + blockedTail),
		},
		{
			name:    "add to a block list with bare CR line breaks",
			seed:    ptr("model: {}\rblocked_paths:\r  - \"/one\"\r  - \"/two\"\r"),
			payload: config.BlockedPathAdd(blockedHome, "/three", ""),
			want:    ptr("model: {}\rblocked_paths:\r  - \"/one\"\r  - \"/two\"\r  - \"/three\"\r"),
		},
		{
			name:    "add an item another spelling already lists",
			seed:    ptr(blockedHead + "blocked_paths:\n  - /home/u/.ssh\n" + blockedTail),
			payload: config.BlockedPathAdd(blockedHome, "~/.ssh", "Keys and passwords"),
			want:    ptr(blockedHead + "blocked_paths:\n  - /home/u/.ssh\n" + blockedTail),
		},
		{
			name:    "add an item that cannot be expanded",
			seed:    ptr(blockedGrouped),
			payload: config.BlockedPathAdd(blockedHome, "relative/path", "Keys and passwords"),
			wantErr: true,
		},
		{
			name:    "a string payload",
			seed:    ptr(blockedGrouped),
			payload: "~/.ssh",
			wantErr: true,
		},
		{
			name:    "a permissions payload",
			seed:    ptr(blockedGrouped),
			payload: config.PermissionDelete(permissions.PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "*", GrantKind: "global"}.DedupKey()),
			wantErr: true,
		},
		{
			name:    "a nil payload",
			seed:    ptr(blockedGrouped),
			payload: nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.yaml")
			var before os.FileInfo
			if tt.seed != nil {
				before = seedOld(t, path, *tt.seed)
			}

			_, _, err := config.RewriteKey(path, "blocked_paths", tt.payload)

			got, readErr := os.ReadFile(path)
			switch {
			case tt.wantErr:
				if err == nil {
					t.Fatalf("RewriteKey succeeded, want an error")
				}
				assertUntouched(t, path, *tt.seed, before)
			case err != nil:
				t.Fatalf("RewriteKey: %v", err)
			case tt.want == nil:
				if !os.IsNotExist(readErr) {
					t.Fatalf("file created on a no-op: %v", readErr)
				}
			case tt.seed != nil && *tt.want == *tt.seed:
				assertUntouched(t, path, *tt.seed, before)
			default:
				if readErr != nil {
					t.Fatalf("read result: %v", readErr)
				}
				if string(got) != *tt.want {
					t.Fatalf("bytes mismatch\n--- got ---\n%s\n--- want ---\n%s", got, *tt.want)
				}
				if _, _, vErr := config.ValidateGlobalSettingsBytes(got, path); vErr != nil {
					t.Fatalf("rewritten file fails validation: %v", vErr)
				}
			}
		})
	}
}

func TestRewriteKey_BlockedPaths_RefusedShapes(t *testing.T) {
	shapes := map[string]string{
		"anchored block list":                                "blocked_paths: &keys\n  - \"~/.ssh\"\n",
		"anchored flow list":                                 "blocked_paths: &keys [\"~/.ssh\"]\n",
		"anchored item":                                      "blocked_paths:\n  - &k \"~/.ssh\"\n",
		"aliased item":                                       "ssh: &k \"~/.ssh\"\nblocked_paths:\n  - *k\n",
		"literal block scalar item":                          "blocked_paths:\n  - |+\n    /home/u/.ssh\n\n  - \"~/.aws\"\n",
		"folded block scalar item":                           "blocked_paths:\n  - >-\n    /home/u/.ssh\n",
		"empty flow list with a comment":                     "blocked_paths: [] # keep\n",
		"multiline plain item":                               "blocked_paths:\n  - /home/u/.ssh\n    backup\n  - \"~/.aws\"\n",
		"multiline double-quoted item":                       "blocked_paths:\n  - \"/home/u/.ssh\n    backup\"\n  - \"~/.aws\"\n",
		"multiline single-quoted item":                       "blocked_paths:\n  - '/home/u/.ssh\n    backup'\n",
		"multiline flow item":                                "blocked_paths: [\"~/.aws\", /home/u/.ssh\n  backup]\n",
		"key with no value":                                  "blocked_paths:\n",
		"key with no value and comments":                     "blocked_paths:\n  # - \"~/.ssh\"\n",
		"empty flow list with a comment on the closing line": "blocked_paths: [\n] # keep\n",
	}
	payloads := map[string]any{
		"remove": config.BlockedPathRemove(blockedHome, "/home/u/.ssh", 0),
		"add":    config.BlockedPathAdd(blockedHome, "~/.gnupg", "Keys and passwords"),
	}
	for shape, seed := range shapes {
		for edit, payload := range payloads {
			t.Run(shape+"/"+edit, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "settings.yaml")
				before := seedOld(t, path, seed)
				if _, _, err := config.RewriteKey(path, "blocked_paths", payload); err == nil {
					t.Fatalf("RewriteKey succeeded, want a refusal")
				}
				assertUntouched(t, path, seed, before)
			})
		}
	}
}

func TestRewriteKey_BlockedPaths_GeneratedFileRoundTrip(t *testing.T) {
	generated := string(bootstrap.GeneratedSettingsBytes())
	path := filepath.Join(t.TempDir(), "settings.yaml")
	if err := os.WriteFile(path, []byte(generated), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := config.RewriteKey(path, "blocked_paths", config.BlockedPathRemove(blockedHome, "/home/u/Library/Keychains", 0)); err != nil {
		t.Fatalf("remove: %v", err)
	}
	removed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(generated, "  - \"~/Library/Keychains\"\n", "", 1); string(removed) != want || want == generated {
		t.Fatalf("removal did not delete only the item line\n--- got ---\n%s", removed)
	}
	if _, _, vErr := config.ValidateGlobalSettingsBytes(removed, path); vErr != nil {
		t.Fatalf("after removal the file fails validation: %v", vErr)
	}

	if _, _, err := config.RewriteKey(path, "blocked_paths", config.BlockedPathAdd(blockedHome, "~/Library/Keychains", "Keys and passwords")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != generated {
		t.Fatalf("round trip differs from the generated file\n--- got ---\n%s", got)
	}
}

func ptr(s string) *string { return &s }

func seedOld(t *testing.T, path, content string) os.FileInfo {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func assertUntouched(t *testing.T, path, content string, before os.FileInfo) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatalf("file changed\n--- got ---\n%s\n--- want ---\n%s", got, content)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("modification time changed: %v -> %v", before.ModTime(), after.ModTime())
	}
}
