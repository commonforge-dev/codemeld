// Tests for the permission event emitter helpers: per-emitter payload
// shape validated against, persisted readback of each emitted record
// the literal-match argument_hash contract, and rejection of the
// cross-field invalid combos through the append path the emitters use.
package events

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
)

// emitFixture builds a fresh session + store wired together so a test can call an
// emitter and then read the persisted record back through the production codec.
func emitFixture() (*sessions.Session, *sessions.Store) {
	sess := newSession()
	return sess, sessions.New("unused-in-tests", sess)
}

func emitMatched(store *sessions.Store, subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, childInvocationID string) error {
	return EmitMatchedIdentityAttributed(store, subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, "", childInvocationID)
}

// reloadOnly marshals sess through the production session codec, reloads it, and
// returns the single persisted event. It fails if the stream does not hold
// exactly one record, so each emitter test asserts against the durable bytes
// rather than the in-memory payload alone, and confirms the load-time validator
// accepts what the emitter wrote.
func reloadOnly(t *testing.T, sess *sessions.Session) sessions.Event {
	t.Helper()
	data, err := sessions.Marshal(sess)
	if err != nil {
		t.Fatalf("sessions.Marshal() error = %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("sessions.Unmarshal() error = %v", err)
	}
	if len(loaded.Records) != 1 {
		t.Fatalf("reloaded session has %d records, want 1", len(loaded.Records))
	}
	ev, ok := loaded.Records[0].(sessions.Event)
	if !ok {
		t.Fatalf("reloaded record is %T, want sessions.Event", loaded.Records[0])
	}
	if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
		t.Fatalf("ValidatePayload() rejected the persisted record: %v", err)
	}
	return ev
}

func reloadRecords(t *testing.T, sess *sessions.Session) []sessions.Event {
	t.Helper()
	data, err := sessions.Marshal(sess)
	if err != nil {
		t.Fatalf("sessions.Marshal() error = %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("sessions.Unmarshal() error = %v", err)
	}
	evs := make([]sessions.Event, 0, len(loaded.Records))
	for _, r := range loaded.Records {
		ev, ok := r.(sessions.Event)
		if !ok {
			t.Fatalf("reloaded record is %T, want sessions.Event", r)
		}
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("ValidatePayload() rejected the persisted record: %v", err)
		}
		evs = append(evs, ev)
	}
	return evs
}

func mustUnmarshal(t *testing.T, payload json.RawMessage, target any) {
	t.Helper()
	if err := json.Unmarshal(payload, target); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
}

func TestEmitPromptShown(t *testing.T) {
	sess, store := emitFixture()
	if err := EmitPromptShown(store, "direct", "git status", "/home/u/proj", nil, "", ""); err != nil {
		t.Fatalf("EmitPromptShown() error = %v", err)
	}
	ev := reloadOnly(t, sess)
	if ev.Kind != KindPermissionPromptShown {
		t.Errorf("kind = %q, want %q", ev.Kind, KindPermissionPromptShown)
	}
	var got PermissionPromptShown
	if err := json.Unmarshal(ev.Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	want := PermissionPromptShown{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj"}
	if got != want {
		t.Errorf("persisted payload = %#v, want %#v", got, want)
	}
}

func TestEmitPromptShown_HostForm(t *testing.T) {
	for _, subject := range []string{"web_fetch", "web_search"} {
		t.Run(subject, func(t *testing.T) {
			sess, store := emitFixture()
			if err := EmitPromptShown(store, "host", subject, "docs.example.com", nil, "", ""); err != nil {
				t.Fatalf("EmitPromptShown() error = %v", err)
			}
			ev := reloadOnly(t, sess)
			if ev.Kind != KindPermissionPromptShown {
				t.Errorf("kind = %q, want %q", ev.Kind, KindPermissionPromptShown)
			}
			if strings.Contains(string(ev.Payload), "path_scope") {
				t.Errorf("host prompt persisted a path field: %s", ev.Payload)
			}
			var got PermissionPromptShown
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			want := PermissionPromptShown{SubjectKind: "host", Subject: subject, HostScope: "docs.example.com"}
			if got != want {
				t.Errorf("persisted payload = %#v, want %#v", got, want)
			}
		})
	}
}

func TestEmitDecision(t *testing.T) {
	t.Run("granted-folder", func(t *testing.T) {
		sess, store := emitFixture()
		if err := EmitDecision(store, "direct", "git status", "/home/u/proj", "granted", "folder", "/home/u/proj", "", ""); err != nil {
			t.Fatalf("EmitDecision() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		if ev.Kind != KindPermissionDecision {
			t.Errorf("kind = %q, want %q", ev.Kind, KindPermissionDecision)
		}
		var got PermissionDecision
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		want := PermissionDecision{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj", Outcome: "granted", GrantKind: "folder", GrantPathScope: "/home/u/proj"}
		if got != want {
			t.Errorf("persisted payload = %#v, want %#v", got, want)
		}
	})

	t.Run("granted-project-host", func(t *testing.T) {
		sess, store := emitFixture()
		if err := EmitDecision(store, "host", "web_fetch", "docs.example.com", "granted", "project", "docs.example.com", "", ""); err != nil {
			t.Fatalf("EmitDecision() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		if strings.Contains(string(ev.Payload), "path_scope") {
			t.Errorf("host decision persisted a path field: %s", ev.Payload)
		}
		var got PermissionDecision
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		want := PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}
		if got != want {
			t.Errorf("persisted payload = %#v, want %#v", got, want)
		}
	})

	t.Run("denied-host-omits-grant-fields", func(t *testing.T) {
		sess, store := emitFixture()
		if err := EmitDecision(store, "host", "web_search", "mcp.exa.ai", "denied", "", "", "", ""); err != nil {
			t.Fatalf("EmitDecision() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		if strings.Contains(string(ev.Payload), "grant_kind") || strings.Contains(string(ev.Payload), "grant_host_scope") {
			t.Errorf("denied host decision persisted grant fields: %s", ev.Payload)
		}
		var got PermissionDecision
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if got.HostScope != "mcp.exa.ai" {
			t.Errorf("host_scope = %q, want the canonical requested host", got.HostScope)
		}
	})

	t.Run("denied-omits-grant-fields", func(t *testing.T) {
		sess, store := emitFixture()
		if err := EmitDecision(store, "direct", "rm -rf /", "/home/u/proj", "denied", "", "", "", ""); err != nil {
			t.Fatalf("EmitDecision() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		// omitempty must drop the grant fields from the persisted bytes on a denial.
		if strings.Contains(string(ev.Payload), "grant_kind") || strings.Contains(string(ev.Payload), "grant_path_scope") {
			t.Errorf("denied decision persisted grant fields: %s", ev.Payload)
		}
		var got PermissionDecision
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if got.GrantKind != "" || got.GrantPathScope != "" {
			t.Errorf("denied decision carried grant fields: %#v", got)
		}
	})
}

func TestEmitDecisionGrant(t *testing.T) {
	cases := []struct {
		name    string
		emit    func(*sessions.Store) error
		want    PermissionDecision
		absent  string
		wantRaw string
	}{
		{
			name: "widened-path-subject",
			emit: func(s *sessions.Store) error {
				return EmitDecisionGrant(s, "direct", "git status", "/home/u/proj", "folder", "/home/u/proj", "git", "", "")
			},
			want:    PermissionDecision{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj", Outcome: "granted", GrantKind: "folder", GrantPathScope: "/home/u/proj", GrantSubject: "git"},
			absent:  "host_scope",
			wantRaw: `{"subject_kind":"direct","subject":"git status","path_scope":"/home/u/proj","outcome":"granted","grant_kind":"folder","grant_path_scope":"/home/u/proj","grant_subject":"git"}`,
		},
		{
			name: "equal-path-subject-still-written",
			emit: func(s *sessions.Store) error {
				return EmitDecisionGrant(s, "direct", "git status", "/home/u/proj", "session", "/home/u/proj", "git status", "", "")
			},
			want:    PermissionDecision{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj", Outcome: "granted", GrantKind: "session", GrantPathScope: "/home/u/proj", GrantSubject: "git status"},
			absent:  "host_scope",
			wantRaw: `{"subject_kind":"direct","subject":"git status","path_scope":"/home/u/proj","outcome":"granted","grant_kind":"session","grant_path_scope":"/home/u/proj","grant_subject":"git status"}`,
		},
		{
			name: "host-form",
			emit: func(s *sessions.Store) error {
				return EmitDecisionGrant(s, "host", "web_fetch", "docs.example.com", "project", "docs.example.com", "web_fetch", "", "")
			},
			want:    PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "docs.example.com", GrantHostScope: "docs.example.com", GrantSubject: "web_fetch"},
			absent:  "path_scope",
			wantRaw: `{"subject_kind":"host","subject":"web_fetch","outcome":"granted","grant_kind":"project","host_scope":"docs.example.com","grant_host_scope":"docs.example.com","grant_subject":"web_fetch"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, store := emitFixture()
			if err := tc.emit(store); err != nil {
				t.Fatalf("EmitDecisionGrant() error = %v", err)
			}
			ev := reloadOnly(t, sess)
			if ev.Kind != KindPermissionDecision {
				t.Errorf("kind = %q, want %q", ev.Kind, KindPermissionDecision)
			}
			if strings.Contains(string(ev.Payload), tc.absent) {
				t.Errorf("persisted payload carries %q: %s", tc.absent, ev.Payload)
			}
			if got := string(ev.Payload); got != tc.wantRaw {
				t.Errorf("persisted payload =\n%s\nwant\n%s", got, tc.wantRaw)
			}
			var got PermissionDecision
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if got != tc.want {
				t.Errorf("persisted payload = %#v, want %#v", got, tc.want)
			}
		})
	}

	t.Run("empty-subject-rejected", func(t *testing.T) {
		store := newStore()
		if err := EmitDecisionGrant(store, "direct", "git status", "/home/u/proj", "folder", "/home/u/proj", "", "", ""); err == nil {
			t.Fatal("EmitDecisionGrant() accepted an empty grant_subject")
		}
		if got := len(store.Records()); got != 0 {
			t.Errorf("rejected emit still appended %d record(s)", got)
		}
	})
}

func TestPermissionDecision_RejectsGrantSubject(t *testing.T) {
	cases := []struct {
		name    string
		payload PermissionDecision
	}{
		{"denied-path", PermissionDecision{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj", Outcome: "denied", GrantSubject: "git"}},
		{"denied-host", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com", Outcome: "denied", GrantSubject: "web_fetch"}},
		{"allow-once-path", PermissionDecision{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj", Outcome: "granted", GrantSubject: "git"}},
		{"allow-once-host", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com", Outcome: "granted", GrantSubject: "web_fetch"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.payload); err == nil {
				t.Fatal("Append() accepted a grant_subject with no stored grant")
			}
			if got := len(store.Records()); got != 0 {
				t.Errorf("rejected append still stored %d record(s)", got)
			}
		})
	}

	t.Run("emitter-without-grant-kind", func(t *testing.T) {
		store := newStore()
		if err := EmitDecisionGrant(store, "direct", "git status", "/home/u/proj", "", "", "git", "", ""); err == nil {
			t.Fatal("EmitDecisionGrant() accepted a grant_subject with no grant_kind")
		}
		if got := len(store.Records()); got != 0 {
			t.Errorf("rejected emit still appended %d record(s)", got)
		}
	})
}

func TestPermissionDecision_LegacyRecordOmitsGrantSubject(t *testing.T) {
	for _, legacy := range []string{
		`{"subject_kind":"direct","subject":"git status","path_scope":"/home/u/proj","outcome":"granted","grant_kind":"folder","grant_path_scope":"/home/u/proj"}`,
		`{"subject_kind":"host","subject":"web_fetch","outcome":"granted","grant_kind":"project","host_scope":"docs.example.com","grant_host_scope":"docs.example.com"}`,
		`{"subject_kind":"direct","subject":"rm -rf /","path_scope":"/home/u/proj","outcome":"denied"}`,
	} {
		if err := ValidatePayload(KindPermissionDecision, json.RawMessage(legacy)); err != nil {
			t.Fatalf("ValidatePayload() rejected a legacy record: %v\n%s", err, legacy)
		}
		var got PermissionDecision
		if err := json.Unmarshal([]byte(legacy), &got); err != nil {
			t.Fatalf("unmarshal legacy record: %v", err)
		}
		if got.GrantSubject != "" {
			t.Errorf("legacy record decoded grant_subject = %q, want empty", got.GrantSubject)
		}
	}
}

func TestEmitMatched(t *testing.T) {
	t.Run("grant-folder", func(t *testing.T) {
		sess, store := emitFixture()
		if err := emitMatched(store, "direct", "git status", "/home/u/proj", "folder", "/home/u/proj", "folder_grant", "grant", "", ""); err != nil {
			t.Fatalf("EmitMatched() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		if ev.Kind != KindPermissionMatched {
			t.Errorf("kind = %q, want %q", ev.Kind, KindPermissionMatched)
		}
		var got PermissionMatched
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		want := PermissionMatched{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "folder_grant", OutcomeSource: "grant"}
		if got != want {
			t.Errorf("persisted payload = %#v, want %#v", got, want)
		}
	})

	for _, tc := range []struct{ grantKind, outcome string }{
		{"project", "project_grant"},
		{"session", "session_grant"},
	} {
		t.Run("grant-host-"+tc.grantKind, func(t *testing.T) {
			sess, store := emitFixture()
			if err := emitMatched(store, "host", "web_fetch", "docs.example.com", tc.grantKind, "docs.example.com", tc.outcome, "grant", "", ""); err != nil {
				t.Fatalf("EmitMatched() error = %v", err)
			}
			ev := reloadOnly(t, sess)
			if strings.Contains(string(ev.Payload), "path_scope") || strings.Contains(string(ev.Payload), "argument_hash") {
				t.Errorf("host match persisted path/hash fields: %s", ev.Payload)
			}
			var got PermissionMatched
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			want := PermissionMatched{SubjectKind: "host", Subject: "web_fetch", GrantKind: tc.grantKind, Outcome: tc.outcome, OutcomeSource: "grant", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}
			if got != want {
				t.Errorf("persisted payload = %#v, want %#v", got, want)
			}
		})
	}

	t.Run("cache-once-omits-grant-and-hash", func(t *testing.T) {
		sess, store := emitFixture()
		if err := emitMatched(store, "direct", "ls", "/home/u/proj", "", "", "once", "cache", "", ""); err != nil {
			t.Fatalf("EmitMatched() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		if strings.Contains(string(ev.Payload), "grant_kind") || strings.Contains(string(ev.Payload), "argument_hash") {
			t.Errorf("cache-once match persisted grant/hash fields: %s", ev.Payload)
		}
	})

	// A protected-state refusal is evidence of a denial, not of a grant, so it carries no grant or
	// hash fields.
	t.Run("protected-state-deny-round-trips", func(t *testing.T) {
		for _, tool := range []string{
			"edit", "create", "delete", "mkdir", "move",
			"vcs_status", "vcs_diff", "vcs_add", "vcs_commit", "vcs_log",
			"vcs_branch_current", "vcs_branch_create", "vcs_branch_switch", "vcs_restore_file",
			"vcs_is_clean", "vcs_stash", "vcs_stash_pop", "vcs_merge_status", "vcs_rebase_status",
		} {
			sess, store := emitFixture()
			if err := emitMatched(store, "tool", tool, "/home/u/proj/.codemeld", "", "", "deny", "protected_state", "", ""); err != nil {
				t.Fatalf("EmitMatched(%s) error = %v", tool, err)
			}
			ev := reloadOnly(t, sess)
			if strings.Contains(string(ev.Payload), "grant_kind") || strings.Contains(string(ev.Payload), "grant_path_scope") || strings.Contains(string(ev.Payload), "argument_hash") {
				t.Errorf("protected-state denial persisted grant/hash fields: %s", ev.Payload)
			}
			var got PermissionMatched
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			want := PermissionMatched{SubjectKind: "tool", Subject: tool, PathScope: "/home/u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state"}
			if got != want {
				t.Errorf("persisted payload = %#v, want %#v", got, want)
			}
		}
	})

	t.Run("literal-hash-mirrors-g115", func(t *testing.T) {
		const subject = "npm test"
		hash := permissions.ComputeArgumentHash(subject)
		sess, store := emitFixture()
		if err := emitMatched(store, "literal", subject, "/home/u/proj", "session", "/home/u/proj", "session_grant", "grant", hash, ""); err != nil {
			t.Fatalf("EmitMatched() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		var got PermissionMatched
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		// The persisted argument_hash must equal the permission-entry hash so
		// the event's denormalized hash stays aligned with the matched entry.
		if got.ArgumentHash != permissions.ComputeArgumentHash(subject) {
			t.Errorf("argument_hash = %q, want ComputeArgumentHash(%q) = %q", got.ArgumentHash, subject, permissions.ComputeArgumentHash(subject))
		}
	})

	// A generalized compound grant records the compound encoding as the matched
	// subject (its `:*` markers are the audit record of which stages widened) and an argument_hash
	// that pins exactly that encoding. The payload validator accepts it under the same literal-subject
	// rule as a byte-exact literal — argument_hash == SHA-256(subject) — with no schema change.
	t.Run("generalized-compound-subject-and-hash", func(t *testing.T) {
		subject, err := permissions.EncodeCompoundSubject(true, []string{"gofmt :*", "go build :*"}, []string{"&&"})
		if err != nil {
			t.Fatalf("EncodeCompoundSubject error: %v", err)
		}
		hash := permissions.ComputeArgumentHash(subject)
		sess, store := emitFixture()
		if err := emitMatched(store, "literal", subject, "/home/u/proj", "folder", "/home/u/proj", "folder_grant", "grant", hash, ""); err != nil {
			t.Fatalf("EmitMatched(generalized compound) error = %v", err)
		}
		ev := reloadOnly(t, sess)
		var got PermissionMatched
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if got.Subject != subject {
			t.Errorf("subject = %q, want the compound encoding %q", got.Subject, subject)
		}
		if got.ArgumentHash != hash {
			t.Errorf("argument_hash = %q, want SHA-256 of the pinned encoding %q", got.ArgumentHash, hash)
		}
	})

	// A Plan mode-posture decision is recorded as permission_matched with
	// outcome_source "mode_auto" and no grant fields, read back from the
	// persisted record store.
	t.Run("mode-auto-allow-omits-grant", func(t *testing.T) {
		sess, store := emitFixture()
		if err := emitMatched(store, "tool", "read_file", "/home/u/proj", "", "", "once", "mode_auto", "", ""); err != nil {
			t.Fatalf("EmitMatched() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		if strings.Contains(string(ev.Payload), "grant_kind") || strings.Contains(string(ev.Payload), "grant_path_scope") {
			t.Errorf("mode_auto allow persisted grant fields: %s", ev.Payload)
		}
		var got PermissionMatched
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		want := PermissionMatched{SubjectKind: "tool", Subject: "read_file", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "mode_auto"}
		if got != want {
			t.Errorf("persisted payload = %#v, want %#v", got, want)
		}
	})

	t.Run("mode-auto-literal-deny-carries-hash", func(t *testing.T) {
		const subject = "npm test"
		sess, store := emitFixture()
		// A literal-shell Plan denial records the same argument_hash projection a grant
		// match would, even though it carries no grant fields.
		if err := emitMatched(store, "literal", subject, "/home/u/proj", "", "", "deny", "mode_auto", permissions.ComputeArgumentHash(subject), ""); err != nil {
			t.Fatalf("EmitMatched() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		var got PermissionMatched
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if got.OutcomeSource != "mode_auto" || got.Outcome != "deny" {
			t.Errorf("persisted mode_auto deny = %#v, want outcome_source mode_auto / outcome deny", got)
		}
		if got.GrantKind != "" || got.GrantPathScope != "" {
			t.Errorf("mode_auto deny carried grant fields: %#v", got)
		}
		if got.ArgumentHash != permissions.ComputeArgumentHash(subject) {
			t.Errorf("argument_hash = %q, want %q", got.ArgumentHash, permissions.ComputeArgumentHash(subject))
		}
	})

	// An Auto edits in-scope approval — the edit tool and its create analog — is
	// recorded as permission_matched with outcome_source "mode_auto", outcome "once", subject_kind
	// "tool", the tool name as subject, the resolved containing-directory path_scope, and no grant
	// fields — read back from the persisted record store (Auto edits bullet, 170, 270).
	// The two cases differ only in the tool subject.
	for _, tc := range []struct{ tag, subject string }{
		{"g500", "edit"},
		{"g515", "create"},
	} {
		t.Run(tc.tag+"-auto-edits-"+tc.subject+"-approval", func(t *testing.T) {
			sess, store := emitFixture()
			if err := emitMatched(store, "tool", tc.subject, "/home/u/proj/sub", "", "", "once", "mode_auto", "", ""); err != nil {
				t.Fatalf("EmitMatched() error = %v", err)
			}
			ev := reloadOnly(t, sess)
			if strings.Contains(string(ev.Payload), "grant_kind") || strings.Contains(string(ev.Payload), "grant_path_scope") || strings.Contains(string(ev.Payload), "argument_hash") {
				t.Errorf("mode_auto %s approval persisted grant/hash fields: %s", tc.subject, ev.Payload)
			}
			var got PermissionMatched
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			want := PermissionMatched{SubjectKind: "tool", Subject: tc.subject, PathScope: "/home/u/proj/sub", Outcome: "once", OutcomeSource: "mode_auto"}
			if got != want {
				t.Errorf("persisted payload = %#v, want %#v", got, want)
			}
		})
	}
}

func TestEmitPersistFailed(t *testing.T) {
	t.Run("global-records-degraded-scope", func(t *testing.T) {
		sess, store := emitFixture()
		if err := EmitPersistFailed(store, "/home/u/.codemeld/global/settings.yaml", "global", "direct", "git status", "write_error", "io_error", "write: io error", "/home/u/proj"); err != nil {
			t.Fatalf("EmitPersistFailed() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		if ev.Kind != KindPermissionPersistFailed {
			t.Errorf("kind = %q, want %q", ev.Kind, KindPermissionPersistFailed)
		}
		var got PermissionPersistFailed
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		want := PermissionPersistFailed{TargetPath: "/home/u/.codemeld/global/settings.yaml", GrantKind: "global", SubjectKind: "direct", Subject: "git status", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "write: io error", DegradedToPathScope: "/home/u/proj"}
		if got != want {
			t.Errorf("persisted payload = %#v, want %#v", got, want)
		}
	})

	t.Run("project-host-records-retained-host", func(t *testing.T) {
		sess, store := emitFixture()
		if err := EmitPersistFailed(store, "/home/u/proj/.codemeld/settings.yaml", "project", "host", "web_fetch", "write_error", "io_error", "write: io error", "docs.example.com"); err != nil {
			t.Fatalf("EmitPersistFailed() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		if strings.Contains(string(ev.Payload), "degraded_to_path_scope") {
			t.Errorf("host persist failure persisted a degraded path scope: %s", ev.Payload)
		}
		var got PermissionPersistFailed
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		want := PermissionPersistFailed{TargetPath: "/home/u/proj/.codemeld/settings.yaml", GrantKind: "project", SubjectKind: "host", Subject: "web_fetch", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "write: io error", HostScope: "docs.example.com"}
		if got != want {
			t.Errorf("persisted payload = %#v, want %#v", got, want)
		}
	})

	t.Run("folder-lock-timeout-omits-category-and-degraded", func(t *testing.T) {
		sess, store := emitFixture()
		// lock_timeout originates in no file syscall: error_category is empty and a
		// folder grant carries no degraded scope, so both must be absent on disk.
		if err := EmitPersistFailed(store, "/home/u/proj/.codemeld/settings.yaml", "folder", "tool", "Read", "lock_timeout", "", lockTimeoutDetail, ""); err != nil {
			t.Fatalf("EmitPersistFailed() error = %v", err)
		}
		ev := reloadOnly(t, sess)
		if strings.Contains(string(ev.Payload), "error_category") || strings.Contains(string(ev.Payload), "degraded_to_path_scope") {
			t.Errorf("folder lock_timeout persisted optional fields: %s", ev.Payload)
		}
		var got PermissionPersistFailed
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if got.ErrorDetail != lockTimeoutDetail {
			t.Errorf("error_detail = %q, want %q", got.ErrorDetail, lockTimeoutDetail)
		}
	})
}

// TestEmitMatched_RejectsInvalidCombos confirms the append-time validators
// still reject the reserved/forbidden permission_matched combinations through the
// emitter, appending nothing.
func TestEmitMatched_RejectsInvalidCombos(t *testing.T) {
	t.Run("outcome-source-prompt", func(t *testing.T) {
		store := newStore()
		// "prompt" is reserved: the prompt path emits permission_decision instead.
		err := emitMatched(store, "direct", "git status", "/home/u/proj", "folder", "/home/u/proj", "folder_grant", "prompt", "", "")
		if err == nil {
			t.Fatal("EmitMatched() accepted outcome_source=prompt")
		}
		if got := len(store.Records()); got != 0 {
			t.Errorf("rejected emit still appended %d record(s)", got)
		}
	})
}

// TestEmitDecision_RejectsDeniedWithGrant confirms a denied decision carrying
// grant fields is rejected at append time and appends nothing.
func TestEmitDecision_RejectsDeniedWithGrant(t *testing.T) {
	store := newStore()
	err := EmitDecision(store, "direct", "rm -rf /", "/home/u/proj", "denied", "folder", "/home/u/proj", "", "")
	if err == nil {
		t.Fatal("EmitDecision() accepted denied outcome with grant fields")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("rejected emit still appended %d record(s)", got)
	}
}

func TestPermissionEvents_PathFormBytesUnchanged(t *testing.T) {
	cases := []struct {
		name string
		emit func(*sessions.Store) error
		want string
	}{
		{
			"prompt_shown/direct",
			func(s *sessions.Store) error {
				return EmitPromptShown(s, "direct", "git status", "/home/u/proj", nil, "", "")
			},
			`{"subject_kind":"direct","subject":"git status","path_scope":"/home/u/proj"}`,
		},
		{
			"decision/folder",
			func(s *sessions.Store) error {
				return EmitDecision(s, "direct", "git status", "/home/u/proj", "granted", "folder", "/home/u/proj", "", "")
			},
			`{"subject_kind":"direct","subject":"git status","path_scope":"/home/u/proj","outcome":"granted","grant_kind":"folder","grant_path_scope":"/home/u/proj"}`,
		},
		{
			"matched/global",
			func(s *sessions.Store) error {
				return emitMatched(s, "tool", "Read", "/home/u/proj", "global", "*", "global_grant", "grant", "", "")
			},
			`{"subject_kind":"tool","subject":"Read","path_scope":"/home/u/proj","grant_kind":"global","grant_path_scope":"*","outcome":"global_grant","outcome_source":"grant"}`,
		},
		{
			"persist_failed/global",
			func(s *sessions.Store) error {
				return EmitPersistFailed(s, "/home/u/.codemeld/global/settings.yaml", "global", "direct", "git status", "write_error", "io_error", "write: io error", "/home/u/proj")
			},
			`{"target_path":"/home/u/.codemeld/global/settings.yaml","grant_kind":"global","subject_kind":"direct","subject":"git status","reason":"write_error","error_category":"io_error","error_detail":"write: io error","degraded_to_path_scope":"/home/u/proj"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, store := emitFixture()
			if err := tc.emit(store); err != nil {
				t.Fatalf("emit error = %v", err)
			}
			if got := string(reloadOnly(t, sess).Payload); got != tc.want {
				t.Errorf("persisted payload =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

func TestEmitHostForms_RejectInvalidScopes(t *testing.T) {
	cases := []struct {
		name string
		emit func(*sessions.Store) error
	}{
		{"prompt_shown/wildcard-host", func(s *sessions.Store) error {
			return EmitPromptShown(s, "host", "web_fetch", "*", nil, "", "")
		}},
		{"prompt_shown/non-canonical-host", func(s *sessions.Store) error {
			return EmitPromptShown(s, "host", "web_fetch", "Docs.Example.com.", nil, "", "")
		}},
		{"prompt_shown/missing-host", func(s *sessions.Store) error {
			return EmitPromptShown(s, "host", "web_fetch", "", nil, "", "")
		}},
		{"prompt_shown/non-web-subject", func(s *sessions.Store) error {
			return EmitPromptShown(s, "host", "Read", "docs.example.com", nil, "", "")
		}},
		{"decision/wildcard-host", func(s *sessions.Store) error {
			return EmitDecision(s, "host", "web_fetch", "*", "granted", "project", "*", "", "")
		}},
		{"decision/non-canonical-host", func(s *sessions.Store) error {
			return EmitDecision(s, "host", "web_fetch", "Docs.Example.com.", "granted", "project", "Docs.Example.com.", "", "")
		}},
		{"decision/grant-host-differs-from-request", func(s *sessions.Store) error {
			return EmitDecision(s, "host", "web_fetch", "docs.example.com", "granted", "project", "evil.example.com", "", "")
		}},
		{"decision/missing-host", func(s *sessions.Store) error {
			return EmitDecision(s, "host", "web_fetch", "", "granted", "project", "", "", "")
		}},
		{"decision/non-web-subject", func(s *sessions.Store) error {
			return EmitDecision(s, "host", "Read", "docs.example.com", "granted", "project", "docs.example.com", "", "")
		}},
		{"matched/folder-lifetime", func(s *sessions.Store) error {
			return emitMatched(s, "host", "web_fetch", "docs.example.com", "folder", "docs.example.com", "folder_grant", "grant", "", "")
		}},
		{"persist_failed/global-grant-kind", func(s *sessions.Store) error {
			return EmitPersistFailed(s, "/home/u/proj/.codemeld/settings.yaml", "global", "host", "web_fetch", "write_error", "io_error", "write: io error", "docs.example.com")
		}},
		{"persist_failed/missing-host", func(s *sessions.Store) error {
			return EmitPersistFailed(s, "/home/u/proj/.codemeld/settings.yaml", "project", "host", "web_fetch", "write_error", "io_error", "write: io error", "")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if err := tc.emit(store); err == nil {
				t.Fatal("emitter accepted an invalid host form")
			}
			if got := len(store.Records()); got != 0 {
				t.Errorf("rejected emit still appended %d record(s)", got)
			}
		})
	}
}

// TestEmitPersistFailed_RejectsWrongLockTimeoutDetail confirms the validator's
// canonical lock_timeout error_detail contract is enforced through the emitter: a
// non-canonical detail is rejected and nothing is appended.
func TestEmitPersistFailed_RejectsWrongLockTimeoutDetail(t *testing.T) {
	store := newStore()
	err := EmitPersistFailed(store, "/home/u/proj/.codemeld/settings.yaml", "folder", "tool", "Read", "lock_timeout", "", "nope", "")
	if err == nil {
		t.Fatal("EmitPersistFailed() accepted a non-canonical lock_timeout detail")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("rejected emit still appended %d record(s)", got)
	}
}

func TestEmitPromptShown_DirectTokens(t *testing.T) {
	cases := []struct {
		name    string
		tokens  []string
		subject string
		want    string
	}{
		{
			"quoted-whitespace-argument",
			[]string{"git", "commit", "-m", "First task"},
			"git commit -m First task",
			`{"subject_kind":"direct","subject":"git commit -m First task","path_scope":"/home/u/proj","direct_tokens":["git","commit","-m","First task"]}`,
		},
		{
			"empty-argument",
			[]string{"grep", "", "file.txt"},
			"grep  file.txt",
			`{"subject_kind":"direct","subject":"grep  file.txt","path_scope":"/home/u/proj","direct_tokens":["grep","","file.txt"]}`,
		},
		{
			"single-token",
			[]string{"ls"},
			"ls",
			`{"subject_kind":"direct","subject":"ls","path_scope":"/home/u/proj","direct_tokens":["ls"]}`,
		},
		{
			"literal-colon-star-argument",
			[]string{"git", ":*"},
			"git :*",
			`{"subject_kind":"direct","subject":"git :*","path_scope":"/home/u/proj","direct_tokens":["git",":*"]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, store := emitFixture()
			if err := EmitPromptShown(store, "direct", tc.subject, "/home/u/proj", tc.tokens, "", ""); err != nil {
				t.Fatalf("EmitPromptShown() error = %v", err)
			}
			ev := reloadOnly(t, sess)
			if got := string(ev.Payload); got != tc.want {
				t.Errorf("persisted payload =\n%s\nwant\n%s", got, tc.want)
			}
			var got PermissionPromptShown
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if got.DirectTokens == nil {
				t.Fatal("reloaded payload has no direct_tokens")
			}
			if !slices.Equal(*got.DirectTokens, tc.tokens) {
				t.Errorf("direct_tokens = %q, want %q", *got.DirectTokens, tc.tokens)
			}
		})
	}
}

func TestEmitPromptShown_DirectTokensCopiedFromCaller(t *testing.T) {
	sess, store := emitFixture()
	tokens := []string{"git", "commit", "-m", "First task"}
	if err := EmitPromptShown(store, "direct", "git commit -m First task", "/home/u/proj", tokens, "", ""); err != nil {
		t.Fatalf("EmitPromptShown() error = %v", err)
	}
	tokens[3] = "mutated"
	ev := reloadOnly(t, sess)
	want := `{"subject_kind":"direct","subject":"git commit -m First task","path_scope":"/home/u/proj","direct_tokens":["git","commit","-m","First task"]}`
	if got := string(ev.Payload); got != want {
		t.Errorf("persisted payload =\n%s\nwant\n%s", got, want)
	}
}

func TestEmitPromptShown_OmitsDirectTokensForOtherKinds(t *testing.T) {
	cases := []struct {
		name        string
		subjectKind string
		subject     string
		scope       string
	}{
		{"literal", "literal", "cat foo | wc -l", "/home/u/proj"},
		{"tool", "tool", "Read", "/home/u/proj"},
		{"host", "host", "web_fetch", "docs.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, store := emitFixture()
			if err := EmitPromptShown(store, tc.subjectKind, tc.subject, tc.scope, nil, "", ""); err != nil {
				t.Fatalf("EmitPromptShown() error = %v", err)
			}
			ev := reloadOnly(t, sess)
			if strings.Contains(string(ev.Payload), "direct_tokens") {
				t.Errorf("%s prompt persisted direct_tokens: %s", tc.subjectKind, ev.Payload)
			}
		})
	}
}

func TestEmitPromptShown_RejectsInvalidDirectTokens(t *testing.T) {
	cases := []struct {
		name        string
		subjectKind string
		subject     string
		scope       string
		tokens      []string
	}{
		{"literal-kind", "literal", "cat foo | wc -l", "/home/u/proj", []string{"cat", "foo"}},
		{"tool-kind", "tool", "Read", "/home/u/proj", []string{"Read"}},
		{"host-kind", "host", "web_fetch", "docs.example.com", []string{"web_fetch"}},
		{"empty-array", "direct", "git status", "/home/u/proj", []string{}},
		{"subject-mismatch", "direct", "git status", "/home/u/proj", []string{"git", "commit"}},
		{"extra-trailing-token", "direct", "git status", "/home/u/proj", []string{"git", "status", "--short"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if err := EmitPromptShown(store, tc.subjectKind, tc.subject, tc.scope, tc.tokens, "", ""); err == nil {
				t.Fatal("EmitPromptShown() accepted an invalid direct_tokens value")
			}
			if got := len(store.Records()); got != 0 {
				t.Errorf("rejected emit still appended %d record(s)", got)
			}
		})
	}
}

func TestValidatePayload_PromptShownDirectTokens(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		wantErr bool
	}{
		{"legacy-direct-without-tokens", `{"subject_kind":"direct","subject":"git commit -m First task","path_scope":"/home/u/proj"}`, false},
		{"legacy-literal-without-tokens", `{"subject_kind":"literal","subject":"cat foo | wc -l","path_scope":"/home/u/proj"}`, false},
		{"present-and-consistent", `{"subject_kind":"direct","subject":"git commit -m First task","path_scope":"/home/u/proj","direct_tokens":["git","commit","-m","First task"]}`, false},
		{"present-empty-array", `{"subject_kind":"direct","subject":"git status","path_scope":"/home/u/proj","direct_tokens":[]}`, true},
		{"present-null", `{"subject_kind":"direct","subject":"git status","path_scope":"/home/u/proj","direct_tokens":null}`, true},
		{"subject-mismatch", `{"subject_kind":"direct","subject":"git status","path_scope":"/home/u/proj","direct_tokens":["git","commit"]}`, true},
		{"unrelated-kind-literal", `{"subject_kind":"literal","subject":"git status","path_scope":"/home/u/proj","direct_tokens":["git","status"]}`, true},
		{"unrelated-kind-tool", `{"subject_kind":"tool","subject":"Read","path_scope":"/home/u/proj","direct_tokens":["Read"]}`, true},
		{"unrelated-kind-host", `{"subject_kind":"host","subject":"web_fetch","host_scope":"docs.example.com","direct_tokens":["web_fetch"]}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(KindPermissionPromptShown, json.RawMessage(tc.payload))
			if tc.wantErr && err == nil {
				t.Fatal("ValidatePayload() accepted an invalid direct_tokens value")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidatePayload() error = %v", err)
			}
		})
	}
}

func TestPromptShown_LegacyAbsenceIsUnknown(t *testing.T) {
	const legacy = `{"subject_kind":"direct","subject":"git commit -m First task","path_scope":"/home/u/proj"}`
	var got PermissionPromptShown
	if err := json.Unmarshal([]byte(legacy), &got); err != nil {
		t.Fatalf("unmarshal legacy payload: %v", err)
	}
	if got.DirectTokens != nil {
		t.Fatalf("legacy record decoded direct_tokens = %q, want nil", *got.DirectTokens)
	}
	if resplit := strings.Split(got.Subject, " "); len(resplit) == 4 {
		t.Fatal("test premise broken: the flattened subject is not lossy")
	}
}

func TestDirectTokensReplayAgainstStoredGrantSyntax(t *testing.T) {
	sess, store := emitFixture()
	tokens := []string{"git", "commit", "-m", "First task"}
	if err := EmitPromptShown(store, "direct", strings.Join(tokens, " "), "/home/u/proj", tokens, "", ""); err != nil {
		t.Fatalf("EmitPromptShown() error = %v", err)
	}
	var persisted PermissionPromptShown
	if err := json.Unmarshal(reloadOnly(t, sess).Payload, &persisted); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if persisted.DirectTokens == nil {
		t.Fatal("reloaded payload has no direct_tokens")
	}
	replay := *persisted.DirectTokens

	cases := []struct {
		name         string
		grantSubject string
		want         bool
	}{
		{"bare-wildcard-covers-later-tokens", `git commit :*`, true},
		{"bare-wildcard-on-program", `git :*`, true},
		{"quoted-wildcard-is-literal", `git commit ":*"`, false},
		{"escaped-wildcard-is-literal", `git commit :\*`, false},
		{"exact-quoted-argument", `git commit -m "First task"`, true},
		{"resplit-argument-does-not-match", `git commit -m First task`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := permissions.MatchesDirectSubject(replay, nil, false, tc.grantSubject); got != tc.want {
				t.Errorf("MatchesDirectSubject(%q, %q) = %v, want %v", replay, tc.grantSubject, got, tc.want)
			}
		})
	}

	literal := []string{"git", ":*"}
	if !permissions.MatchesDirectSubject(literal, nil, false, `git ":*"`) {
		t.Error("a quoted literal :* grant must still match the literal :* argument")
	}
	if permissions.MatchesDirectSubject([]string{"git", "push", "--force"}, nil, false, `git ":*"`) {
		t.Error("a quoted literal :* grant must not behave as a wildcard")
	}
}

// --- declared write scopes ---

// TestPermissionMatched_AppendTimeVocabularyStaysClosed proves the writer accepts the new
// declared_scope source and nothing outside the known vocabulary, so a misspelled or future source
// can never be persisted by this build.
func TestPermissionMatched_AppendTimeVocabularyStaysClosed(t *testing.T) {
	accepted := []struct {
		name    string
		payload PermissionMatched
	}{
		{"declared-scope allow", PermissionMatched{SubjectKind: "tool", Subject: "create", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "declared_scope"}},
		{"declared-scope deny", PermissionMatched{SubjectKind: "tool", Subject: "delete", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "declared_scope"}},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.payload); err != nil {
				t.Fatalf("Append() rejected a valid declared_scope record: %v", err)
			}
			if got := len(store.Records()); got != 1 {
				t.Errorf("accepted append stored %d record(s), want 1", got)
			}
			if _, err := Build(tc.payload); err != nil {
				t.Fatalf("Build() rejected a valid declared_scope record: %v", err)
			}
		})
	}

	rejected := []struct {
		name    string
		payload PermissionMatched
	}{
		{"empty source", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", Outcome: "once"}},
		{"reserved prompt source", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "prompt"}},
		{"misspelled known source", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "declared-scope"}},
		{"hypothetical future source", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "policy_engine"}},
		{"declared scope with a grant outcome", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "folder_grant", OutcomeSource: "declared_scope"}},
		{"declared scope once carrying grant fields", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "declared_scope"}},
		{"grant match deny carrying grant fields", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "grant"}},
		{"grant match once without grant fields", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "grant"}},
		{"grant match deny without grant fields", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "grant"}},
		{"host grant match once without grant fields", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com", Outcome: "once", OutcomeSource: "grant"}},
		{"host grant match deny without grant fields", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com", Outcome: "deny", OutcomeSource: "grant"}},
		{"declared scope on a host record", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com", Outcome: "once", OutcomeSource: "declared_scope"}},
		{"mode auto on a host record", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com", Outcome: "once", OutcomeSource: "mode_auto"}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.payload); err == nil {
				t.Fatalf("Append() accepted %s", tc.name)
			}
			if got := len(store.Records()); got != 0 {
				t.Errorf("rejected append still stored %d record(s)", got)
			}
			if _, err := Build(tc.payload); err == nil {
				t.Fatalf("Build() accepted %s", tc.name)
			}
		})
	}
}

func TestPermissionMatched_DeclaredCommandAppendTimeVocabulary(t *testing.T) {
	accepted := []struct {
		name    string
		payload PermissionMatched
	}{
		{"declared-command allow", PermissionMatched{SubjectKind: "direct", Subject: "prep-open-tasks.sh --only i425", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "declared_command"}},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.payload); err != nil {
				t.Fatalf("Append() rejected a valid declared_command record: %v", err)
			}
			if got := len(store.Records()); got != 1 {
				t.Errorf("accepted append stored %d record(s), want 1", got)
			}
			if _, err := Build(tc.payload); err != nil {
				t.Fatalf("Build() rejected a valid declared_command record: %v", err)
			}
		})
	}

	rejected := []struct {
		name    string
		payload PermissionMatched
	}{
		{"declared-command deny", PermissionMatched{SubjectKind: "direct", Subject: "prep-open-tasks.sh --only i425", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "declared_command"}},
		{"declared-command with a grant outcome", PermissionMatched{SubjectKind: "direct", Subject: "prep-open-tasks.sh --only i425", PathScope: "/home/u/proj", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "folder_grant", OutcomeSource: "declared_command"}},
		{"declared-command once carrying grant fields", PermissionMatched{SubjectKind: "direct", Subject: "prep-open-tasks.sh --only i425", PathScope: "/home/u/proj", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "declared_command"}},
		{"declared-command on a host record", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com", Outcome: "once", OutcomeSource: "declared_command"}},
		{"declared-command with an argument_hash", PermissionMatched{SubjectKind: "direct", Subject: "prep-open-tasks.sh --only i425", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "declared_command", ArgumentHash: strings.Repeat("a", 64)}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.payload); err == nil {
				t.Fatalf("Append() accepted %s", tc.name)
			}
			if got := len(store.Records()); got != 0 {
				t.Errorf("rejected append still stored %d record(s)", got)
			}
			if _, err := Build(tc.payload); err == nil {
				t.Fatalf("Build() accepted %s", tc.name)
			}
		})
	}
}

func TestPermissionMatched_ConfinedSource(t *testing.T) {
	accepted := []PermissionMatched{
		{SubjectKind: "direct", Subject: "touch a", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "confined"},
		{SubjectKind: "literal", Subject: "ls > out", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "confined", ArgumentHash: literalArgumentHash("ls > out")},
	}
	for _, payload := range accepted {
		t.Run("accepted "+payload.SubjectKind, func(t *testing.T) {
			if _, err := Append(newStore(), payload); err != nil {
				t.Fatalf("Append() rejected a valid confined record: %v", err)
			}
		})
	}

	rejected := []struct {
		name    string
		payload PermissionMatched
	}{
		{"deny", PermissionMatched{SubjectKind: "direct", Subject: "touch a", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "confined"}},
		{"tool subject", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "confined"}},
		{"host subject", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com", Outcome: "once", OutcomeSource: "confined"}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Append(newStore(), tc.payload); err == nil {
				t.Fatalf("Append() accepted %s", tc.name)
			}
		})
	}
}

func TestPermissionMatched_OpenReadAppendTimeVocabulary(t *testing.T) {
	for _, subject := range []string{"read", "read_image", "grep", "glob", "list", "tree", "file_count"} {
		t.Run("accepted "+subject, func(t *testing.T) {
			payload := PermissionMatched{SubjectKind: "tool", Subject: subject, PathScope: "/home/u/other", Outcome: "once", OutcomeSource: "open_read"}
			store := newStore()
			if _, err := Append(store, payload); err != nil {
				t.Fatalf("Append() rejected a valid open_read record: %v", err)
			}
			if got := len(store.Records()); got != 1 {
				t.Errorf("accepted append stored %d record(s), want 1", got)
			}
			if _, err := Build(payload); err != nil {
				t.Fatalf("Build() rejected a valid open_read record: %v", err)
			}
		})
	}

	rejected := []struct {
		name    string
		payload PermissionMatched
	}{
		{"open-read deny", PermissionMatched{SubjectKind: "tool", Subject: "read", PathScope: "/home/u/other", Outcome: "deny", OutcomeSource: "open_read"}},
		{"open-read with a grant outcome", PermissionMatched{SubjectKind: "tool", Subject: "read", PathScope: "/home/u/other", GrantKind: "folder", GrantPathScope: "/home/u/other", Outcome: "folder_grant", OutcomeSource: "open_read"}},
		{"open-read on a direct subject", PermissionMatched{SubjectKind: "direct", Subject: "cat /home/u/other/a.txt", PathScope: "/home/u/other", Outcome: "once", OutcomeSource: "open_read"}},
		{"open-read on a write tool", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/other", Outcome: "once", OutcomeSource: "open_read"}},
		{"open-read on a host record", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com", Outcome: "once", OutcomeSource: "open_read"}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.payload); err == nil {
				t.Fatalf("Append() accepted %s", tc.name)
			}
			if got := len(store.Records()); got != 0 {
				t.Errorf("rejected append still stored %d record(s)", got)
			}
			if _, err := Build(tc.payload); err == nil {
				t.Fatalf("Build() accepted %s", tc.name)
			}
		})
	}
}

// TestValidatePayload_PermissionMatchedToleratesFutureSources proves the load path opens a
// shape-valid record whose outcome_source this build does not know, for both path and host
// subjects, so one such record cannot fail a whole session — while every other rule still holds.
func TestValidatePayload_PermissionMatchedToleratesFutureSources(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantErr bool
	}{
		{
			name:    "path record with a future source",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","outcome":"once","outcome_source":"policy_engine"}`,
		},
		{
			name:    "host record with a future source",
			payload: `{"subject_kind":"host","subject":"web_fetch","host_scope":"docs.example.com","outcome":"once","outcome_source":"policy_engine"}`,
		},
		{
			name:    "path record with a future source and a grant outcome",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","grant_kind":"folder","grant_path_scope":"/home/u/proj","outcome":"folder_grant","outcome_source":"policy_engine"}`,
		},
		{
			name:    "declared_scope path record",
			payload: `{"subject_kind":"tool","subject":"create","path_scope":"/home/u/proj","outcome":"once","outcome_source":"declared_scope"}`,
		},
		{
			name:    "declared_command path record",
			payload: `{"subject_kind":"direct","subject":"prep-open-tasks.sh --only i425","path_scope":"/home/u/proj","outcome":"once","outcome_source":"declared_command"}`,
		},
		{
			name:    "declared_command with a deny outcome",
			payload: `{"subject_kind":"direct","subject":"prep-open-tasks.sh --only i425","path_scope":"/home/u/proj","outcome":"deny","outcome_source":"declared_command"}`,
			wantErr: true,
		},
		{
			name:    "declared_command on a host record",
			payload: `{"subject_kind":"host","subject":"web_fetch","host_scope":"docs.example.com","outcome":"once","outcome_source":"declared_command"}`,
			wantErr: true,
		},
		{
			name:    "protected_state path record",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj/.codemeld","outcome":"deny","outcome_source":"protected_state"}`,
		},
		{
			name:    "protected_state with an allow outcome",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj/.codemeld","outcome":"once","outcome_source":"protected_state"}`,
			wantErr: true,
		},
		{
			name:    "protected_state with a non-tool subject",
			payload: `{"subject_kind":"direct","subject":"rm -rf /","path_scope":"/home/u/proj/.codemeld","outcome":"deny","outcome_source":"protected_state"}`,
			wantErr: true,
		},
		{
			name:    "protected_state with an unguarded known tool",
			payload: `{"subject_kind":"tool","subject":"read","path_scope":"/home/u/proj/.codemeld","outcome":"deny","outcome_source":"protected_state"}`,
			wantErr: true,
		},
		{
			name:    "protected_state on a VCS action",
			payload: `{"subject_kind":"tool","subject":"vcs_restore_file","path_scope":"/home/u/proj","outcome":"deny","outcome_source":"protected_state"}`,
		},
		{
			name:    "protected_state on a VCS name that is not a registered action",
			payload: `{"subject_kind":"tool","subject":"vcs_checkout","path_scope":"/home/u/proj","outcome":"deny","outcome_source":"protected_state"}`,
			wantErr: true,
		},
		{
			name:    "protected_state with an unknown tool name",
			payload: `{"subject_kind":"tool","subject":"frobnicate","path_scope":"/home/u/proj/.codemeld","outcome":"deny","outcome_source":"protected_state"}`,
			wantErr: true,
		},
		{
			name:    "protected_state on a host record",
			payload: `{"subject_kind":"host","subject":"web_fetch","host_scope":"docs.example.com","outcome":"deny","outcome_source":"protected_state"}`,
			wantErr: true,
		},
		{
			name:    "blocked_path read record",
			payload: `{"subject_kind":"tool","subject":"read","path_scope":"/home/u/.ssh","outcome":"deny","outcome_source":"blocked_path"}`,
		},
		{
			name:    "blocked_path with an allow outcome",
			payload: `{"subject_kind":"tool","subject":"read","path_scope":"/home/u/.ssh","outcome":"once","outcome_source":"blocked_path"}`,
			wantErr: true,
		},
		{
			name:    "blocked_path on a host record",
			payload: `{"subject_kind":"host","subject":"web_fetch","host_scope":"docs.example.com","outcome":"deny","outcome_source":"blocked_path"}`,
			wantErr: true,
		},
		{
			name:    "blocked_path on a VCS action",
			payload: `{"subject_kind":"tool","subject":"vcs_commit","path_scope":"/home/u/proj","outcome":"deny","outcome_source":"blocked_path"}`,
			wantErr: true,
		},
		{
			name:    "blocked_path on a VCS status action",
			payload: `{"subject_kind":"tool","subject":"vcs_status","path_scope":"/home/u/proj","outcome":"deny","outcome_source":"blocked_path","blocked_entry":"/home/u/proj/secrets"}`,
			wantErr: true,
		},
		{
			name:    "blocked_path on a VCS rewrite action",
			payload: `{"subject_kind":"tool","subject":"vcs_restore_file","path_scope":"/home/u/proj","outcome":"deny","outcome_source":"blocked_path","blocked_entry":"/home/u/proj/secrets"}`,
		},
		{
			name:    "blocked_path record with its entry and source",
			payload: `{"subject_kind":"tool","subject":"read","path_scope":"/home/u/.ssh","outcome":"deny","outcome_source":"blocked_path","blocked_entry":"/home/u/.ssh","blocked_entry_source":"/home/u/.codemeld/global/settings.yaml"}`,
		},
		{
			name:    "blocked_path with a relative entry",
			payload: `{"subject_kind":"tool","subject":"read","path_scope":"/home/u/.ssh","outcome":"deny","outcome_source":"blocked_path","blocked_entry":".ssh"}`,
			wantErr: true,
		},
		{
			name:    "blocked_path on a direct shell record",
			payload: `{"subject_kind":"direct","subject":"cat /home/u/.ssh/k","path_scope":"/home/u/proj","outcome":"deny","outcome_source":"blocked_path","direct_request_subject":"cat /home/u/.ssh/k","blocked_entry":"/home/u/.ssh"}`,
		},
		{
			name:    "blocked_path on a direct shell record with an allow outcome",
			payload: `{"subject_kind":"direct","subject":"cat /home/u/.ssh/k","path_scope":"/home/u/proj","outcome":"once","outcome_source":"blocked_path","blocked_entry":"/home/u/.ssh"}`,
			wantErr: true,
		},
		{
			name:    "open_read path record",
			payload: `{"subject_kind":"tool","subject":"read","path_scope":"/home/u/other","outcome":"once","outcome_source":"open_read"}`,
		},
		{
			name:    "open_read with a deny outcome",
			payload: `{"subject_kind":"tool","subject":"read","path_scope":"/home/u/other","outcome":"deny","outcome_source":"open_read"}`,
			wantErr: true,
		},
		{
			name:    "open_read with a grant outcome",
			payload: `{"subject_kind":"tool","subject":"read","path_scope":"/home/u/other","grant_kind":"folder","grant_path_scope":"/home/u/other","outcome":"folder_grant","outcome_source":"open_read"}`,
			wantErr: true,
		},
		{
			name:    "open_read on a direct subject",
			payload: `{"subject_kind":"direct","subject":"cat /home/u/other/a.txt","path_scope":"/home/u/other","outcome":"once","outcome_source":"open_read"}`,
			wantErr: true,
		},
		{
			name:    "open_read on a write tool",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/other","outcome":"once","outcome_source":"open_read"}`,
			wantErr: true,
		},
		{
			name:    "blocked_entry on a protected_state record",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj/.codemeld","outcome":"deny","outcome_source":"protected_state","blocked_entry":"/home/u/proj/.codemeld"}`,
			wantErr: true,
		},
		{
			name:    "blocked_entry_source on a mode_auto record",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","outcome":"once","outcome_source":"mode_auto","blocked_entry_source":"/home/u/.codemeld/global/settings.yaml"}`,
			wantErr: true,
		},
		{
			name:    "future source with a blocked entry",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","outcome":"deny","outcome_source":"policy_engine","blocked_entry":"/home/u/proj"}`,
		},
		{
			name:    "future source with a relative blocked entry",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","outcome":"deny","outcome_source":"policy_engine","blocked_entry":"proj"}`,
			wantErr: true,
		},
		{
			name:    "empty source",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","outcome":"once","outcome_source":""}`,
			wantErr: true,
		},
		{
			name:    "reserved prompt source",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","outcome":"once","outcome_source":"prompt"}`,
			wantErr: true,
		},
		{
			name:    "known source invalid for a host subject",
			payload: `{"subject_kind":"host","subject":"web_fetch","host_scope":"docs.example.com","outcome":"once","outcome_source":"declared_scope"}`,
			wantErr: true,
		},
		{
			name:    "grant source with a per-call once",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","outcome":"once","outcome_source":"grant"}`,
			wantErr: true,
		},
		{
			name:    "grant source with a per-call deny",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","outcome":"deny","outcome_source":"grant"}`,
			wantErr: true,
		},
		{
			name:    "host grant source with a per-call once",
			payload: `{"subject_kind":"host","subject":"web_fetch","host_scope":"docs.example.com","outcome":"once","outcome_source":"grant"}`,
			wantErr: true,
		},
		{
			name:    "future source with a grant-bearing once",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","grant_kind":"folder","grant_path_scope":"/home/u/proj","outcome":"once","outcome_source":"policy_engine"}`,
			wantErr: true,
		},
		{
			name:    "future source with a malformed grant outcome",
			payload: `{"subject_kind":"tool","subject":"edit","path_scope":"/home/u/proj","grant_kind":"session","grant_path_scope":"/home/u/proj","outcome":"folder_grant","outcome_source":"policy_engine"}`,
			wantErr: true,
		},
		{
			name:    "future host source with a grant-bearing deny",
			payload: `{"subject_kind":"host","subject":"web_fetch","host_scope":"docs.example.com","grant_kind":"session","grant_host_scope":"docs.example.com","outcome":"deny","outcome_source":"policy_engine"}`,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(KindPermissionMatched, json.RawMessage(tc.payload))
			if tc.wantErr && err == nil {
				t.Fatalf("ValidatePayload() accepted %s", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidatePayload() rejected %s: %v", tc.name, err)
			}
		})
	}
}

// TestSessionResume_OpensDeclaredAndFutureOutcomeSources drives the pair a resume runs — the
// production codec plus the ValidatePayload the resume resolver is wired with — over a whole
// session carrying a declared_scope record and one carrying a shape-valid future source.
func TestSessionResume_OpensDeclaredAndFutureOutcomeSources(t *testing.T) {
	for _, source := range []string{"declared_scope", "policy_engine"} {
		t.Run(source, func(t *testing.T) {
			sess, store := emitFixture()
			if err := emitMatched(store, "tool", "create", "/home/u/proj", "", "", "once", "declared_scope", "", ""); err != nil {
				t.Fatalf("EmitMatched() error = %v", err)
			}
			data, err := sessions.Marshal(sess)
			if err != nil {
				t.Fatalf("sessions.Marshal() error = %v", err)
			}
			data = []byte(strings.Replace(string(data), `"outcome_source":"declared_scope"`, `"outcome_source":"`+source+`"`, 1))
			loaded, err := sessions.Unmarshal(data)
			if err != nil {
				t.Fatalf("sessions.Unmarshal() rejected a session carrying outcome_source %q: %v", source, err)
			}
			ev, ok := loaded.Records[0].(sessions.Event)
			if !ok {
				t.Fatalf("reloaded record is %T, want sessions.Event", loaded.Records[0])
			}
			if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
				t.Fatalf("ValidatePayload() rejected outcome_source %q: %v", source, err)
			}
		})
	}
}

// The closed append-time shape must also be the shape a later resume accepts.
func TestSessionResume_OpensProtectedStateDenial(t *testing.T) {
	sess, store := emitFixture()
	if err := emitMatched(store, "tool", "move", "/home/u/proj", "", "", "deny", "protected_state", "", ""); err != nil {
		t.Fatalf("EmitMatched() error = %v", err)
	}
	data, err := sessions.Marshal(sess)
	if err != nil {
		t.Fatalf("sessions.Marshal() error = %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("sessions.Unmarshal() rejected a session carrying a guard denial: %v", err)
	}
	ev, ok := loaded.Records[0].(sessions.Event)
	if !ok {
		t.Fatalf("reloaded record is %T, want sessions.Event", loaded.Records[0])
	}
	if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
		t.Fatalf("ValidatePayload() rejected a guard denial: %v", err)
	}
}

func TestSessionResume_OpensLegacyBlockedPathDenial(t *testing.T) {
	sess, store := emitFixture()
	p := PermissionMatched{SubjectKind: "tool", Subject: "read", PathScope: "/home/u/.ssh", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/.ssh"}
	if _, err := Append(store, p); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	data, err := sessions.Marshal(sess)
	if err != nil {
		t.Fatalf("sessions.Marshal() error = %v", err)
	}
	legacy := strings.Replace(string(data), `,"blocked_entry":"/home/u/.ssh"`, "", 1)
	if strings.Contains(legacy, "blocked_entry") {
		t.Fatalf("legacy fixture still carries an entry field:\n%s", legacy)
	}
	loaded, err := sessions.Unmarshal([]byte(legacy))
	if err != nil {
		t.Fatalf("sessions.Unmarshal() rejected a legacy blocked_path denial: %v", err)
	}
	ev, ok := loaded.Records[0].(sessions.Event)
	if !ok {
		t.Fatalf("reloaded record is %T, want sessions.Event", loaded.Records[0])
	}
	if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
		t.Fatalf("ValidatePayload() rejected a legacy blocked_path denial: %v", err)
	}
}

func TestEmitDirectIdentitiesAreOpaqueAndLegacyCompatible(t *testing.T) {
	const command = "git commit -m 'a b'"
	request, err := permissions.EncodeDirectEnvSubject([]string{"FOO=a b"}, false, command)
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject: %v", err)
	}
	tokens := []string{"git", "commit", "-m", "a b"}
	joined := strings.Join(tokens, " ")

	sess, store := emitFixture()
	if err := EmitPromptShown(store, "direct", joined, "/home/u/proj", tokens, command, request); err != nil {
		t.Fatalf("EmitPromptShown() error = %v", err)
	}
	if err := EmitDecisionGrant(store, "direct", joined, "/home/u/proj", "folder", "/home/u/proj", request, command, request); err != nil {
		t.Fatalf("EmitDecisionGrant() error = %v", err)
	}
	if err := EmitMatchedIdentity(store, "direct", joined, "/home/u/proj", "folder", "/home/u/proj", "folder_grant", "grant", "", request); err != nil {
		t.Fatalf("EmitMatchedIdentity() error = %v", err)
	}

	reloaded := reloadRecords(t, sess)
	if len(reloaded) != 3 {
		t.Fatalf("reloaded records = %d, want 3", len(reloaded))
	}

	var prompt PermissionPromptShown
	mustUnmarshal(t, reloaded[0].Payload, &prompt)
	if prompt.Subject != joined || !slices.Equal(*prompt.DirectTokens, tokens) {
		t.Fatalf("prompt legacy fields = %q/%v, want %q/%v", prompt.Subject, *prompt.DirectTokens, joined, tokens)
	}
	if prompt.DirectCommandSubject != command || prompt.DirectRequestSubject != request {
		t.Fatalf("prompt identities = %q/%q, want %q/%q", prompt.DirectCommandSubject, prompt.DirectRequestSubject, command, request)
	}

	var decision PermissionDecision
	mustUnmarshal(t, reloaded[1].Payload, &decision)
	if decision.Subject != joined || decision.DirectCommandSubject != command || decision.DirectRequestSubject != request {
		t.Fatalf("decision = %+v, want subject %q and identities %q/%q", decision, joined, command, request)
	}

	var matched PermissionMatched
	mustUnmarshal(t, reloaded[2].Payload, &matched)
	if matched.Subject != joined || matched.DirectRequestSubject != request {
		t.Fatalf("matched = %+v, want subject %q and identity %q", matched, joined, request)
	}
}

func TestDirectIdentityFieldsRejectInvalidPresence(t *testing.T) {
	cases := []struct {
		name    string
		payload EventPayload
	}{
		{"prompt on a tool subject", PermissionPromptShown{
			SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj",
			DirectCommandSubject: "ls", DirectRequestSubject: "ls",
		}},
		{"prompt with only the command identity", PermissionPromptShown{
			SubjectKind: "direct", Subject: "ls", PathScope: "/home/u/proj", DirectCommandSubject: "ls",
		}},
		{"prompt with only the request identity", PermissionPromptShown{
			SubjectKind: "direct", Subject: "ls", PathScope: "/home/u/proj", DirectRequestSubject: "ls",
		}},
		{"decision on a literal subject", PermissionDecision{
			SubjectKind: "literal", Subject: "cat a | wc", PathScope: "/home/u/proj", Outcome: "granted",
			DirectCommandSubject: "ls", DirectRequestSubject: "ls",
		}},
		{"decision with only the request identity", PermissionDecision{
			SubjectKind: "direct", Subject: "ls", PathScope: "/home/u/proj", Outcome: "granted",
			DirectRequestSubject: "ls",
		}},
		{"matched on a tool subject", PermissionMatched{
			SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", Outcome: "once",
			OutcomeSource: "mode_auto", DirectRequestSubject: "ls",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.payload); err == nil {
				t.Fatal("Append accepted an invalid direct identity field combination")
			}
			if got := len(store.Records()); got != 0 {
				t.Errorf("rejected append still added %d record(s)", got)
			}
		})
	}
}

func TestLegacyDirectRecordsLoadWithoutIdentities(t *testing.T) {
	sess, store := emitFixture()
	tokens := []string{"git", "status"}
	if err := EmitPromptShown(store, "direct", "git status", "/home/u/proj", tokens, "", ""); err != nil {
		t.Fatalf("EmitPromptShown() error = %v", err)
	}
	reloaded := reloadRecords(t, sess)
	if strings.Contains(string(reloaded[0].Payload), "direct_command_subject") ||
		strings.Contains(string(reloaded[0].Payload), "direct_request_subject") {
		t.Fatalf("absent identities were persisted: %s", reloaded[0].Payload)
	}
	var prompt PermissionPromptShown
	mustUnmarshal(t, reloaded[0].Payload, &prompt)
	if prompt.DirectCommandSubject != "" || prompt.DirectRequestSubject != "" {
		t.Fatalf("legacy record decoded identities %q/%q, want none", prompt.DirectCommandSubject, prompt.DirectRequestSubject)
	}
}

func TestPermissionEvents_ChildAttributionRoundTrip(t *testing.T) {
	child := ids.NewV7()
	const scope = "/home/u/proj/a.txt"

	tests := []struct {
		name string
		emit func(store *sessions.Store, childInvocationID string) error
		read func(t *testing.T, payload json.RawMessage) string
	}{
		{"prompt_shown", func(store *sessions.Store, id string) error {
			return EmitPromptShownAttributed(store, "tool", "edit", scope, nil, "", "", id)
		}, func(t *testing.T, payload json.RawMessage) string {
			var got PermissionPromptShown
			mustUnmarshal(t, payload, &got)
			return got.ChildInvocationID
		}},
		{"decision", func(store *sessions.Store, id string) error {
			return EmitDecisionAttributed(store, "tool", "edit", scope, "denied", "", "", "", "", id)
		}, func(t *testing.T, payload json.RawMessage) string {
			var got PermissionDecision
			mustUnmarshal(t, payload, &got)
			return got.ChildInvocationID
		}},
		{"decision_grant", func(store *sessions.Store, id string) error {
			return EmitDecisionGrantAttributed(store, "tool", "edit", scope, "session", scope, "edit", "", "", id)
		}, func(t *testing.T, payload json.RawMessage) string {
			var got PermissionDecision
			mustUnmarshal(t, payload, &got)
			return got.ChildInvocationID
		}},
		{"matched", func(store *sessions.Store, id string) error {
			return emitMatched(store, "tool", "edit", scope, "", "", "once", "declared_scope", "", id)
		}, func(t *testing.T, payload json.RawMessage) string {
			var got PermissionMatched
			mustUnmarshal(t, payload, &got)
			return got.ChildInvocationID
		}},
		{"matched_identity", func(store *sessions.Store, id string) error {
			return EmitMatchedIdentityAttributed(store, "tool", "edit", scope, "", "", "once", "declared_scope", "", "", id)
		}, func(t *testing.T, payload json.RawMessage) string {
			var got PermissionMatched
			mustUnmarshal(t, payload, &got)
			return got.ChildInvocationID
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess, store := emitFixture()
			if err := tc.emit(store, child); err != nil {
				t.Fatalf("emit error = %v", err)
			}
			if got := tc.read(t, reloadOnly(t, sess).Payload); got != child {
				t.Errorf("child_invocation_id = %q, want %q", got, child)
			}

			parentSess, parentStore := emitFixture()
			if err := tc.emit(parentStore, ""); err != nil {
				t.Fatalf("emit error = %v", err)
			}
			payload := reloadOnly(t, parentSess).Payload
			var fields map[string]json.RawMessage
			mustUnmarshal(t, payload, &fields)
			if _, present := fields["child_invocation_id"]; present {
				t.Errorf("a parent's own event carries child_invocation_id: %s", payload)
			}
		})
	}
}

func TestPermissionEvents_RejectAMalformedChildAttribution(t *testing.T) {
	_, store := emitFixture()
	if err := EmitPromptShownAttributed(store, "tool", "edit", "/home/u/proj/a.txt", nil, "", "", "not-a-v7"); err == nil {
		t.Fatal("EmitPromptShownAttributed() = nil error, want a non-UUIDv7 child_invocation_id rejected")
	}
}

func systemOneScored(outcome, effect string) PermissionSystemOneCheck {
	return PermissionSystemOneCheck{
		SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj",
		Provider: "openrouter", ModelID: "jev/jev-1-20261001", Outcome: outcome, Effect: effect,
		PReadOnly: f64(0.97), PSecrets: f64(0), PCode: f64(0.02),
		TReadOnly: f64(0.9), TSecrets: f64(0.3), TCode: f64(0),
		DurationMs: 420,
	}
}

func systemOneUnscored(outcome, reason string) PermissionSystemOneCheck {
	return PermissionSystemOneCheck{
		SubjectKind: "literal", Subject: "ls | wc -l", Provider: "venice", ModelID: "venice/configured-model",
		Outcome: outcome, Reason: reason,
	}
}

func systemOneScores(p *PermissionSystemOneCheck) map[string]**float64 {
	return map[string]**float64{
		"p_read_only": &p.PReadOnly, "p_secrets": &p.PSecrets, "p_code": &p.PCode,
		"t_read_only": &p.TReadOnly, "t_secrets": &p.TSecrets, "t_code": &p.TCode,
	}
}

func TestPermissionSystemOneCheck_AcceptsEachOutcomeAndRoundTrips(t *testing.T) {
	declinedReadOnly := systemOneScored("declined", "read_only")
	declinedReadOnly.PCode = f64(0.8)
	accepted := []struct {
		name    string
		payload PermissionSystemOneCheck
		scored  bool
	}{
		{"allowed", systemOneScored("allowed", "read_only"), true},
		{"declined with a read_only top label", declinedReadOnly, true},
		{"declined", systemOneScored("declined", "writes_files"), true},
		{"failed without a reply", systemOneUnscored("failed", "timeout"), false},
		{"failed with no key", systemOneUnscored("failed", "no_key"), false},
		{"skipped while paused", systemOneUnscored("skipped", "paused"), false},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidatePayload(KindPermissionSystemOneCheck, raw); err != nil {
				t.Fatalf("ValidatePayload() rejected a valid record: %v\n%s", err, raw)
			}

			sess, store := emitFixture()
			child := ids.NewV7()
			if err := EmitSystemOneCheckAttributed(store, tc.payload, child); err != nil {
				t.Fatalf("EmitSystemOneCheckAttributed() error = %v", err)
			}
			ev := reloadOnly(t, sess)
			if ev.Kind != "permission_system_one_check" {
				t.Fatalf("kind = %q, want permission_system_one_check", ev.Kind)
			}
			var got PermissionSystemOneCheck
			mustUnmarshal(t, ev.Payload, &got)
			want := tc.payload
			want.ChildInvocationID = child
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip = %+v, want %+v", got, want)
			}

			var fields map[string]json.RawMessage
			mustUnmarshal(t, ev.Payload, &fields)
			for _, name := range []string{"p_read_only", "p_secrets", "p_code", "t_read_only", "t_secrets", "t_code"} {
				_, present := fields[name]
				if present != tc.scored {
					t.Errorf("%s present = %v, want %v: %s", name, present, tc.scored, ev.Payload)
				}
			}
			if tc.scored {
				if string(fields["p_secrets"]) != "0" || string(fields["t_code"]) != "0" {
					t.Errorf("explicit zeros not persisted: %s", ev.Payload)
				}
				return
			}
			if string(fields["provider"]) != `"venice"` || string(fields["model_id"]) != `"venice/configured-model"` {
				t.Errorf("an unscored record lost its configured provider or model id: %s", ev.Payload)
			}
		})
	}
}

func TestPermissionSystemOneCheck_RecordsTheSuppliedModelSnapshot(t *testing.T) {
	sess, store := emitFixture()
	p := systemOneScored("allowed", "read_only")
	p.ModelID = "jev/jev-1-snapshot-20261020"
	if err := EmitSystemOneCheckAttributed(store, p, ""); err != nil {
		t.Fatalf("EmitSystemOneCheckAttributed() error = %v", err)
	}
	var got PermissionSystemOneCheck
	mustUnmarshal(t, reloadOnly(t, sess).Payload, &got)
	if got.ModelID != "jev/jev-1-snapshot-20261020" {
		t.Fatalf("model_id = %q, want the supplied snapshot", got.ModelID)
	}
}

func TestPermissionSystemOneCheck_Rejects(t *testing.T) {
	type mutate func(p *PermissionSystemOneCheck)
	cases := []struct {
		name string
		base PermissionSystemOneCheck
		edit mutate
	}{
		{"allowed without probabilities or thresholds", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) {
			p.PReadOnly, p.PSecrets, p.PCode, p.TReadOnly, p.TSecrets, p.TCode = nil, nil, nil, nil, nil, nil
		}},
		{"failed without a reason", systemOneUnscored("failed", ""), nil},
		{"failed with a paused reason", systemOneUnscored("failed", "paused"), nil},
		{"failed with an unknown reason", systemOneUnscored("failed", "teapot"), nil},
		{"skipped with a timeout reason", systemOneUnscored("skipped", "timeout"), nil},
		{"skipped without a reason", systemOneUnscored("skipped", ""), nil},
		{"probability 1.2", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.PReadOnly = f64(1.2) }},
		{"negative threshold", systemOneScored("declined", "network"), func(p *PermissionSystemOneCheck) { p.TSecrets = f64(-0.1) }},
		{"NaN probability", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.PCode = f64(math.NaN()) }},
		{"infinite threshold", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.TCode = f64(math.Inf(1)) }},
		{"unknown effect label", systemOneScored("allowed", "reads"), nil},
		{"allowed without an effect", systemOneScored("allowed", ""), nil},
		{"declined without an effect", systemOneScored("declined", ""), nil},
		{"allowed with a reason", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.Reason = "timeout" }},
		{"declined with a reason", systemOneScored("declined", "deletes"), func(p *PermissionSystemOneCheck) { p.Reason = "paused" }},
		{"failed with an effect", systemOneUnscored("failed", "server"), func(p *PermissionSystemOneCheck) { p.Effect = "read_only" }},
		{"skipped with an effect", systemOneUnscored("skipped", "paused"), func(p *PermissionSystemOneCheck) { p.Effect = "read_only" }},
		{"tool subject kind", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.SubjectKind = "tool" }},
		{"unknown provider", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.Provider = "openai" }},
		{"empty provider", systemOneUnscored("failed", "auth"), func(p *PermissionSystemOneCheck) { p.Provider = "" }},
		{"unknown outcome", systemOneScored("maybe", "read_only"), nil},
		{"negative duration", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.DurationMs = -1 }},
		{"empty subject", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.Subject = "" }},
		{"empty model id", systemOneUnscored("skipped", "paused"), func(p *PermissionSystemOneCheck) { p.ModelID = "" }},
		{"relative path scope", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.PathScope = "home/u/proj" }},
		{"unclean path scope", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.PathScope = "/home/u/proj/../x" }},
		{"invalid child invocation id", systemOneScored("allowed", "read_only"), func(p *PermissionSystemOneCheck) { p.ChildInvocationID = "not-a-v7" }},
	}
	for _, outcome := range []string{"allowed", "declined"} {
		for name := range systemOneScores(&PermissionSystemOneCheck{}) {
			cases = append(cases, struct {
				name string
				base PermissionSystemOneCheck
				edit mutate
			}{outcome + " without " + name, systemOneScored(outcome, "read_only"), func(p *PermissionSystemOneCheck) { *systemOneScores(p)[name] = nil }})
		}
	}
	for _, unscored := range []PermissionSystemOneCheck{systemOneUnscored("failed", "credits"), systemOneUnscored("skipped", "paused")} {
		for name := range systemOneScores(&PermissionSystemOneCheck{}) {
			cases = append(cases, struct {
				name string
				base PermissionSystemOneCheck
				edit mutate
			}{unscored.Outcome + " with " + name, unscored, func(p *PermissionSystemOneCheck) { *systemOneScores(p)[name] = f64(0) }})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.base
			if tc.edit != nil {
				tc.edit(&p)
			}
			if _, err := Append(newStore(), p); err == nil {
				t.Fatalf("Append() accepted %s", tc.name)
			}
			raw, err := json.Marshal(p)
			if err != nil {
				return
			}
			if err := ValidatePayload(KindPermissionSystemOneCheck, raw); err == nil {
				t.Fatalf("ValidatePayload() accepted %s: %s", tc.name, raw)
			}
		})
	}
}

func TestPermissionSystemOneCheck_ConcurrentEmittersKeepBothRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())
	subjects := []string{"git status", "git log"}
	var wg sync.WaitGroup
	errs := make([]error, len(subjects))
	for i, subject := range subjects {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := systemOneScored("allowed", "read_only")
			p.Subject = subject
			errs[i] = EmitSystemOneCheckAttributed(store, p, "")
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("EmitSystemOneCheckAttributed() error = %v", err)
		}
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("sessions.Unmarshal() error = %v", err)
	}
	var got []string
	for _, rec := range loaded.Records {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != KindPermissionSystemOneCheck {
			continue
		}
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("ValidatePayload() rejected a flushed record: %v", err)
		}
		var p PermissionSystemOneCheck
		mustUnmarshal(t, ev.Payload, &p)
		got = append(got, p.Subject)
	}
	slices.Sort(got)
	if want := []string{"git log", "git status"}; !slices.Equal(got, want) {
		t.Fatalf("flushed subjects = %v, want %v", got, want)
	}
}

func TestPermissionMatched_SystemOneCheckSource(t *testing.T) {
	accepted := []PermissionMatched{
		{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "system_one_check"},
		{SubjectKind: "literal", Subject: "ls | wc -l", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "system_one_check", ArgumentHash: literalArgumentHash("ls | wc -l")},
	}
	for _, payload := range accepted {
		t.Run("accepted "+payload.SubjectKind, func(t *testing.T) {
			if _, err := Append(newStore(), payload); err != nil {
				t.Fatalf("Append() rejected a valid system_one_check record: %v", err)
			}
		})
	}
	rejected := []struct {
		name    string
		payload PermissionMatched
	}{
		{"deny", PermissionMatched{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "system_one_check"}},
		{"tool subject", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "system_one_check"}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Append(newStore(), tc.payload); err == nil {
				t.Fatalf("Append() accepted %s", tc.name)
			}
			raw, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidatePayload(KindPermissionMatched, raw); err == nil {
				t.Fatalf("ValidatePayload() accepted %s", tc.name)
			}
		})
	}
}

func TestPermissionSystemOneCheck_SkippedAcceptsEveryEligibilityReason(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	t.Setenv("PATH", t.TempDir())
	blocked := permissions.NewBlockedPaths(home, []permissions.BlockedEntry{{Path: filepath.Join(home, "secret"), Source: "s"}})
	mc := permissions.ModeContext{Mode: "auto_edits", ProjectRoot: root}
	cases := []struct {
		command string
		blocked *permissions.BlockedPaths
	}{
		{"ls\nls", blocked},
		{"ls", nil},
		{"echo $(id)", blocked},
		{"cat " + filepath.Join(home, "secret", "a"), blocked},
		{"bash --version | head -1", blocked},
		{"nosuchprogram x", blocked},
		{"ls > out", blocked},
	}
	produced := map[string]bool{}
	for _, tc := range cases {
		req := permissions.MatchRequest{Kind: "literal", Subject: tc.command, PathScope: root}
		reason := permissions.SystemOneEligible(req, mc, tc.blocked, tc.command)
		if reason == "" {
			t.Fatalf("SystemOneEligible(%q) = \"\", want a reason", tc.command)
		}
		produced[reason] = true
	}
	if len(produced) != len(cases) {
		t.Fatalf("produced reasons = %v, want %d distinct", produced, len(cases))
	}
	produced["paused"] = true
	for reason := range produced {
		p := systemOneUnscored("skipped", reason)
		if _, err := Build(p); err != nil {
			t.Errorf("Build(skipped/%s) error = %v", reason, err)
		}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidatePayload(KindPermissionSystemOneCheck, raw); err != nil {
			t.Errorf("ValidatePayload(skipped/%s) error = %v", reason, err)
		}
	}
	unknown := systemOneUnscored("skipped", "teapot")
	if _, err := Build(unknown); err == nil {
		t.Error("Build accepted an unknown skipped reason")
	}
	raw, _ := json.Marshal(unknown)
	if err := ValidatePayload(KindPermissionSystemOneCheck, raw); err == nil {
		t.Error("ValidatePayload accepted an unknown skipped reason")
	}
}
