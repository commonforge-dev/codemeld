// Tests for the two records that describe protected state: permission_revoke_requested, and
// the security_state_halted record plus the security_halted terminal a settings checkpoint
// writes. Both are covered for their closed vocabularies, their rejections, and an
// append/reload round trip through the session codec.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
)

const revokeLiteral = `sh -c "echo hi"`

// TestEmitPermissionRevokeRequested_RoundTripsEachIdentityForm appends one revocation per stored
// identity shape, reloads the session through the production codec, and re-validates the payload on
// the load path — so a form that appends but cannot be read back fails here.
func TestEmitPermissionRevokeRequested_RoundTripsEachIdentityForm(t *testing.T) {
	for _, tc := range []struct {
		name         string
		entryKind    string
		subject      string
		pathScope    string
		hostScope    string
		grantKind    string
		argumentHash string
	}{
		{name: "folder tool grant", entryKind: "tool", subject: "read_file", pathScope: "/home/u/proj", grantKind: "folder"},
		{name: "global direct grant", entryKind: "direct", subject: "git :*", pathScope: "*", grantKind: "global"},
		{name: "session direct grant", entryKind: "direct", subject: "ls", pathScope: "/home/u/proj", grantKind: "session"},
		{
			name: "literal grant", entryKind: "literal", subject: revokeLiteral,
			pathScope: "/home/u/proj", grantKind: "folder", argumentHash: litHash(revokeLiteral),
		},
		{name: "capability tool grant", entryKind: "tool", subject: "write_tree", pathScope: "/home/u/proj", grantKind: "folder"},
		{name: "project host grant", entryKind: "tool", subject: "web_fetch", hostScope: "docs.example.com", grantKind: "project"},
		{name: "session host grant", entryKind: "tool", subject: "web_search", hostScope: "mcp.exa.ai", grantKind: "session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := newSession()
			store := sessions.New("unused-in-tests", sess)
			if err := EmitPermissionRevokeRequested(store, tc.entryKind, tc.subject, tc.pathScope, tc.hostScope, tc.grantKind, tc.argumentHash); err != nil {
				t.Fatalf("EmitPermissionRevokeRequested error = %v", err)
			}

			data, err := sessions.Marshal(sess)
			if err != nil {
				t.Fatalf("sessions.Marshal error = %v", err)
			}
			loaded, err := sessions.Unmarshal(data)
			if err != nil {
				t.Fatalf("sessions.Unmarshal error = %v", err)
			}
			if len(loaded.Records) != 1 {
				t.Fatalf("reloaded records = %d, want 1", len(loaded.Records))
			}
			ev, ok := loaded.Records[0].(sessions.Event)
			if !ok || ev.Kind != KindPermissionRevokeRequested {
				t.Fatalf("reloaded record = %T kind %q, want sessions.Event %q", loaded.Records[0], ev.Kind, KindPermissionRevokeRequested)
			}
			if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
				t.Fatalf("reloaded payload fails load validation: %v", err)
			}

			var got PermissionRevokeRequested
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("decode reloaded payload: %v", err)
			}
			want := PermissionRevokeRequested{
				EntryKind: tc.entryKind, Subject: tc.subject, PathScope: tc.pathScope, HostScope: tc.hostScope,
				GrantKind: tc.grantKind, ArgumentHash: tc.argumentHash, Source: RevokeSourcePermissionsUI,
			}
			if got != want {
				t.Fatalf("reloaded payload = %+v, want %+v", got, want)
			}
		})
	}
}

// The emitter is the only writer of source, so a caller cannot record a revocation under any other
// provenance, and the on-disk field names are the stored grant's own.
func TestEmitPermissionRevokeRequested_PinsSourceAndStoredFieldNames(t *testing.T) {
	store := newStore()
	if err := EmitPermissionRevokeRequested(store, "tool", "read_file", "/home/u/proj", "", "folder", ""); err != nil {
		t.Fatalf("EmitPermissionRevokeRequested error = %v", err)
	}
	recs := store.Records()
	if len(recs) != 1 {
		t.Fatalf("appended records = %d, want 1", len(recs))
	}
	var wire map[string]any
	if err := json.Unmarshal(recs[0].(sessions.Event).Payload, &wire); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	want := map[string]any{
		"kind": "tool", "subject": "read_file", "path_scope": "/home/u/proj",
		"grant_kind": "folder", "source": "permissions_ui",
	}
	if len(wire) != len(want) {
		t.Fatalf("payload fields = %v, want exactly %v", wire, want)
	}
	for k, v := range want {
		if wire[k] != v {
			t.Errorf("payload[%q] = %v, want %v", k, wire[k], v)
		}
	}
	if RevokeSourcePermissionsUI != "permissions_ui" {
		t.Errorf("RevokeSourcePermissionsUI = %q, want the persisted token %q", RevokeSourcePermissionsUI, "permissions_ui")
	}
}

// A rejected payload never reaches the record stream: append validates first, so a revoke whose
// identity could not be recorded queues nothing rather than a partial or wrong record.
func TestPermissionRevokeRequested_RejectionsAppendNothing(t *testing.T) {
	valid := PermissionRevokeRequested{
		EntryKind: "tool", Subject: "read_file", PathScope: "/home/u/proj",
		GrantKind: "folder", Source: RevokeSourcePermissionsUI,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("base payload should validate, got %v", err)
	}

	for name, mutate := range map[string]func(*PermissionRevokeRequested){
		"unknown source":           func(p *PermissionRevokeRequested) { p.Source = "settings_edit" },
		"empty source":             func(p *PermissionRevokeRequested) { p.Source = "" },
		"outcome source borrowed":  func(p *PermissionRevokeRequested) { p.Source = outcomeSourceGrant },
		"kind host":                func(p *PermissionRevokeRequested) { p.EntryKind = subjectKindHost },
		"kind unknown":             func(p *PermissionRevokeRequested) { p.EntryKind = "capability" },
		"empty kind":               func(p *PermissionRevokeRequested) { p.EntryKind = "" },
		"empty subject":            func(p *PermissionRevokeRequested) { p.Subject = "" },
		"unknown grant kind":       func(p *PermissionRevokeRequested) { p.GrantKind = "project" },
		"empty grant kind":         func(p *PermissionRevokeRequested) { p.GrantKind = "" },
		"empty path scope":         func(p *PermissionRevokeRequested) { p.PathScope = "" },
		"relative path scope":      func(p *PermissionRevokeRequested) { p.PathScope = "proj" },
		"uncleaned path scope":     func(p *PermissionRevokeRequested) { p.PathScope = "/home/u/proj/" },
		"all-paths without global": func(p *PermissionRevokeRequested) { p.PathScope = "*" },
		"global with folder path":  func(p *PermissionRevokeRequested) { p.GrantKind = "global" },
		"path and host both set":   func(p *PermissionRevokeRequested) { p.HostScope = "docs.example.com" },
		"argument hash on non-literal": func(p *PermissionRevokeRequested) {
			p.ArgumentHash = litHash("read_file")
		},
		"literal without hash": func(p *PermissionRevokeRequested) {
			p.EntryKind, p.Subject = "literal", revokeLiteral
		},
		"literal with malformed hash": func(p *PermissionRevokeRequested) {
			p.EntryKind, p.Subject, p.ArgumentHash = "literal", revokeLiteral, "not-a-digest"
		},
		"literal with another subject's hash": func(p *PermissionRevokeRequested) {
			p.EntryKind, p.Subject, p.ArgumentHash = "literal", revokeLiteral, litHash("sh -c \"echo bye\"")
		},
		"capability subject with direct kind": func(p *PermissionRevokeRequested) {
			p.EntryKind, p.Subject = "direct", "write"
		},
		"capability subject with literal kind": func(p *PermissionRevokeRequested) {
			p.EntryKind, p.Subject, p.ArgumentHash = "literal", "read*", litHash("read*")
		},
		"capability tree subject with direct kind": func(p *PermissionRevokeRequested) {
			p.EntryKind, p.Subject = "direct", "write_tree"
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := valid
			mutate(&p)
			if err := p.validate(); err == nil {
				t.Fatalf("validate accepted %s, want rejection", name)
			}
			store := newStore()
			if _, err := Append(store, p); err == nil {
				t.Fatalf("Append accepted %s, want rejection", name)
			}
			if n := len(store.Records()); n != 0 {
				t.Fatalf("rejected append queued %d record(s), want 0", n)
			}
		})
	}
}

// The host arm is scoped by host, so it carries no path_scope and no argument_hash, its grant kind
// comes from the host vocabulary, and its host must be stored canonically.
func TestPermissionRevokeRequested_HostRejections(t *testing.T) {
	valid := PermissionRevokeRequested{
		EntryKind: "tool", Subject: "web_fetch", HostScope: "docs.example.com",
		GrantKind: "project", Source: RevokeSourcePermissionsUI,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("base host payload should validate, got %v", err)
	}

	for name, mutate := range map[string]func(*PermissionRevokeRequested){
		"path scope set":         func(p *PermissionRevokeRequested) { p.PathScope = "/home/u/proj" },
		"missing host scope":     func(p *PermissionRevokeRequested) { p.HostScope = "" },
		"wildcard host":          func(p *PermissionRevokeRequested) { p.HostScope = "*" },
		"uncanonical host":       func(p *PermissionRevokeRequested) { p.HostScope = "Docs.Example.COM" },
		"path grant kind":        func(p *PermissionRevokeRequested) { p.GrantKind = "folder" },
		"global grant kind":      func(p *PermissionRevokeRequested) { p.GrantKind = "global" },
		"non-tool matching kind": func(p *PermissionRevokeRequested) { p.EntryKind = "direct" },
		"argument hash set":      func(p *PermissionRevokeRequested) { p.ArgumentHash = litHash("web_fetch") },
	} {
		t.Run(name, func(t *testing.T) {
			p := valid
			mutate(&p)
			if err := p.validate(); err == nil {
				t.Fatalf("validate accepted %s, want rejection", name)
			}
		})
	}
}

// The load path holds a stored record to the same rules and refuses one that omits a field the
// canonical wire form always carries, so a hand-edited revocation cannot pass as evidence.
func TestPermissionRevokeRequested_LoadRejections(t *testing.T) {
	for name, raw := range map[string]string{
		"missing source":                `{"kind":"tool","subject":"read_file","path_scope":"/home/u/proj","grant_kind":"folder"}`,
		"null source":                   `{"kind":"tool","subject":"read_file","path_scope":"/home/u/proj","grant_kind":"folder","source":null}`,
		"missing kind":                  `{"subject":"read_file","path_scope":"/home/u/proj","grant_kind":"folder","source":"permissions_ui"}`,
		"missing grant_kind":            `{"kind":"tool","subject":"read_file","path_scope":"/home/u/proj","source":"permissions_ui"}`,
		"unknown source":                `{"kind":"tool","subject":"read_file","path_scope":"/home/u/proj","grant_kind":"folder","source":"file_edit"}`,
		"host and path both":            `{"kind":"tool","subject":"web_fetch","path_scope":"/home/u/proj","host_scope":"docs.example.com","grant_kind":"project","source":"permissions_ui"}`,
		"capability subject as direct":  `{"kind":"direct","subject":"write_tree","path_scope":"/home/u/proj","grant_kind":"folder","source":"permissions_ui"}`,
		"capability subject as literal": `{"kind":"literal","subject":"write","path_scope":"/home/u/proj","grant_kind":"folder","source":"permissions_ui","argument_hash":"` + litHash("write") + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePayload(KindPermissionRevokeRequested, json.RawMessage(raw)); err == nil {
				t.Fatalf("ValidatePayload accepted %s, want rejection", name)
			}
		})
	}

	ok := `{"kind":"tool","subject":"read_file","path_scope":"/home/u/proj","grant_kind":"folder","source":"permissions_ui"}`
	if err := ValidatePayload(KindPermissionRevokeRequested, json.RawMessage(ok)); err != nil {
		t.Fatalf("ValidatePayload rejected a well-formed record: %v", err)
	}
}

// The stored subject is copied verbatim: hashing or truncating it would break the correlation to
// the removed grant, which is the whole point of the record.
func TestPermissionRevokeRequested_KeepsTheStoredSubjectVerbatim(t *testing.T) {
	const stored = `git commit -m "First task"`
	store := newStore()
	if err := EmitPermissionRevokeRequested(store, "direct", stored, "/home/u/proj", "", "folder", ""); err != nil {
		t.Fatalf("EmitPermissionRevokeRequested error = %v", err)
	}
	var p PermissionRevokeRequested
	if err := json.Unmarshal(store.Records()[0].(sessions.Event).Payload, &p); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if p.Subject != stored {
		t.Fatalf("recorded subject = %q, want the stored grant subject %q", p.Subject, stored)
	}
	if strings.Contains(p.Subject, "…") || len(p.Subject) != len(stored) {
		t.Fatalf("recorded subject %q was redacted or truncated", p.Subject)
	}
}

const (
	haltGlobalPath  = "/home/u/.codemeld/settings.yaml"
	haltProjectPath = "/home/u/proj/.codemeld/settings.yaml"
)

func semanticHalt() SecurityStateHalted {
	return SecurityStateHalted{
		Path:           haltGlobalPath,
		DetectionPoint: SecurityDetectionBeforeMutatingCall,
		Sections:       []string{"permissions", "provider_credential"},
		Labels:         []string{"added", "changed"},
	}
}

// The persisted section, label, and unavailable-reason tokens are the monitor's own, spelled
// out in internal/events only because importing internal/securitystate would close a cycle
// (securitystate -> trust -> filetools -> events). This reads the tokens and their fixed order
// straight out of the two source files, so a rename or a reorder there fails here instead of
// silently splitting into a second vocabulary.
func TestSecurityStateHalted_VocabularyMatchesTheMonitor(t *testing.T) {
	const monitorPath = "../securitystate/monitor.go"
	monitor := parseGoConsts(t, monitorPath)

	for _, tc := range []struct {
		orderVar string
		got      []string
	}{
		{"sectionOrder", securitySectionOrder},
		{"labelOrder", securityLabelOrder},
	} {
		names := parseGoSliceVar(t, monitorPath, tc.orderVar)
		if len(names) != len(tc.got) {
			t.Fatalf("%s has %d entries, but this package carries %d: %v", tc.orderVar, len(names), len(tc.got), tc.got)
		}
		for i, name := range names {
			want, ok := monitor[name]
			if !ok {
				t.Fatalf("%s[%d] names %s, which %s does not declare as a constant", tc.orderVar, i, name, monitorPath)
			}
			if tc.got[i] != want {
				t.Errorf("entry %d = %q, want the monitor's %s = %q", i, tc.got[i], name, want)
			}
		}
	}

	locksConsts := parseGoConsts(t, "../locks/flock.go")
	wantCauses := []string{locksConsts["ReasonLockTimeout"], locksConsts["ReasonLockAcquireError"]}
	if len(securityUnavailableCause) != len(wantCauses) {
		t.Fatalf("securityUnavailableCause = %v, want exactly %v", securityUnavailableCause, wantCauses)
	}
	for _, reason := range wantCauses {
		if !securityUnavailableCause[reason] {
			t.Errorf("securityUnavailableCause is missing the lock reason %q", reason)
		}
	}
	for _, name := range []string{"ReasonNone", "ReasonLockContended"} {
		if securityUnavailableCause[locksConsts[name]] {
			t.Errorf("securityUnavailableCause accepts %s, which Monitor.check never reports as unavailable", name)
		}
	}
}

// parseGoConsts returns every string constant declared in path, keyed by its Go name.
func parseGoConsts(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				value, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					t.Fatalf("unquote %s: %v", name.Name, uerr)
				}
				out[name.Name] = value
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no string constants found in %s", path)
	}
	return out
}

// parseGoSliceVar returns the constant names a package-level slice variable lists, in order.
func parseGoSliceVar(t *testing.T, path, varName string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != varName || len(vs.Values) != 1 {
				continue
			}
			composite, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatalf("%s in %s is not a composite literal", varName, path)
			}
			var names []string
			for _, elt := range composite.Elts {
				ident, ok := elt.(*ast.Ident)
				if !ok {
					t.Fatalf("%s in %s lists a non-identifier entry", varName, path)
				}
				names = append(names, ident.Name)
			}
			return names
		}
	}
	t.Fatalf("%s declares no %s", path, varName)
	return nil
}

// Each result arm the monitor can produce is appended, reloaded through the production
// session codec, re-validated on the load path, and compared field for field, so an arm
// that appends but cannot be read back fails here.
func TestSecurityStateHalted_RoundTripsEachResultArm(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload SecurityStateHalted
	}{
		{"semantic drift", semanticHalt()},
		{
			name: "every section and semantic label",
			payload: SecurityStateHalted{
				Path: haltProjectPath, DetectionPoint: SecurityDetectionBeforeFinalSuccess,
				Sections: securitySectionOrder, Labels: []string{"added", "removed", "changed"},
			},
		},
		{
			name: "malformed",
			payload: SecurityStateHalted{
				Path: haltProjectPath, DetectionPoint: SecurityDetectionBeforeFinalSuccess,
				Labels: []string{"malformed"},
			},
		},
		{
			name: "unreadable",
			payload: SecurityStateHalted{
				Path: haltProjectPath, DetectionPoint: SecurityDetectionStartup,
				Labels: []string{"unreadable"},
			},
		},
		{
			name: "whole-file absence",
			payload: SecurityStateHalted{
				Path: haltProjectPath, DetectionPoint: SecurityDetectionStartup,
				Labels: []string{"missing"},
			},
		},
		{
			name: "unavailable after a lock timeout",
			payload: SecurityStateHalted{
				Path: haltGlobalPath, DetectionPoint: SecurityDetectionBeforeMutatingCall,
				UnavailableReason: "lock_timeout",
			},
		},
		{
			name: "unavailable after a lock acquire failure",
			payload: SecurityStateHalted{
				Path: haltGlobalPath, DetectionPoint: SecurityDetectionStartup,
				UnavailableReason: "lock_acquire_error",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := newSession()
			store := sessions.New("unused-in-tests", sess)
			if _, err := Append(store, tc.payload); err != nil {
				t.Fatalf("Append error = %v", err)
			}
			data, err := sessions.Marshal(sess)
			if err != nil {
				t.Fatalf("sessions.Marshal error = %v", err)
			}
			loaded, err := sessions.Unmarshal(data)
			if err != nil {
				t.Fatalf("sessions.Unmarshal error = %v", err)
			}
			if len(loaded.Records) != 1 {
				t.Fatalf("reloaded records = %d, want 1", len(loaded.Records))
			}
			ev, ok := loaded.Records[0].(sessions.Event)
			if !ok || ev.Kind != KindSecurityStateHalted {
				t.Fatalf("reloaded record = %T kind %q, want sessions.Event %q", loaded.Records[0], ev.Kind, KindSecurityStateHalted)
			}
			if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
				t.Fatalf("reloaded payload fails load validation: %v", err)
			}
			var got SecurityStateHalted
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("decode reloaded payload: %v", err)
			}
			if got.Path != tc.payload.Path || got.DetectionPoint != tc.payload.DetectionPoint ||
				got.UnavailableReason != tc.payload.UnavailableReason ||
				!slices.Equal(got.Sections, tc.payload.Sections) || !slices.Equal(got.Labels, tc.payload.Labels) {
				t.Fatalf("reloaded payload = %+v, want %+v", got, tc.payload)
			}
		})
	}
}

// The on-disk record carries the affected file, the point the check ran, and the monitor's
// bounded classification — and nothing else. A field list that grows silently is exactly
// how settings content or a credential would reach the session file.
func TestSecurityStateHalted_PersistsOnlyBoundedFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload SecurityStateHalted
		want    map[string]any
	}{
		{
			name:    "semantic drift",
			payload: semanticHalt(),
			want: map[string]any{
				"path": haltGlobalPath, "detection_point": "before_mutating_call",
				"sections": []any{"permissions", "provider_credential"},
				"labels":   []any{"added", "changed"},
			},
		},
		{
			name: "unavailable",
			payload: SecurityStateHalted{
				Path: haltGlobalPath, DetectionPoint: SecurityDetectionStartup,
				UnavailableReason: "lock_timeout",
			},
			want: map[string]any{
				"path": haltGlobalPath, "detection_point": "startup",
				"unavailable_reason": "lock_timeout",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.payload); err != nil {
				t.Fatalf("Append error = %v", err)
			}
			var wire map[string]any
			if err := json.Unmarshal(store.Records()[0].(sessions.Event).Payload, &wire); err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			if !reflect.DeepEqual(wire, tc.want) {
				t.Fatalf("payload fields = %v, want exactly %v", wire, tc.want)
			}
		})
	}
}

// A rejected record never reaches the stream: append validates first, so a halt whose
// classification could not be recorded queues nothing rather than a partial or wrong record.
func TestSecurityStateHalted_RejectionsAppendNothing(t *testing.T) {
	if err := semanticHalt().validate(); err != nil {
		t.Fatalf("base payload should validate, got %v", err)
	}
	for name, mutate := range map[string]func(*SecurityStateHalted){
		"empty path":               func(p *SecurityStateHalted) { p.Path = "" },
		"relative path":            func(p *SecurityStateHalted) { p.Path = ".codemeld/settings.yaml" },
		"uncleaned path":           func(p *SecurityStateHalted) { p.Path = "/home/u/../u/.codemeld/settings.yaml" },
		"empty detection point":    func(p *SecurityStateHalted) { p.DetectionPoint = "" },
		"unknown detection point":  func(p *SecurityStateHalted) { p.DetectionPoint = "before_reply" },
		"unknown section":          func(p *SecurityStateHalted) { p.Sections = []string{"provider.openai"} },
		"duplicate section":        func(p *SecurityStateHalted) { p.Sections = []string{"permissions", "permissions"} },
		"reordered sections":       func(p *SecurityStateHalted) { p.Sections = []string{"provider_credential", "permissions"} },
		"unknown label":            func(p *SecurityStateHalted) { p.Labels = []string{"revoked"} },
		"duplicate label":          func(p *SecurityStateHalted) { p.Labels = []string{"added", "added"} },
		"reordered labels":         func(p *SecurityStateHalted) { p.Labels = []string{"changed", "added"} },
		"no labels and no reason":  func(p *SecurityStateHalted) { p.Labels = nil },
		"semantic without section": func(p *SecurityStateHalted) { p.Sections = nil },
		"mixed result arms": func(p *SecurityStateHalted) {
			p.Labels = []string{"changed", "malformed"}
		},
		"two non-projectable labels": func(p *SecurityStateHalted) {
			p.Sections, p.Labels = nil, []string{"malformed", "unreadable"}
		},
		"malformed with sections": func(p *SecurityStateHalted) {
			p.Labels = []string{"malformed"}
		},
		"unavailable with sections and labels": func(p *SecurityStateHalted) {
			p.UnavailableReason = "lock_timeout"
		},
		"unavailable with labels only": func(p *SecurityStateHalted) {
			p.Sections, p.UnavailableReason = nil, "lock_timeout"
		},
		"unknown unavailable reason": func(p *SecurityStateHalted) {
			p.Sections, p.Labels, p.UnavailableReason = nil, nil, "lock_contended"
		},
		"raw lock error as the unavailable reason": func(p *SecurityStateHalted) {
			p.Sections, p.Labels, p.UnavailableReason = nil, nil, "flock /home/u/.codemeld/settings.yaml.lock: EAGAIN"
		},
		"settings content smuggled into a section": func(p *SecurityStateHalted) {
			p.Sections = []string{`permissions: [{"subject":"bash"}]`}
		},
		"credential smuggled into a label": func(p *SecurityStateHalted) {
			p.Labels = []string{"sk_live_abcdef0123456789"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := semanticHalt()
			mutate(&p)
			if err := p.validate(); err == nil {
				t.Fatalf("validate accepted %s, want rejection", name)
			}
			store := newStore()
			if _, err := Append(store, p); err == nil {
				t.Fatalf("Append accepted %s, want rejection", name)
			}
			if n := len(store.Records()); n != 0 {
				t.Fatalf("rejected append queued %d record(s), want 0", n)
			}
		})
	}
}

// The load path holds a stored record to the same rules, refuses the content field names a
// halt record must never carry, and still ignores an unknown field so an additive record
// written by a later version stays loadable.
func TestSecurityStateHalted_LoadRules(t *testing.T) {
	const semantic = `{"path":"/home/u/.codemeld/settings.yaml","detection_point":"startup",` +
		`"sections":["permissions"],"labels":["changed"]}`
	for name, raw := range map[string]string{
		"missing path":               `{"detection_point":"startup","labels":["missing"]}`,
		"missing detection point":    `{"path":"/home/u/.codemeld/settings.yaml","labels":["missing"]}`,
		"null detection point":       `{"path":"/home/u/.codemeld/settings.yaml","detection_point":null,"labels":["missing"]}`,
		"no arm at all":              `{"path":"/home/u/.codemeld/settings.yaml","detection_point":"startup"}`,
		"unavailable with labels":    `{"path":"/home/u/.codemeld/settings.yaml","detection_point":"startup","labels":["missing"],"unavailable_reason":"lock_timeout"}`,
		"unknown unavailable reason": `{"path":"/home/u/.codemeld/settings.yaml","detection_point":"startup","unavailable_reason":"lock_contended"}`,
		"sections not a list":        `{"path":"/home/u/.codemeld/settings.yaml","detection_point":"startup","sections":"permissions","labels":["changed"]}`,
		"settings content field":     semantic[:len(semantic)-1] + `,"settings":"provider:\n  openai:\n    api_key: sk_live"}`,
		"api key field":              semantic[:len(semantic)-1] + `,"api_key":"sk_live_abcdef"}`,
		"access token field":         semantic[:len(semantic)-1] + `,"access_token":"ya29.a0"}`,
		"refresh token field":        semantic[:len(semantic)-1] + `,"refresh_token":"1//0g"}`,
		"account id field":           semantic[:len(semantic)-1] + `,"account_id":"acct_123"}`,
		"permission arguments":       semantic[:len(semantic)-1] + `,"arguments":"cat /etc/passwd"}`,
		"tool arguments field":       semantic[:len(semantic)-1] + `,"tool_arguments":"{}"}`,
		"direct tokens field":        semantic[:len(semantic)-1] + `,"direct_tokens":["curl","-H","Authorization: Bearer sk_live_abcdef"]}`,
		"direct command subject":     semantic[:len(semantic)-1] + `,"direct_command_subject":"curl -H Authorization: Bearer sk_live_abcdef"}`,
		"direct request subject":     semantic[:len(semantic)-1] + `,"direct_request_subject":"https://api.example.com?token=sk_live_abcdef"}`,
		"parse text field":           semantic[:len(semantic)-1] + `,"parse_error":"yaml: line 4: found unexpected ':'"}`,
		"raw error field":            semantic[:len(semantic)-1] + `,"error":"open settings.yaml: permission denied"}`,
		"error detail field":         semantic[:len(semantic)-1] + `,"error_detail":"open settings.yaml: permission denied"}`,
		"secret field":               semantic[:len(semantic)-1] + `,"secret":"hunter2"}`,
		"credential field":           semantic[:len(semantic)-1] + `,"credential":"hunter2"}`,
		"provider credential field":  semantic[:len(semantic)-1] + `,"provider_credential":"sk_live_abcdef"}`,
		"provider auth header field": semantic[:len(semantic)-1] + `,"provider_auth_header":"Bearer sk_live_abcdef"}`,
		"web research credential":    semantic[:len(semantic)-1] + `,"web_research_credential":"tvly-abcdef"}`,
		"not an object":              `["/home/u/.codemeld/settings.yaml"]`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePayload(KindSecurityStateHalted, json.RawMessage(raw)); err == nil {
				t.Fatalf("ValidatePayload accepted %s, want rejection", name)
			}
		})
	}

	if err := ValidatePayload(KindSecurityStateHalted, json.RawMessage(semantic)); err != nil {
		t.Fatalf("ValidatePayload rejected a well-formed record: %v", err)
	}
	future := semantic[:len(semantic)-1] + `,"layer":"global"}`
	if err := ValidatePayload(KindSecurityStateHalted, json.RawMessage(future)); err != nil {
		t.Fatalf("ValidatePayload rejected an additive future field: %v", err)
	}
}

// One checkpoint can report both settings layers, so every affected layer gets its own
// record, in the order the monitor returned them, ahead of the single terminal and the
// single store commit that makes the whole halt durable.
func TestEmitSecurityStateHalt_RecordsEveryLayerThenTheTerminal(t *testing.T) {
	var commits int
	restoreCommit := commitStore
	commitStore = func(ctx context.Context, s *sessions.Store, recs ...sessions.Record) (fserrors.Category, sessions.WriteReason, error) {
		commits++
		return s.CommitRecords(ctx, recs...)
	}
	t.Cleanup(func() { commitStore = restoreCommit })

	global := semanticHalt()
	project := SecurityStateHalted{
		Path: haltProjectPath, DetectionPoint: SecurityDetectionBeforeMutatingCall,
		UnavailableReason: "lock_acquire_error",
	}
	terminal := TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted, DispatchStarted: true}

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	if err := EmitSecurityStateHalt(context.Background(), store, []SecurityStateHalted{global, project}, &terminal, failOnWriteFailure(t)); err != nil {
		t.Fatalf("EmitSecurityStateHalt error = %v", err)
	}
	if commits != 1 {
		t.Fatalf("store commits = %d, want exactly 1", commits)
	}

	loaded := reloadSession(t, store)
	wantKinds := []string{KindSecurityStateHalted, KindSecurityStateHalted, KindTurnTerminal}
	if len(loaded.Records) != len(wantKinds) {
		t.Fatalf("records = %d, want %d", len(loaded.Records), len(wantKinds))
	}
	for i, want := range wantKinds {
		ev, ok := loaded.Records[i].(sessions.Event)
		if !ok || ev.Kind != want {
			t.Fatalf("record %d = %T kind %q, want %q", i, loaded.Records[i], ev.Kind, want)
		}
	}
	for i, want := range []string{global.Path, project.Path} {
		var p SecurityStateHalted
		if err := json.Unmarshal(loaded.Records[i].(sessions.Event).Payload, &p); err != nil {
			t.Fatalf("decode record %d: %v", i, err)
		}
		if p.Path != want {
			t.Fatalf("record %d path = %q, want the monitor's order %q", i, p.Path, want)
		}
	}
}

// A startup checkpoint runs before any prompt is accepted or any round is started, so it
// persists the event alone: a synthetic terminal would sit in the session matching no round.
func TestEmitSecurityStateHalt_StartupPersistsTheEventAlone(t *testing.T) {
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	record := SecurityStateHalted{
		Path: haltGlobalPath, DetectionPoint: SecurityDetectionStartup, Labels: []string{"missing"},
	}
	if err := EmitSecurityStateHalt(context.Background(), store, []SecurityStateHalted{record}, nil, failOnWriteFailure(t)); err != nil {
		t.Fatalf("EmitSecurityStateHalt error = %v", err)
	}
	loaded := reloadSession(t, store)
	if len(loaded.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(loaded.Records))
	}
	ev, ok := loaded.Records[0].(sessions.Event)
	if !ok || ev.Kind != KindSecurityStateHalted {
		t.Fatalf("record = %T kind %q, want %q", loaded.Records[0], ev.Kind, KindSecurityStateHalted)
	}
}

func TestEmitSecurityStateHalt_RejectionsRecordNothing(t *testing.T) {
	terminal := TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted}
	completed := TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeCompleted}
	startup := SecurityStateHalted{Path: haltGlobalPath, DetectionPoint: SecurityDetectionStartup, Labels: []string{"missing"}}
	noTurnID := TurnTerminal{RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted}
	badTurnID := TurnTerminal{TurnID: "not-a-uuidv7", RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted}
	badRoundID := TurnTerminal{TurnID: testTurnID, RoundID: "not-a-uuidv7", Outcome: TurnOutcomeSecurityHalted}
	withFailurePhase := TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted, FailurePhase: "dial"}
	withFailedTool := TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted, FailedTool: "read_file", FailureReason: DispatchReasonToolDispatchFailed}

	for name, tc := range map[string]struct {
		records  []SecurityStateHalted
		terminal *TurnTerminal
	}{
		"no affected layer":             {nil, &terminal},
		"invalid record":                {[]SecurityStateHalted{{Path: haltGlobalPath, DetectionPoint: "before_reply"}}, &terminal},
		"one invalid among many":        {[]SecurityStateHalted{semanticHalt(), {Path: haltProjectPath}}, &terminal},
		"startup with a terminal":       {[]SecurityStateHalted{startup}, &terminal},
		"in-turn halt without terminal": {[]SecurityStateHalted{semanticHalt()}, nil},
		"terminal for another outcome":  {[]SecurityStateHalted{semanticHalt()}, &completed},
		"two detection points at once":  {[]SecurityStateHalted{semanticHalt(), startup}, &terminal},
		"terminal missing its turn id":  {[]SecurityStateHalted{semanticHalt()}, &noTurnID},
		"terminal turn id not uuidv7":   {[]SecurityStateHalted{semanticHalt()}, &badTurnID},
		"terminal round id not uuidv7":  {[]SecurityStateHalted{semanticHalt()}, &badRoundID},
		"terminal with failure phase":   {[]SecurityStateHalted{semanticHalt()}, &withFailurePhase},
		"terminal with failed tool":     {[]SecurityStateHalted{semanticHalt()}, &withFailedTool},
	} {
		t.Run(name, func(t *testing.T) {
			var committed bool
			restoreCommit := commitStore
			commitStore = func(ctx context.Context, s *sessions.Store, recs ...sessions.Record) (fserrors.Category, sessions.WriteReason, error) {
				committed = true
				return s.CommitRecords(ctx, recs...)
			}
			t.Cleanup(func() { commitStore = restoreCommit })

			store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
			if err := EmitSecurityStateHalt(context.Background(), store, tc.records, tc.terminal, failOnWriteFailure(t)); err == nil {
				t.Fatalf("EmitSecurityStateHalt accepted %s, want rejection", name)
			}
			if committed {
				t.Fatalf("%s reached the store commit", name)
			}
			if n := len(store.Records()); n != 0 {
				t.Fatalf("%s queued %d record(s), want 0", name, n)
			}
		})
	}
}

// A halt whose records cannot be made durable is reported as a write failure and as an error
// to the caller, so the caller keeps the turn stopped and surfaces the write failure instead
// of claiming a recorded halt.
func TestEmitSecurityStateHalt_FlushFailureReachesTheWriteFailurePath(t *testing.T) {
	for _, tc := range []struct {
		name        string
		reason      sessions.WriteReason
		wantHandled int
	}{
		{"atomic write failure", sessions.ReasonWriteError, 1},
		{"a commit error the write-failure record cannot encode", sessions.ReasonNone, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restoreCommit := commitStore
			commitStore = func(ctx context.Context, s *sessions.Store, recs ...sessions.Record) (fserrors.Category, sessions.WriteReason, error) {
				return fserrors.IOError, tc.reason, errors.New("disk full")
			}
			t.Cleanup(func() { commitStore = restoreCommit })

			var handled int
			store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
			terminal := TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted}
			err := EmitSecurityStateHalt(context.Background(), store, []SecurityStateHalted{semanticHalt()}, &terminal,
				func(cat fserrors.Category, reason sessions.WriteReason, err error) { handled++ })
			if err == nil {
				t.Fatal("EmitSecurityStateHalt reported a durable halt after a failed flush")
			}
			if handled != tc.wantHandled {
				t.Fatalf("write-failure handler calls = %d, want %d", handled, tc.wantHandled)
			}
		})
	}
}

// A store closed by a fork or an in-process session switch drops a bare append without
// reporting it, and a flush that follows then has nothing new to write and succeeds. The
// halt must be reported as undurable so its caller takes the write-failure path instead of
// presenting a recorded halt the session file does not hold.
func TestEmitSecurityStateHalt_ClosedStoreIsNotADurableHalt(t *testing.T) {
	terminal := TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted, DispatchStarted: true}
	startup := SecurityStateHalted{Path: haltGlobalPath, DetectionPoint: SecurityDetectionStartup, Labels: []string{"missing"}}

	for name, tc := range map[string]struct {
		records  []SecurityStateHalted
		terminal *TurnTerminal
	}{
		"in-turn halt": {[]SecurityStateHalted{semanticHalt()}, &terminal},
		"startup halt": {[]SecurityStateHalted{startup}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
			if _, err := Append(store, LaunchBegan{Source: "fresh"}); err != nil {
				t.Fatalf("seed append: %v", err)
			}
			if _, _, err := store.Flush(context.Background()); err != nil {
				t.Fatalf("seed flush: %v", err)
			}
			store.Close()

			if err := EmitSecurityStateHalt(context.Background(), store, tc.records, tc.terminal, failOnWriteFailure(t)); err == nil {
				t.Fatal("EmitSecurityStateHalt reported a durable halt on a closed store")
			}
			if n := len(store.Records()); n != 1 {
				t.Fatalf("queued records = %d, want only the pre-close record", n)
			}
			loaded := reloadSession(t, store)
			if len(loaded.Records) != 1 {
				t.Fatalf("persisted records = %d, want only the pre-close record", len(loaded.Records))
			}
			ev, ok := loaded.Records[0].(sessions.Event)
			if !ok || ev.Kind != KindLaunchBegan {
				t.Fatalf("record = %T kind %q, want %q", loaded.Records[0], ev.Kind, KindLaunchBegan)
			}
		})
	}
}

// The halt is all-or-nothing under concurrency: a close that lands part-way through and
// unrelated appends racing the same store cannot leave the session file holding the
// security_state_halted records without the terminal that closes their round, and cannot
// leave a success reported for a halt no append reached. A count of records taken before and
// after the appends cannot tell those apart — a foreign append covers for a dropped one.
func TestEmitSecurityStateHalt_ConcurrentCloseAndAppendsAreAllOrNothing(t *testing.T) {
	terminal := TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted, DispatchStarted: true}
	for range 100 {
		store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
		if _, err := Append(store, LaunchBegan{Source: "fresh"}); err != nil {
			t.Fatalf("seed append: %v", err)
		}
		if _, _, err := store.Flush(context.Background()); err != nil {
			t.Fatalf("seed flush: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 8 {
				_, _ = Append(store, LaunchBegan{Source: "fresh"})
			}
		}()
		go func() {
			defer wg.Done()
			store.Close()
		}()
		err := EmitSecurityStateHalt(context.Background(), store, []SecurityStateHalted{semanticHalt()}, &terminal, failOnWriteFailure(t))
		wg.Wait()

		if _, _, ferr := store.Flush(context.Background()); ferr != nil {
			t.Fatalf("post-halt flush: %v", ferr)
		}
		var halts, terminals int
		for _, rec := range reloadSession(t, store).Records {
			ev, ok := rec.(sessions.Event)
			if !ok {
				continue
			}
			switch ev.Kind {
			case KindSecurityStateHalted:
				halts++
			case KindTurnTerminal:
				terminals++
			}
		}
		wantHalts, wantTerminals := 1, 1
		if err != nil {
			wantHalts, wantTerminals = 0, 0
		}
		if halts != wantHalts || terminals != wantTerminals {
			t.Fatalf("EmitSecurityStateHalt error = %v; persisted %d halt record(s) and %d terminal(s), want %d and %d",
				err, halts, terminals, wantHalts, wantTerminals)
		}
	}
}

func reloadSession(t *testing.T, store *sessions.Store) *sessions.Session {
	t.Helper()
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("read flushed session: %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("sessions.Unmarshal error = %v", err)
	}
	return loaded
}
