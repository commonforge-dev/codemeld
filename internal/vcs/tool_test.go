// Unit tests for the vcs_<action> tool wrapper: name/subject, arg decoding and
// routing, EffectiveCWD agreement with ResolveActionCWD, and template registration.
package vcs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/tools"
)

func gitTemplate() *Template {
	return &Template{
		Name:   "git",
		Source: "/etc/codemeld/vcs/git.yaml",
		Detect: &DetectSpec{Marker: ".git"},
		Actions: map[string]ActionSpec{
			"status":        {Argv: []string{"git", "status"}},
			"add":           {Argv: []string{"git", "add", "{path}"}},
			"commit":        {Argv: []string{"git", "commit", "-m", "{message}"}},
			"branch-create": {Argv: []string{"git", "branch", "{branch}"}},
			"log":           {Argv: []string{"missing-binary", "log"}},
		},
	}
}

func TestActionTool_NameAndSubjectKind(t *testing.T) {
	tool := &ActionTool{actionName: "add"}
	if tool.Name() != "vcs_add" {
		t.Errorf("Name() = %q, want vcs_add", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Errorf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}
}

func TestActionTool_InvokeDecodesArgsAndRoutes(t *testing.T) {
	repo := t.TempDir()
	fr := &fakeRunner{id: ids.NewV7(), result: cmdrunner.RunResult{ExitCode: 0}}
	c := newCapture()
	tool := &ActionTool{
		actionName: "add",
		action:     ActionSpec{Argv: []string{"git", "add", "{path}"}},
		repoRoot:   repo,
		runner:     fr,
		emit:       c.appendEvent,
	}

	if _, err := tool.Invoke(context.Background(), map[string]any{"path": "a/b.go"}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if got := fr.gotSpec.Argv; len(got) != 3 || got[2] != "a/b.go" {
		t.Errorf("routed argv = %v, want last element a/b.go", got)
	}
}

func TestActionTool_InvokeMissingRequiredArg(t *testing.T) {
	repo := t.TempDir()
	fr := &fakeRunner{id: ids.NewV7()}
	c := newCapture()
	tool := &ActionTool{
		actionName: "add",
		action:     ActionSpec{Argv: []string{"git", "add", "{path}"}},
		repoRoot:   repo,
		runner:     fr,
		emit:       c.appendEvent,
	}
	if _, err := tool.Invoke(context.Background(), map[string]any{}); err == nil {
		t.Fatal("Invoke accepted a missing required {path} argument")
	}
	if fr.execCalls != 0 {
		t.Errorf("runner ran %d times, want 0", fr.execCalls)
	}
}

func TestActionTool_EffectiveCWDMatchesResolver(t *testing.T) {
	repo := t.TempDir()

	t.Run("contained", func(t *testing.T) {
		tool := &ActionTool{actionName: "status", action: ActionSpec{}, repoRoot: repo}
		gotTool, errTool := tool.EffectiveCWD()
		gotFn, errFn := ResolveActionCWD(&tool.action, repo)
		if gotTool != gotFn || (errTool == nil) != (errFn == nil) {
			t.Fatalf("EffectiveCWD = (%q,%v), ResolveActionCWD = (%q,%v); must match", gotTool, errTool, gotFn, errFn)
		}
		if gotTool != evalSym(t, repo) {
			t.Errorf("EffectiveCWD = %q, want %q", gotTool, evalSym(t, repo))
		}
	})

	t.Run("escape", func(t *testing.T) {
		outside := t.TempDir()
		tool := &ActionTool{actionName: "status", action: ActionSpec{Cwd: outside}, repoRoot: repo}
		gotTool, errTool := tool.EffectiveCWD()
		gotFn, errFn := ResolveActionCWD(&tool.action, repo)
		var escTool, escFn *CWDEscapeError
		if !errors.As(errTool, &escTool) || !errors.As(errFn, &escFn) {
			t.Fatalf("EffectiveCWD err %v / ResolveActionCWD err %v; both must be *CWDEscapeError", errTool, errFn)
		}
		if gotTool != gotFn || escTool.ResolvedCwd != escFn.ResolvedCwd {
			t.Errorf("escape mismatch: EffectiveCWD (%q,%q) vs ResolveActionCWD (%q,%q)", gotTool, escTool.ResolvedCwd, gotFn, escFn.ResolvedCwd)
		}
	})
}

func TestRegisterActions_RegistersNonDetectByName(t *testing.T) {
	repo := t.TempDir()
	fr := &fakeRunner{id: ids.NewV7()}
	c := newCapture()
	reg := tools.NewRegistry()

	if err := RegisterActions(reg, gitTemplate(), repo, fr, c.appendEvent, 64); err != nil {
		t.Fatalf("RegisterActions: %v", err)
	}

	for _, action := range []string{"status", "add", "commit", "branch-create", "log"} {
		name := toolName(action)
		got, ok := reg.Lookup(name)
		if !ok {
			t.Errorf("Lookup(%q) miss, want registered", name)
			continue
		}
		if got.Name() != name {
			t.Errorf("registered tool Name() = %q, want %q", got.Name(), name)
		}
		if _, isAction := got.(*ActionTool); !isAction {
			t.Errorf("registered %q is %T, want *ActionTool", name, got)
		}
	}
	// detect is not a runnable action and must not be registered.
	if _, ok := reg.Lookup(toolName("detect")); ok {
		t.Error("vcs_detect was registered; detect must never become a tool")
	}
}

func TestRegisterActions_NoTemplateRegistersNothing(t *testing.T) {
	repo := t.TempDir()
	fr := &fakeRunner{id: ids.NewV7()}
	c := newCapture()
	reg := tools.NewRegistry()

	if err := RegisterActions(reg, nil, repo, fr, c.appendEvent, 64); err != nil {
		t.Fatalf("RegisterActions(nil): %v", err)
	}
	if _, ok := reg.Lookup("vcs_status"); ok {
		t.Error("a vcs_<action> tool was registered with no active template")
	}
}

// TestRegisterActions_ThreadsCapToPersistedEnd asserts the cap handed to
// RegisterActions reaches the persisted tool_exec_end of a *registered* tool —
// the registration path that direct-Invoke tests in invoke_test.go bypass. Both
// dispatch entry points are covered: the Invoke path and the
// InvokeWithEffectiveCWD path structured dispatch uses. Miswiring
// RegisterActions to store cap 0 (tool.go:111) or InvokeWithEffectiveCWD to pass
// 0 (tool.go:54) must fail these.
func TestRegisterActions_ThreadsCapToPersistedEnd(t *testing.T) {
	const cap = 4
	rawOut := bytes.Repeat([]byte("a"), 20)
	rawErr := bytes.Repeat([]byte("b"), 30)

	assertCapped := func(t *testing.T, end events.ToolExecEnd) {
		t.Helper()
		if end.Stdout != "aaaa" || end.Stderr != "bbbb" {
			t.Errorf("persisted stdout/stderr = %q/%q, want aaaa/bbbb (cap not threaded)", end.Stdout, end.Stderr)
		}
		if !end.Truncated {
			t.Error("persisted truncated = false, want true")
		}
		if end.OriginalBytes == nil {
			t.Fatal("persisted original_bytes is nil, want set")
		}
		if end.OriginalBytes.Stdout != 20 || end.OriginalBytes.Stderr != 30 {
			t.Errorf("original_bytes = %+v, want {20 30}", *end.OriginalBytes)
		}
	}

	t.Run("Invoke path", func(t *testing.T) {
		repo := t.TempDir()
		fr := &fakeRunner{id: ids.NewV7(), result: cmdrunner.RunResult{ExitCode: 0, Stdout: rawOut, Stderr: rawErr}}
		c := newCapture()
		reg := tools.NewRegistry()
		if err := RegisterActions(reg, gitTemplate(), repo, fr, c.appendEvent, cap); err != nil {
			t.Fatalf("RegisterActions: %v", err)
		}
		tool, ok := reg.Lookup("vcs_status")
		if !ok {
			t.Fatal("vcs_status not registered")
		}
		if _, err := tool.Invoke(context.Background(), nil); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		assertCapped(t, c.persistedEnd(t))
	})

	t.Run("InvokeWithEffectiveCWD path", func(t *testing.T) {
		repo := t.TempDir()
		fr := &fakeRunner{id: ids.NewV7(), result: cmdrunner.RunResult{ExitCode: 0, Stdout: rawOut, Stderr: rawErr}}
		c := newCapture()
		reg := tools.NewRegistry()
		if err := RegisterActions(reg, gitTemplate(), repo, fr, c.appendEvent, cap); err != nil {
			t.Fatalf("RegisterActions: %v", err)
		}
		got, ok := reg.Lookup("vcs_status")
		if !ok {
			t.Fatal("vcs_status not registered")
		}
		at, ok := got.(*ActionTool)
		if !ok {
			t.Fatalf("registered vcs_status is %T, want *ActionTool", got)
		}
		cwd, cwdErr := at.EffectiveCWD()
		if _, err := at.InvokeWithEffectiveCWD(context.Background(), nil, cwd, cwdErr); err != nil {
			t.Fatalf("InvokeWithEffectiveCWD: %v", err)
		}
		assertCapped(t, c.persistedEnd(t))
	})
}

// mustLoadBuiltin returns the named embedded built-in template, whose synthetic Source token
// (built-in:<name>) is what drives the product-authored read-only classification.
func mustLoadBuiltin(t *testing.T, name string) *Template {
	t.Helper()
	m, err := LoadBuiltinTemplates()
	if err != nil {
		t.Fatalf("LoadBuiltinTemplates: %v", err)
	}
	tmpl, ok := m[name]
	if !ok {
		t.Fatalf("built-in template %q not loaded", name)
	}
	return tmpl
}

// registerBuiltinActions registers every non-detect action of the named built-in template into a
// fresh registry so a test can inspect the advertised metadata of real registered tools.
func registerBuiltinActions(t *testing.T, name string) *tools.Registry {
	t.Helper()
	reg := tools.NewRegistry()
	if err := RegisterActions(reg, mustLoadBuiltin(t, name), t.TempDir(), &fakeRunner{id: ids.NewV7()}, newCapture().appendEvent, 64); err != nil {
		t.Fatalf("RegisterActions: %v", err)
	}
	return reg
}

func registerActionsForTest(t *testing.T, tmpl *Template, trustExplicitClasses bool) *tools.Registry {
	t.Helper()
	reg := tools.NewRegistry()
	register := RegisterActions
	if trustExplicitClasses {
		register = RegisterActionsWithTrustedClasses
	}
	if err := register(reg, tmpl, t.TempDir(), &fakeRunner{id: ids.NewV7()}, newCapture().appendEvent, 64); err != nil {
		t.Fatalf("RegisterActions: %v", err)
	}
	return reg
}

func registeredReadOnly(t *testing.T, reg *tools.Registry, action string) bool {
	t.Helper()
	tool, ok := reg.Lookup(toolName(action))
	if !ok {
		t.Fatalf("%s not registered", toolName(action))
	}
	return tool.Advertise().ReadOnly
}

// TestActionTool_BuiltinMetadataAndParamSchema asserts every registered built-in vcs_<action> tool
// carries a non-empty description and a parameter JSON-Schema matching its placeholder
// contract: no-placeholder actions take an empty object; placeholder actions require exactly their
// single string property (path/message/branch). Both shapes forbid additional properties.
func TestActionTool_BuiltinMetadataAndParamSchema(t *testing.T) {
	reg := registerBuiltinActions(t, "git")
	for _, action := range requiredActions {
		if action == "detect" {
			continue
		}
		tool, ok := reg.Lookup(toolName(action))
		if !ok {
			t.Fatalf("%s not registered", toolName(action))
		}
		md := tool.Advertise()
		if strings.TrimSpace(md.Description) == "" {
			t.Errorf("%s: empty advertising description", toolName(action))
		}
		if md.Parameters["type"] != "object" {
			t.Errorf("%s: parameter schema type = %v, want object", toolName(action), md.Parameters["type"])
		}
		if md.Parameters["additionalProperties"] != false {
			t.Errorf("%s: additionalProperties = %v, want false", toolName(action), md.Parameters["additionalProperties"])
		}
		props, ok := md.Parameters["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s: properties is %T, want map[string]any", toolName(action), md.Parameters["properties"])
		}

		accepted := placeholderActions[action]
		if accepted == "" {
			if len(props) != 0 {
				t.Errorf("%s: no-placeholder action has %d properties, want 0", toolName(action), len(props))
			}
			if _, has := md.Parameters["required"]; has {
				t.Errorf("%s: no-placeholder action declares required, want none", toolName(action))
			}
			continue
		}

		key := strings.Trim(accepted, "{}")
		if len(props) != 1 {
			t.Errorf("%s: placeholder action has %d properties, want exactly 1 (%q)", toolName(action), len(props), key)
		}
		prop, ok := props[key].(map[string]any)
		if !ok || prop["type"] != "string" {
			t.Errorf("%s: property %q = %v, want a string-typed schema", toolName(action), key, props[key])
		}
		req, ok := md.Parameters["required"].([]string)
		if !ok || !slices.Equal(req, []string{key}) {
			t.Errorf("%s: required = %v, want exactly [%q]", toolName(action), md.Parameters["required"], key)
		}
	}
}

// TestActionTool_BuiltinReadOnlyClassificationExactSets pins the exact read-only and mutating
// action sets for a built-in template source, enumerated via the deterministic registry listing so
// no action is silently miscounted. A drift in either list (e.g. moving stash into read-only) fails.
func TestActionTool_BuiltinReadOnlyClassificationExactSets(t *testing.T) {
	reg := registerBuiltinActions(t, "git")

	gotReadOnly := map[string]bool{}
	gotMutating := map[string]bool{}
	for _, tool := range reg.List() {
		if tool.Advertise().ReadOnly {
			gotReadOnly[tool.Name()] = true
		} else {
			gotMutating[tool.Name()] = true
		}
	}

	wantReadOnly := map[string]bool{
		"vcs_status": true, "vcs_diff": true, "vcs_log": true,
		"vcs_branch_current": true, "vcs_is_clean": true,
		"vcs_merge_status": true, "vcs_rebase_status": true,
	}
	wantMutating := map[string]bool{
		"vcs_add": true, "vcs_commit": true, "vcs_branch_create": true,
		"vcs_branch_switch": true, "vcs_restore_file": true,
		"vcs_stash": true, "vcs_stash_pop": true,
	}
	if !maps.Equal(gotReadOnly, wantReadOnly) {
		t.Errorf("built-in read-only set = %v, want %v", gotReadOnly, wantReadOnly)
	}
	if !maps.Equal(gotMutating, wantMutating) {
		t.Errorf("built-in mutating set = %v, want %v", gotMutating, wantMutating)
	}
}

// TestActionTool_BuiltinClassificationIsByNameNotArgv pins that built-in classification is keyed on
// action name, not the underlying argv. In the jj built-in, stash/stash-pop and merge-status/
// rebase-status all run `jj status`, yet stash/stash-pop must stay mutating and the status probes
// read-only — proving the class comes from the product-authored action-name lists, not the
// command behind the action.
func TestActionTool_BuiltinClassificationIsByNameNotArgv(t *testing.T) {
	reg := registerBuiltinActions(t, "jj")
	classOf := func(action string) bool {
		tool, ok := reg.Lookup(toolName(action))
		if !ok {
			t.Fatalf("%s not registered", toolName(action))
		}
		return tool.Advertise().ReadOnly
	}
	for _, action := range []string{"stash", "stash-pop"} {
		if classOf(action) {
			t.Errorf("jj %s classified read-only, want mutating (action-name based, req 220)", toolName(action))
		}
	}
	for _, action := range []string{"merge-status", "rebase-status"} {
		if !classOf(action) {
			t.Errorf("jj %s classified mutating, want read-only (action-name based, req 220)", toolName(action))
		}
	}
}

func TestActionTool_UnchangedReferenceCopyUsesBuiltinClassification(t *testing.T) {
	tmpl := &Template{
		Name:                 "git",
		Source:               "/home/user/.codemeld/global/vcs/git.yaml",
		BuiltinReferenceCopy: true,
		Actions: map[string]ActionSpec{
			"status": {Argv: []string{"git", "status"}},
			"diff":   {Argv: []string{"git", "diff"}},
			"add":    {Argv: []string{"git", "add", "{path}"}},
		},
	}
	reg := registerActionsForTest(t, tmpl, false)

	for _, action := range []string{"status", "diff"} {
		if !registeredReadOnly(t, reg, action) {
			t.Errorf("unchanged reference %s classified mutating, want read-only", toolName(action))
		}
	}
	if registeredReadOnly(t, reg, "add") {
		t.Error("unchanged reference vcs_add classified read-only, want mutating")
	}
}

// A trusted global template's read_only declaration is honored only over the product's own read-only
// command: an altered argv behind a familiar action name is a claim about something unvetted.
func TestActionTool_TrustedClassCanMarkReadOnly(t *testing.T) {
	tmpl := &Template{
		Name:   "git",
		Source: "/home/user/.codemeld/global/vcs/git.yaml",
		Actions: map[string]ActionSpec{
			"log":            {Argv: builtinArgv()["git"]["log"], Class: ClassReadOnly},
			"diff":           {Argv: []string{"git", "diff", "--safe"}, Class: ClassReadOnly},
			"status":         {Argv: builtinArgv()["git"]["status"]},
			"restore-file":   {Argv: builtinArgv()["git"]["restore-file"], Class: ClassReadOnly},
			"branch-current": {Argv: builtinArgv()["hg"]["branch-current"], Class: ClassReadOnly},
		},
	}
	reg := registerActionsForTest(t, tmpl, true)

	if !registeredReadOnly(t, reg, "log") {
		t.Error("trusted explicit class over the built-in argv did not make vcs_log read-only")
	}
	if registeredReadOnly(t, reg, "diff") {
		t.Error("trusted explicit class over an altered argv made vcs_diff read-only, want mutating")
	}
	if registeredReadOnly(t, reg, "status") {
		t.Error("trusted vcs_status without an explicit class classified read-only, want mutating")
	}
	if registeredReadOnly(t, reg, "restore-file") {
		t.Error("trusted explicit class over a mutating action made vcs_restore_file read-only, want mutating")
	}
	if registeredReadOnly(t, reg, "branch-current") {
		t.Error("trusted explicit class over another backend's argv made vcs_branch_current read-only, want mutating")
	}
}

func TestActionTool_UntrustedClassIgnored(t *testing.T) {
	tmpl := &Template{
		Name:   "git",
		Source: "/repo/.codemeld/vcs/git.yaml",
		Actions: map[string]ActionSpec{
			"status": {Argv: []string{"git", "push"}, Class: ClassReadOnly},
		},
	}
	reg := registerActionsForTest(t, tmpl, false)

	if registeredReadOnly(t, reg, "status") {
		t.Error("untrusted explicit class made vcs_status read-only, want mutating")
	}
}

// TestActionTool_UserTemplateActionsDefaultMutating proves: a disk-loaded template — even one
// overriding a built-in name — is a user source, so every action is classified mutating by default,
// including an overridden status that the built-in classifies read-only. Classification is per
// template source, not per action name, so Plan's read-only guarantee never trusts user argv.
func TestActionTool_UserTemplateActionsDefaultMutating(t *testing.T) {
	tmpl := &Template{
		Name:   "git",
		Source: "/home/user/.codemeld/vcs/git.yaml", // a file path, not the built-in:git token
		Actions: map[string]ActionSpec{
			"status": {Argv: []string{"git", "status"}},
			"diff":   {Argv: []string{"git", "push"}}, // arbitrary argv behind a known, validated name
		},
	}
	reg := tools.NewRegistry()
	if err := RegisterActions(reg, tmpl, t.TempDir(), &fakeRunner{id: ids.NewV7()}, newCapture().appendEvent, 64); err != nil {
		t.Fatalf("RegisterActions: %v", err)
	}
	for _, action := range []string{"status", "diff"} {
		tool, ok := reg.Lookup(toolName(action))
		if !ok {
			t.Fatalf("%s not registered", toolName(action))
		}
		if tool.Advertise().ReadOnly {
			t.Errorf("user-template %s classified read-only, want mutating (req 225)", toolName(action))
		}
	}
}

func TestRegisterActions_RegisteredWrapperPreservesLaunchFailure(t *testing.T) {
	repo := t.TempDir()
	fr := &fakeRunner{id: ids.NewV7(), result: cmdrunner.RunResult{ExitCode: -1, LaunchErrCategory: fserrors.NotFound}}
	c := newCapture()
	reg := tools.NewRegistry()
	if err := RegisterActions(reg, gitTemplate(), repo, fr, c.appendEvent, 64); err != nil {
		t.Fatalf("RegisterActions: %v", err)
	}

	tool, ok := reg.Lookup("vcs_log")
	if !ok {
		t.Fatal("vcs_log not registered")
	}
	res, err := tool.Invoke(context.Background(), nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	want := "codemeld: vcs_log: launch failed: missing-binary: not_found"
	if res.ExitCode != -1 || string(res.Stderr) != want {
		t.Errorf("result = {exit %d stderr %q}, want {exit -1 stderr %q}", res.ExitCode, res.Stderr, want)
	}
}

func registeredDescription(t *testing.T, reg *tools.Registry, action string) string {
	t.Helper()
	tool, ok := reg.Lookup(toolName(action))
	if !ok {
		t.Fatalf("%s not registered", toolName(action))
	}
	return tool.Advertise().Description
}

func TestActionTool_HgDescriptionsStateMercurialBehavior(t *testing.T) {
	reg := registerBuiltinActions(t, "hg")

	cases := map[string][]string{
		"status":        {"modified", "added", "removed", "deleted", "unknown", "no staging concept"},
		"add":           {"already tracked", "needs no add"},
		"commit":        {"every tracked modified file", "no staging step"},
		"branch-create": {"current working-directory branch", "rather than creating a branch without switching"},
	}
	for action, wants := range cases {
		got := registeredDescription(t, reg, action)
		for _, want := range wants {
			if !strings.Contains(got, want) {
				t.Errorf("hg %s description %q does not state %q", toolName(action), got, want)
			}
		}
		if got == actionDescriptions[action] {
			t.Errorf("hg %s still advertises the generic description", toolName(action))
		}
	}
	if status := registeredDescription(t, reg, "status"); strings.Contains(status, "ignored") {
		t.Errorf("hg vcs_status description %q claims ignored files, which bare `hg status` omits", status)
	}
}

func TestActionTool_GitDescriptionsStayGeneric(t *testing.T) {
	reg := registerBuiltinActions(t, "git")

	for _, action := range requiredActions {
		if action == "detect" {
			continue
		}
		if got := registeredDescription(t, reg, action); got != actionDescriptions[action] {
			t.Errorf("git %s description = %q, want the generic %q", toolName(action), got, actionDescriptions[action])
		}
	}
}

func TestActionTool_NonOverriddenHgActionsStayGeneric(t *testing.T) {
	reg := registerBuiltinActions(t, "hg")

	expectedOverrides := []string{"add", "branch-create", "commit", "status"}
	if got := slices.Sorted(maps.Keys(vcsActionDescriptions["hg"])); !slices.Equal(got, expectedOverrides) {
		t.Fatalf("hg override actions = %v, want exactly %v", got, expectedOverrides)
	}

	for _, action := range requiredActions {
		if action == "detect" || slices.Contains(expectedOverrides, action) {
			continue
		}
		if got := registeredDescription(t, reg, action); got != actionDescriptions[action] {
			t.Errorf("hg %s description = %q, want the generic %q", toolName(action), got, actionDescriptions[action])
		}
	}
}

// TestActionTool_UnknownVCSNameFallsBackToGeneric loads a user template whose name is outside the
// built-in set, so the fallback is proven for a name the override map will never gain an entry for.
func TestActionTool_UnknownVCSNameFallsBackToGeneric(t *testing.T) {
	loaded, err := loadOne(t, "svn.yaml", buildTemplate(nil))
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	tmpl, ok := loaded["svn"]
	if !ok {
		t.Fatalf("template svn not loaded; got keys %v", slices.Sorted(maps.Keys(loaded)))
	}
	reg := registerActionsForTest(t, tmpl, false)

	for _, action := range requiredActions {
		if action == "detect" {
			continue
		}
		got := registeredDescription(t, reg, action)
		if strings.TrimSpace(got) == "" {
			t.Errorf("%s: empty advertising description", toolName(action))
		}
		if got != actionDescriptions[action] {
			t.Errorf("svn %s description = %q, want the generic %q", toolName(action), got, actionDescriptions[action])
		}
	}
}

func jjOverrideActions() []string {
	return []string{"add", "branch-current", "commit", "merge-status", "rebase-status", "stash", "stash-pop", "status"}
}

func TestActionTool_JJDescriptionsStateJujutsuBehavior(t *testing.T) {
	reg := registerBuiltinActions(t, "jj")

	cases := map[string][]string{
		"status":         {"changed files", "no staging step"},
		"add":            {"does not track yet", "working-copy snapshot excludes", "tracks working-copy files automatically"},
		"commit":         {"Describe the existing working-copy commit", "all of its current changes", "new working-copy commit on top", "no staging step"},
		"stash":          {"set nothing aside", "no stash", "already a commit"},
		"stash-pop":      {"reapply nothing", "no stash", "already a commit"},
		"branch-current": {"List Jujutsu bookmarks", "rather than reporting a checked-out branch"},
		"merge-status":   {"general working-copy state", "conflicts recorded in commits", "rather than whether a merge is in progress"},
		"rebase-status":  {"general working-copy state", "general status probe, not a rebase-specific one"},
	}
	if got := slices.Sorted(maps.Keys(cases)); !slices.Equal(got, jjOverrideActions()) {
		t.Fatalf("covered jj actions = %v, want exactly %v", got, jjOverrideActions())
	}
	for action, wants := range cases {
		got := registeredDescription(t, reg, action)
		for _, want := range wants {
			if !strings.Contains(got, want) {
				t.Errorf("jj %s description %q does not state %q", toolName(action), got, want)
			}
		}
		if got == actionDescriptions[action] {
			t.Errorf("jj %s still advertises the generic description", toolName(action))
		}
	}
}

func TestActionTool_NonOverriddenJJActionsStayGeneric(t *testing.T) {
	reg := registerBuiltinActions(t, "jj")

	if got := slices.Sorted(maps.Keys(vcsActionDescriptions["jj"])); !slices.Equal(got, jjOverrideActions()) {
		t.Fatalf("jj override actions = %v, want exactly %v", got, jjOverrideActions())
	}

	for _, action := range requiredActions {
		if action == "detect" || slices.Contains(jjOverrideActions(), action) {
			continue
		}
		if got := registeredDescription(t, reg, action); got != actionDescriptions[action] {
			t.Errorf("jj %s description = %q, want the generic %q", toolName(action), got, actionDescriptions[action])
		}
	}
}

// customizedJJTemplate writes a jj.yaml carrying the embedded Jujutsu argv with argv substituted for
// the changed action, then loads it through the ordinary loader so the registered actions come from
// parsed user-supplied YAML rather than a handwritten Template value.
func customizedJJTemplate(t *testing.T, changed string, argv []string) *Template {
	t.Helper()
	builtinJJ := mustLoadBuiltin(t, "jj")
	var sb strings.Builder
	sb.WriteString("detect:\n  marker: .jj\n\n")
	for _, action := range requiredActions {
		if action == "detect" {
			continue
		}
		spec, ok := builtinJJ.Actions[action]
		if !ok {
			t.Fatalf("embedded jj template has no %q action", action)
		}
		words := spec.Argv
		if action == changed {
			words = argv
		}
		quoted := make([]string, len(words))
		for i, word := range words {
			quoted[i] = strconv.Quote(word)
		}
		fmt.Fprintf(&sb, "%s:\n  argv: [%s]\n\n", action, strings.Join(quoted, ", "))
	}
	loaded, err := loadOne(t, "jj.yaml", sb.String())
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	tmpl, ok := loaded["jj"]
	if !ok {
		t.Fatalf("template jj not loaded; got keys %v", slices.Sorted(maps.Keys(loaded)))
	}
	return tmpl
}

// TestActionTool_CustomizedJJActionLosesBuiltinClaim pins that description selection is per action
// argv, not per template name: a jj.yaml redefining one action drops only that action's built-in
// Jujutsu claim, while its untouched actions keep the accurate wording.
func TestActionTool_CustomizedJJActionLosesBuiltinClaim(t *testing.T) {
	const changed = "stash"
	tmpl := customizedJJTemplate(t, changed, []string{"jj", "new"})
	reg := registerActionsForTest(t, tmpl, false)

	got := registeredDescription(t, reg, changed)
	if got == vcsActionDescriptions["jj"][changed] {
		t.Errorf("customized jj %s advertises the built-in Jujutsu description %q", toolName(changed), got)
	}
	if got == actionDescriptions[changed] {
		t.Errorf("customized jj %s advertises the generic git-oriented description %q", toolName(changed), got)
	}
	if !strings.Contains(got, "configured Jujutsu stash action") {
		t.Errorf("customized jj %s description = %q, want it to name the configured action", toolName(changed), got)
	}

	for _, action := range jjOverrideActions() {
		if action == changed {
			continue
		}
		if got := registeredDescription(t, reg, action); got != vcsActionDescriptions["jj"][action] {
			t.Errorf("unchanged jj %s description = %q, want the Jujutsu override %q", toolName(action), got, vcsActionDescriptions["jj"][action])
		}
	}
	for _, action := range requiredActions {
		if action == "detect" || slices.Contains(jjOverrideActions(), action) {
			continue
		}
		if got := registeredDescription(t, reg, action); got != actionDescriptions[action] {
			t.Errorf("unchanged jj %s description = %q, want the generic %q", toolName(action), got, actionDescriptions[action])
		}
	}
}

// scriptRunner answers a fixed sequence of results and records every spec, so a test can assert the
// exact query argv and drive a multi-query verdict.
type scriptRunner struct {
	results []cmdrunner.RunResult
	err     error
	specs   []cmdrunner.RunSpec
}

func (s *scriptRunner) NewInvocationID() string { return ids.NewV7() }

func (s *scriptRunner) Exec(_ context.Context, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	s.specs = append(s.specs, spec)
	if s.err != nil {
		return cmdrunner.RunResult{}, s.err
	}
	if len(s.results) == 0 {
		return cmdrunner.RunResult{}, fmt.Errorf("unscripted exec of %v", spec.Argv)
	}
	res := s.results[0]
	s.results = s.results[1:]
	return res, nil
}

func (s *scriptRunner) argvs() [][]string {
	var out [][]string
	for _, spec := range s.specs {
		out = append(out, spec.Argv)
	}
	return out
}

func builtinAction(t *testing.T, vcsName, actionName, repoRoot string, r cmdrunner.Runner) *ActionTool {
	t.Helper()
	tmpl := mustLoadBuiltin(t, vcsName)
	action, ok := tmpl.Actions[actionName]
	if !ok {
		t.Fatalf("built-in %s template has no action %q", vcsName, actionName)
	}
	return &ActionTool{
		actionName: actionName,
		action:     action,
		repoRoot:   repoRoot,
		runner:     r,
		emit:       newCapture().appendEvent,
		vcsName:    vcsName,
		reference:  true,
	}
}

func fixedProtected(paths ...string) func(string) ([]string, error) {
	return func(string) ([]string, error) { return paths, nil }
}

// Only a product-authored command may skip the guard: a customized action is refused without any
// query, because nothing constrains what its argv does.
func TestActionTool_ProtectedStateRiskProvenanceAndArgv(t *testing.T) {
	root := t.TempDir()
	protected := fixedProtected(filepath.Join(root, ".codemeld", "settings.yaml"))
	gitStatus := builtinArgv()["git"]["status"]
	gitAdd := builtinArgv()["git"]["add"]

	cases := []struct {
		name string
		tool *ActionTool
		want bool
	}{
		{"embedded built-in", &ActionTool{actionName: "status", action: ActionSpec{Argv: gitStatus}, vcsName: "git", reference: true}, false},
		{"trusted global read_only over exact built-in argv", &ActionTool{actionName: "status", action: ActionSpec{Argv: gitStatus, Class: ClassReadOnly}, vcsName: "git", trusted: true}, false},
		{"trusted global read_only over altered argv", &ActionTool{actionName: "status", action: ActionSpec{Argv: []string{"git", "status", "--porcelain"}, Class: ClassReadOnly}, vcsName: "git", trusted: true}, true},
		{"trusted global exact argv without a class declaration", &ActionTool{actionName: "status", action: ActionSpec{Argv: gitStatus}, vcsName: "git", trusted: true}, true},
		{"project template read_only over exact built-in argv", &ActionTool{actionName: "status", action: ActionSpec{Argv: gitStatus, Class: ClassReadOnly}, vcsName: "git"}, true},
		{"trusted global read_only over a mutating action", &ActionTool{actionName: "add", action: ActionSpec{Argv: gitAdd, Class: ClassReadOnly}, vcsName: "git", trusted: true}, true},
		{"nominal status that rewrites the settings file", &ActionTool{actionName: "status", action: ActionSpec{Argv: []string{"git", "checkout", "--", ".codemeld/settings.yaml"}, Class: ClassReadOnly}, vcsName: "git", trusted: true}, true},
		{"template naming a backend the product does not author", &ActionTool{actionName: "status", action: ActionSpec{Argv: []string{"svn", "status"}, Class: ClassReadOnly}, vcsName: "svn", trusted: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := &scriptRunner{}
			tc.tool.runner = run
			tc.tool.repoRoot = root
			if got := tc.tool.ProtectedStateRisk(context.Background(), nil, protected); got != tc.want {
				t.Fatalf("ProtectedStateRisk = %v, want %v", got, tc.want)
			}
			if len(run.specs) != 0 {
				t.Fatalf("ran %v; a provenance verdict must not launch a query", run.argvs())
			}
		})
	}
}

// The queries are the whole security argument: assert the exact argv each risky action runs.
func TestActionTool_ProtectedStateRiskQueryArgv(t *testing.T) {
	root := t.TempDir()
	settings := filepath.Join(root, ".codemeld", "settings.yaml")
	protected := fixedProtected(settings)
	const sha = "0123456789abcdef0123456789abcdef01234567"
	const base = "89abcdef0123456789abcdef0123456789abcdef"
	revOut := cmdrunner.RunResult{Stdout: []byte(sha + "\n")}
	baseOut := cmdrunner.RunResult{Stdout: []byte(base + "\n")}
	clean := cmdrunner.RunResult{}
	untracked := cmdrunner.RunResult{ExitCode: 1}

	cases := []struct {
		name    string
		vcsName string
		action  string
		args    map[string]any
		results []cmdrunner.RunResult
		want    [][]string
	}{
		{
			name: "git branch switch", vcsName: "git", action: "branch-switch",
			args: map[string]any{"branch": "other"}, results: []cmdrunner.RunResult{revOut, clean},
			want: [][]string{
				{"git", "rev-parse", "--verify", "--quiet", "other^{commit}"},
				{"git", "--literal-pathspecs", "diff", "--quiet", "--no-ext-diff", sha, "--", ".codemeld/settings.yaml"},
			},
		},
		{
			name: "git restore", vcsName: "git", action: "restore-file",
			args: map[string]any{"path": ".codemeld/settings.yaml"}, results: []cmdrunner.RunResult{untracked},
			want: [][]string{{"git", "--literal-pathspecs", "ls-files", "--error-unmatch", "--", ".codemeld/settings.yaml"}},
		},
		{
			name: "git stash", vcsName: "git", action: "stash",
			results: []cmdrunner.RunResult{clean, clean},
			want: [][]string{
				{"git", "--literal-pathspecs", "diff", "--quiet", "--no-ext-diff", "--", ".codemeld/settings.yaml"},
				{"git", "--literal-pathspecs", "diff", "--quiet", "--no-ext-diff", "--cached", "--", ".codemeld/settings.yaml"},
			},
		},
		{
			name: "git stash pop", vcsName: "git", action: "stash-pop",
			results: []cmdrunner.RunResult{revOut, baseOut, clean},
			want: [][]string{
				{"git", "rev-parse", "--verify", "--quiet", "refs/stash"},
				{"git", "rev-parse", "--verify", "--quiet", "refs/stash^1"},
				{"git", "--literal-pathspecs", "diff", "--quiet", "--no-ext-diff", base, sha, "--", ".codemeld/settings.yaml"},
			},
		},
		{
			name: "hg branch switch", vcsName: "hg", action: "branch-switch",
			args: map[string]any{"branch": "other"}, results: []cmdrunner.RunResult{clean},
			want: [][]string{{"hg", "status", "--rev", "other", "--", "path:.codemeld/settings.yaml"}},
		},
		{
			name: "hg restore", vcsName: "hg", action: "restore-file",
			args: map[string]any{"path": ".codemeld/settings.yaml"}, results: []cmdrunner.RunResult{untracked},
			want: [][]string{{"hg", "files", "--", "path:.codemeld/settings.yaml"}},
		},
		{
			name: "hg stash", vcsName: "hg", action: "stash",
			results: []cmdrunner.RunResult{clean},
			want:    [][]string{{"hg", "status", "--modified", "--added", "--removed", "--deleted", "--", "path:.codemeld/settings.yaml"}},
		},
		{
			name: "jj branch switch", vcsName: "jj", action: "branch-switch",
			args: map[string]any{"branch": "other"}, results: []cmdrunner.RunResult{clean},
			want: [][]string{{"jj", "diff", "--from", "other", "--to", "@", "--name-only", "--", `root:".codemeld/settings.yaml"`}},
		},
		{
			name: "jj restore", vcsName: "jj", action: "restore-file",
			args: map[string]any{"path": ".codemeld/settings.yaml"}, results: []cmdrunner.RunResult{clean},
			want: [][]string{{"jj", "diff", "--from", "@-", "--to", "@", "--name-only", "--", `root:".codemeld/settings.yaml"`}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := &scriptRunner{results: tc.results}
			tool := builtinAction(t, tc.vcsName, tc.action, root, run)
			if risk := tool.ProtectedStateRisk(context.Background(), tc.args, protected); risk {
				t.Fatalf("ProtectedStateRisk = true, want false for a query set that reports no change")
			}
			if got := run.argvs(); !slices.EqualFunc(got, tc.want, slices.Equal) {
				t.Fatalf("queries = %v, want %v", got, tc.want)
			}
			for _, spec := range run.specs {
				if spec.Cwd != root {
					t.Fatalf("query cwd = %q, want the repo root %q", spec.Cwd, root)
				}
			}
		})
	}
}

func TestActionTool_ProtectedStateRiskSelectorNamedCandidateArgv(t *testing.T) {
	root := t.TempDir()
	const sha = "0123456789abcdef0123456789abcdef01234567"
	cases := []struct {
		vcsName   string
		candidate string
		results   []cmdrunner.RunResult
		want      [][]string
	}{
		{"git", ":(literal)secret", []cmdrunner.RunResult{{Stdout: []byte(sha + "\n")}, {}}, [][]string{
			{"git", "rev-parse", "--verify", "--quiet", "other^{commit}"},
			{"git", "--literal-pathspecs", "diff", "--quiet", "--no-ext-diff", sha, "--", ":(literal)secret"},
		}},
		{"hg", "path:secret", []cmdrunner.RunResult{{}}, [][]string{{"hg", "status", "--rev", "other", "--", "path:path:secret"}}},
	}
	for _, tc := range cases {
		t.Run(tc.vcsName, func(t *testing.T) {
			run := &scriptRunner{results: tc.results}
			tool := builtinAction(t, tc.vcsName, "branch-switch", root, run)
			if tool.ProtectedStateRisk(context.Background(), map[string]any{"branch": "other"}, fixedProtected(filepath.Join(root, tc.candidate))) {
				t.Fatal("ProtectedStateRisk = true, want false for a query set that reports no change")
			}
			if got := run.argvs(); !slices.EqualFunc(got, tc.want, slices.Equal) {
				t.Fatalf("queries = %v, want %v", got, tc.want)
			}
		})
	}
}

// The affected verdicts, and the actions that need no query at all.
func TestActionTool_ProtectedStateRiskAffectedAndExemptActions(t *testing.T) {
	root := t.TempDir()
	protected := fixedProtected(filepath.Join(root, ".codemeld", "settings.yaml"))
	const sha = "0123456789abcdef0123456789abcdef01234567"
	differs := cmdrunner.RunResult{ExitCode: 1}
	named := cmdrunner.RunResult{Stdout: []byte(".codemeld/settings.yaml\n")}

	cases := []struct {
		name    string
		vcsName string
		action  string
		args    map[string]any
		results []cmdrunner.RunResult
		want    bool
	}{
		{"git branch switch reaching the file", "git", "branch-switch", map[string]any{"branch": "other"}, []cmdrunner.RunResult{{Stdout: []byte(sha)}, differs}, true},
		{"git restore of a tracked file", "git", "restore-file", map[string]any{"path": ".codemeld/settings.yaml"}, []cmdrunner.RunResult{{}}, true},
		{"git stash with a staged change", "git", "stash", nil, []cmdrunner.RunResult{{}, differs}, true},
		{"git stash pop with nothing stashed", "git", "stash-pop", nil, []cmdrunner.RunResult{{ExitCode: 1}}, false},
		{"hg branch switch reaching the file", "hg", "branch-switch", map[string]any{"branch": "other"}, []cmdrunner.RunResult{named}, true},
		{"hg restore of a tracked file", "hg", "restore-file", map[string]any{"path": ".codemeld/settings.yaml"}, []cmdrunner.RunResult{{}}, true},
		{"hg unshelve has no affected-path query", "hg", "stash-pop", nil, nil, true},
		{"jj restore reaching the file", "jj", "restore-file", map[string]any{"path": ".codemeld/settings.yaml"}, []cmdrunner.RunResult{named}, true},
		{"jj stash only reports status", "jj", "stash", nil, nil, false},
		{"jj stash pop only reports status", "jj", "stash-pop", nil, nil, false},
		{"git add", "git", "add", map[string]any{"path": ".codemeld/settings.yaml"}, nil, false},
		{"git commit", "git", "commit", map[string]any{"message": "m"}, nil, false},
		{"git branch create", "git", "branch-create", map[string]any{"branch": "other"}, nil, false},
		{"hg add", "hg", "add", map[string]any{"path": ".codemeld/settings.yaml"}, nil, false},
		{"hg commit", "hg", "commit", map[string]any{"message": "m"}, nil, false},
		{"jj add", "jj", "add", map[string]any{"path": ".codemeld/settings.yaml"}, nil, false},
		{"jj commit", "jj", "commit", map[string]any{"message": "m"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := &scriptRunner{results: tc.results}
			tool := builtinAction(t, tc.vcsName, tc.action, root, run)
			if got := tool.ProtectedStateRisk(context.Background(), tc.args, protected); got != tc.want {
				t.Fatalf("ProtectedStateRisk = %v, want %v (queries run: %v)", got, tc.want, run.argvs())
			}
		})
	}
}

// Anything the guard cannot prove safe refuses: a failed query, an unexpected status, output it
// cannot bound or parse, an argument it cannot pass safely, and a protected set it cannot enumerate.
func TestActionTool_ProtectedStateRiskFailsClosed(t *testing.T) {
	root := t.TempDir()
	settings := filepath.Join(root, ".codemeld", "settings.yaml")
	protected := fixedProtected(settings)

	cases := []struct {
		name      string
		action    string
		args      map[string]any
		run       *scriptRunner
		protected func(string) ([]string, error)
	}{
		{"runner error", "restore-file", map[string]any{"path": ".codemeld/settings.yaml"}, &scriptRunner{err: errors.New("exec failed")}, protected},
		{"launch failure", "restore-file", map[string]any{"path": ".codemeld/settings.yaml"}, &scriptRunner{results: []cmdrunner.RunResult{{ExitCode: -1, LaunchErrCategory: fserrors.NotFound}}}, protected},
		{"unexpected exit status", "restore-file", map[string]any{"path": ".codemeld/settings.yaml"}, &scriptRunner{results: []cmdrunner.RunResult{{ExitCode: 128}}}, protected},
		{"oversized output", "restore-file", map[string]any{"path": ".codemeld/settings.yaml"}, &scriptRunner{results: []cmdrunner.RunResult{{Stdout: bytes.Repeat([]byte("a"), maxProtectQueryBytes+1)}}}, protected},
		{"NUL in output", "restore-file", map[string]any{"path": ".codemeld/settings.yaml"}, &scriptRunner{results: []cmdrunner.RunResult{{Stdout: []byte("a\x00b")}}}, protected},
		{"protected set cannot be enumerated", "restore-file", map[string]any{"path": ".codemeld/settings.yaml"}, &scriptRunner{}, func(string) ([]string, error) { return nil, errors.New("walk failed") }},
		{"flag-shaped branch", "branch-switch", map[string]any{"branch": "--exec=rm -rf /"}, &scriptRunner{}, protected},
		{"whole-tree branch argument", "branch-switch", map[string]any{"branch": "main -- ."}, &scriptRunner{}, protected},
		{"missing branch argument", "branch-switch", map[string]any{}, &scriptRunner{}, protected},
		{"unresolvable revision", "branch-switch", map[string]any{"branch": "other"}, &scriptRunner{results: []cmdrunner.RunResult{{ExitCode: 1}}}, protected},
		{"ambiguous revision", "branch-switch", map[string]any{"branch": "other"}, &scriptRunner{results: []cmdrunner.RunResult{{Stdout: []byte("0123456789abcdef0123456789abcdef01234567\nfedcba9876543210fedcba9876543210fedcba98\n")}}}, protected},
		{"non-hex revision", "branch-switch", map[string]any{"branch": "other"}, &scriptRunner{results: []cmdrunner.RunResult{{Stdout: []byte("not-an-object-id")}}}, protected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool := builtinAction(t, "git", tc.action, root, tc.run)
			if !tool.ProtectedStateRisk(context.Background(), tc.args, tc.protected) {
				t.Fatalf("ProtectedStateRisk = false; an unestablished verdict must refuse (queries run: %v)", tc.run.argvs())
			}
		})
	}
}

// A candidate the guard cannot name in a query refuses; one that lies outside the repository at all
// is never reached, because the enumerated set is repository-scoped.
func TestActionTool_ProtectedStateRiskCandidatePathForms(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name      string
		candidate string
	}{
		{"escaping the repo root", filepath.Join(filepath.Dir(root), "outside", "settings.yaml")},
		{"the repo root itself", root},
		{"a quote a fileset cannot express", filepath.Join(root, `set"tings.yaml`)},
		{"a newline an argument list cannot express", filepath.Join(root, "settings\n.yaml")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := &scriptRunner{}
			tool := builtinAction(t, "git", "restore-file", root, run)
			if !tool.ProtectedStateRisk(context.Background(), map[string]any{"path": "x"}, fixedProtected(tc.candidate)) {
				t.Fatal("ProtectedStateRisk = false; a candidate with no safe query form must refuse")
			}
			if len(run.specs) != 0 {
				t.Fatalf("ran %v; an unnameable candidate must refuse before any query", run.argvs())
			}
		})
	}
}

// Every protected candidate is queried, so an alias cannot ride along behind a safe one.
func TestActionTool_ProtectedStateRiskChecksEveryCandidate(t *testing.T) {
	root := t.TempDir()
	const sha = "0123456789abcdef0123456789abcdef01234567"
	run := &scriptRunner{results: []cmdrunner.RunResult{{Stdout: []byte(sha + "\n")}, {}, {ExitCode: 1}}}
	tool := builtinAction(t, "git", "branch-switch", root, run)
	protected := fixedProtected(filepath.Join(root, ".codemeld", "settings.yaml"), filepath.Join(root, "alias.yaml"))

	if !tool.ProtectedStateRisk(context.Background(), map[string]any{"branch": "other"}, protected) {
		t.Fatal("ProtectedStateRisk = false; a hardlink alias behind a safe candidate must refuse")
	}
	if len(run.specs) != 3 {
		t.Fatalf("queries = %v, want a revision resolution plus one query per candidate", run.argvs())
	}
}

// A restore names a path: it is refused for what that path can select, not for the mere presence of
// protected state somewhere else in the repository.
func TestActionTool_ProtectedStateRiskRestorePathScope(t *testing.T) {
	root := t.TempDir()
	settings := filepath.Join(root, ".codemeld", "settings.yaml")
	protected := fixedProtected(settings, filepath.Join(root, "alias.yaml"))
	tracked := cmdrunner.RunResult{}

	cases := []struct {
		name       string
		path       string
		results    []cmdrunner.RunResult
		want       bool
		wantQuerie [][]string
	}{
		{
			name: "an unrelated repository file", path: "README.md", want: false,
		},
		{
			name: "an unrelated file beside the protected directory", path: ".codemeld-notes/todo.md", want: false,
		},
		{
			name: "the protected file itself", path: ".codemeld/settings.yaml",
			results: []cmdrunner.RunResult{tracked}, want: true,
			wantQuerie: [][]string{{"git", "--literal-pathspecs", "ls-files", "--error-unmatch", "--", ".codemeld/settings.yaml"}},
		},
		{
			name: "the same file spelled with a redundant segment", path: "./x/../.codemeld/settings.yaml",
			results: []cmdrunner.RunResult{tracked}, want: true,
			wantQuerie: [][]string{{"git", "--literal-pathspecs", "ls-files", "--error-unmatch", "--", ".codemeld/settings.yaml"}},
		},
		{
			name: "an ancestor directory", path: ".codemeld",
			results: []cmdrunner.RunResult{tracked}, want: true,
			wantQuerie: [][]string{{"git", "--literal-pathspecs", "ls-files", "--error-unmatch", "--", ".codemeld/settings.yaml"}},
		},
		{
			name: "a hardlink alias", path: "alias.yaml",
			results: []cmdrunner.RunResult{tracked}, want: true,
			wantQuerie: [][]string{{"git", "--literal-pathspecs", "ls-files", "--error-unmatch", "--", "alias.yaml"}},
		},
		{
			name: "an absolute path to the protected file", path: settings,
			results: []cmdrunner.RunResult{tracked}, want: true,
			wantQuerie: [][]string{{"git", "--literal-pathspecs", "ls-files", "--error-unmatch", "--", ".codemeld/settings.yaml"}},
		},
		{name: "the whole tree", path: ".", want: true},
		{name: "an empty path", path: "", want: true},
		{name: "a flag-shaped path", path: "--staged", want: true},
		{name: "a wildcard", path: "*.yaml", want: true},
		{name: "a git pathspec magic prefix", path: ":(glob)**/settings.yaml", want: true},
		{name: "a Mercurial pattern prefix", path: "glob:**/settings.yaml", want: true},
		{name: "a Jujutsu fileset expression", path: "all()", want: true},
		{name: "a path escaping the repository", path: "../elsewhere/settings.yaml", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := &scriptRunner{results: tc.results}
			tool := builtinAction(t, "git", "restore-file", root, run)
			if got := tool.ProtectedStateRisk(context.Background(), map[string]any{"path": tc.path}, protected); got != tc.want {
				t.Fatalf("ProtectedStateRisk = %v, want %v (queries run: %v)", got, tc.want, run.argvs())
			}
			if got := run.argvs(); !slices.EqualFunc(got, tc.wantQuerie, slices.Equal) {
				t.Fatalf("queries = %v, want %v", got, tc.wantQuerie)
			}
		})
	}
}

func TestActionTool_ProtectedStateRiskFolderCandidate(t *testing.T) {
	root := t.TempDir()
	protected := fixedProtected(filepath.Join(root, "secrets"))
	cases := []struct {
		vcsName string
		result  cmdrunner.RunResult
		want    []string
	}{
		{"git", cmdrunner.RunResult{}, []string{"git", "--literal-pathspecs", "ls-files", "--error-unmatch", "--", "secrets"}},
		{"hg", cmdrunner.RunResult{}, []string{"hg", "files", "--", "path:secrets"}},
		{"jj", cmdrunner.RunResult{Stdout: []byte("secrets/k\n")}, []string{"jj", "diff", "--from", "@-", "--to", "@", "--name-only", "--", `root:"secrets"`}},
	}
	for _, tc := range cases {
		t.Run(tc.vcsName, func(t *testing.T) {
			run := &scriptRunner{results: []cmdrunner.RunResult{tc.result}}
			tool := builtinAction(t, tc.vcsName, "restore-file", root, run)
			if !tool.ProtectedStateRisk(context.Background(), map[string]any{"path": "secrets/k"}, protected) {
				t.Fatalf("ProtectedStateRisk = false for a file inside the protected folder (queries run: %v)", run.argvs())
			}
			if got := run.argvs(); !slices.EqualFunc(got, [][]string{tc.want}, slices.Equal) {
				t.Fatalf("queries = %v, want %v", got, [][]string{tc.want})
			}
			sibling := &scriptRunner{}
			if builtinAction(t, tc.vcsName, "restore-file", root, sibling).ProtectedStateRisk(context.Background(), map[string]any{"path": "secrets-old/k"}, protected) {
				t.Fatalf("ProtectedStateRisk = true for a sibling sharing the folder's prefix (queries run: %v)", sibling.argvs())
			}
		})
	}
}

// A restore reaching the protected file through a symlinked directory is the same restore.
func TestActionTool_ProtectedStateRiskRestoreThroughSymlink(t *testing.T) {
	root := t.TempDir()
	settings := writeSettings(t, root, "permissions: []\n")
	if err := os.Symlink(filepath.Join(root, ".codemeld"), filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	run := &scriptRunner{results: []cmdrunner.RunResult{{}}}
	tool := builtinAction(t, "git", "restore-file", root, run)

	if !tool.ProtectedStateRisk(context.Background(), map[string]any{"path": "link/settings.yaml"}, fixedProtected(settings)) {
		t.Fatal("ProtectedStateRisk = false; a restore through a symlinked directory reaches the protected file")
	}
}

// A path made only of whitespace is a filename, so an output query that names it has named a
// protected alias — trimming that record away would report the action as safe.
func TestActionTool_ProtectedStateRiskWhitespaceOutputRecord(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name   string
		stdout []byte
	}{
		{"a whitespace-named alias", []byte(" \n")},
		{"a blank record", []byte("\n")},
		{"a record escaping the repository", []byte("../elsewhere/settings.yaml\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := &scriptRunner{results: []cmdrunner.RunResult{{Stdout: tc.stdout}}}
			tool := builtinAction(t, "jj", "restore-file", root, run)
			if !tool.ProtectedStateRisk(context.Background(), map[string]any{"path": " "}, fixedProtected(filepath.Join(root, " "))) {
				t.Fatalf("ProtectedStateRisk = false for output %q; a named record must refuse", tc.stdout)
			}
		})
	}
}

func runIn(t *testing.T, dir string, argv ...string) {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v in %s: %v\n%s", argv, dir, err, out)
	}
}

func writeSettings(t *testing.T, root, content string) string {
	t.Helper()
	path := filepath.Join(root, ".codemeld", "settings.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available: %v", name, err)
	}
}

func terminalRisk(t *testing.T, vcsName, action, root string, args map[string]any, protected func(string) ([]string, error)) bool {
	t.Helper()
	return builtinAction(t, vcsName, action, root, cmdrunner.DirectExecRunner{}).ProtectedStateRisk(context.Background(), args, protected)
}

// The real git binary decides every verdict here: nothing is stubbed below ProtectedStateRisk.
func TestActionTool_ProtectedStateRiskGitTerminal(t *testing.T) {
	requireBinary(t, "git")
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", filepath.Join(t.TempDir(), "gitsystem"))
	t.Setenv("GIT_AUTHOR_NAME", "codemeld")
	t.Setenv("GIT_AUTHOR_EMAIL", "codemeld@example.test")
	t.Setenv("GIT_COMMITTER_NAME", "codemeld")
	t.Setenv("GIT_COMMITTER_EMAIL", "codemeld@example.test")
	runIn(t, root, "git", "init", "-b", "main")
	settings := writeSettings(t, root, "permissions: []\n")
	approved, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	runIn(t, root, "git", "add", ".")
	runIn(t, root, "git", "commit", "-m", "base")
	runIn(t, root, "git", "branch", "other")
	protected := fixedProtected(settings)

	if terminalRisk(t, "git", "branch-switch", root, map[string]any{"branch": "other"}, protected) {
		t.Fatal("branch switch to an identical branch was refused")
	}
	if terminalRisk(t, "git", "restore-file", root, map[string]any{"path": "README.md"}, protected) {
		t.Fatal("restore of an unrelated file was refused; a tracked settings file is not that file")
	}
	if !terminalRisk(t, "git", "restore-file", root, map[string]any{"path": ".codemeld/settings.yaml"}, protected) {
		t.Fatal("restore of the protected settings file was allowed")
	}
	if !terminalRisk(t, "git", "restore-file", root, map[string]any{"path": "."}, protected) {
		t.Fatal("whole-tree restore was allowed")
	}
	if terminalRisk(t, "git", "stash", root, nil, protected) {
		t.Fatal("stash of a clean working tree was refused")
	}
	if terminalRisk(t, "git", "stash-pop", root, nil, protected) {
		t.Fatal("stash pop with nothing stashed was refused")
	}
	for _, action := range []string{"add", "commit", "branch-create", "status", "diff"} {
		args := map[string]any{"path": ".codemeld/settings.yaml", "message": "m", "branch": "third"}
		if terminalRisk(t, "git", action, root, args, protected) {
			t.Fatalf("%s was refused; it cannot rewrite a checked-out file", action)
		}
	}

	writeSettings(t, root, "permissions: [\"grant\"]\n")
	if !terminalRisk(t, "git", "stash", root, nil, protected) {
		t.Fatal("stash was allowed while the protected settings file has uncommitted changes")
	}
	runIn(t, root, "git", "stash", "push")
	if !terminalRisk(t, "git", "stash-pop", root, nil, protected) {
		t.Fatal("stash pop was allowed while the stash carries a settings change")
	}
	runIn(t, root, "git", "stash", "drop")
	runIn(t, root, "git", "checkout", "other")
	writeSettings(t, root, "permissions: [\"other-branch\"]\n")
	runIn(t, root, "git", "commit", "-am", "diverge")
	runIn(t, root, "git", "checkout", "main")
	if !terminalRisk(t, "git", "branch-switch", root, map[string]any{"branch": "other"}, protected) {
		t.Fatal("branch switch to a branch holding different settings bytes was allowed")
	}
	current, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(current, approved) {
		t.Fatalf("settings bytes = %q, want the approved %q — a query rewrote the file", current, approved)
	}

	selector := filepath.Join(root, ":(literal)secret")
	if err := os.WriteFile(selector, []byte("key\n"), 0o600); err != nil {
		t.Skipf("filename unsupported: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret"), []byte("plain\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	runIn(t, root, "git", "add", "-A")
	runIn(t, root, "git", "commit", "-m", "selector names")
	runIn(t, root, "git", "checkout", "-b", "rotated")
	if err := os.WriteFile(selector, []byte("rotated\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	runIn(t, root, "git", "commit", "-am", "rotate")
	runIn(t, root, "git", "checkout", "main")
	if !terminalRisk(t, "git", "branch-switch", root, map[string]any{"branch": "rotated"}, fixedProtected(selector)) {
		t.Fatal("branch switch to a branch holding different bytes under a pathspec-magic filename was allowed")
	}
	if terminalRisk(t, "git", "branch-switch", root, map[string]any{"branch": "rotated"}, fixedProtected(filepath.Join(root, "secret"))) {
		t.Fatal("branch switch was refused for the file the pathspec-magic filename would otherwise select")
	}
}

func TestActionTool_ProtectedStateRiskHgTerminal(t *testing.T) {
	requireBinary(t, "hg")
	root := t.TempDir()
	t.Setenv("HGRCPATH", filepath.Join(t.TempDir(), "hgrc"))
	t.Setenv("HGUSER", "codemeld <codemeld@example.test>")
	runIn(t, root, "hg", "init")
	settings := writeSettings(t, root, "permissions: []\n")
	protected := fixedProtected(settings)

	if terminalRisk(t, "hg", "restore-file", root, map[string]any{"path": ".codemeld/settings.yaml"}, protected) {
		t.Fatal("revert was refused while the settings file is untracked")
	}
	runIn(t, root, "hg", "add", ".codemeld/settings.yaml")
	runIn(t, root, "hg", "commit", "-m", "base")
	if !terminalRisk(t, "hg", "restore-file", root, map[string]any{"path": ".codemeld/settings.yaml"}, protected) {
		t.Fatal("revert was allowed while the protected settings file is tracked")
	}
	if terminalRisk(t, "hg", "restore-file", root, map[string]any{"path": "README.md"}, protected) {
		t.Fatal("revert of an unrelated file was refused; a tracked settings file is not that file")
	}
	if !terminalRisk(t, "hg", "restore-file", root, map[string]any{"path": "glob:**"}, protected) {
		t.Fatal("revert of a Mercurial pattern was allowed")
	}
	if terminalRisk(t, "hg", "stash", root, nil, protected) {
		t.Fatal("shelve of a clean working directory was refused")
	}
	if !terminalRisk(t, "hg", "stash-pop", root, nil, protected) {
		t.Fatal("unshelve was allowed; Mercurial offers no lossless affected-path query for it")
	}
	if terminalRisk(t, "hg", "branch-switch", root, map[string]any{"branch": "0"}, protected) {
		t.Fatal("update to the revision already checked out was refused")
	}
	writeSettings(t, root, "permissions: [\"grant\"]\n")
	runIn(t, root, "hg", "commit", "-m", "diverge")
	if !terminalRisk(t, "hg", "branch-switch", root, map[string]any{"branch": "0"}, protected) {
		t.Fatal("update to a revision holding different settings bytes was allowed")
	}
	writeSettings(t, root, "permissions: [\"uncommitted\"]\n")
	if !terminalRisk(t, "hg", "stash", root, nil, protected) {
		t.Fatal("shelve was allowed while the protected settings file has uncommitted changes")
	}
	for _, action := range []string{"add", "commit", "status", "diff"} {
		args := map[string]any{"path": ".codemeld/settings.yaml", "message": "m"}
		if terminalRisk(t, "hg", action, root, args, protected) {
			t.Fatalf("%s was refused; it cannot rewrite a checked-out file", action)
		}
	}

	selector := filepath.Join(root, "path:secret")
	if err := os.WriteFile(selector, []byte("key\n"), 0o600); err != nil {
		t.Skipf("filename unsupported: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret"), []byte("plain\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	runIn(t, root, "hg", "add")
	runIn(t, root, "hg", "commit", "-m", "selector names")
	if err := os.WriteFile(selector, []byte("rotated\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	runIn(t, root, "hg", "commit", "-m", "rotate")
	if !terminalRisk(t, "hg", "branch-switch", root, map[string]any{"branch": "2"}, fixedProtected(selector)) {
		t.Fatal("update to a revision holding different bytes under a pattern-prefixed filename was allowed")
	}
	if terminalRisk(t, "hg", "branch-switch", root, map[string]any{"branch": "2"}, fixedProtected(filepath.Join(root, "secret"))) {
		t.Fatal("update was refused for the file the pattern-prefixed filename would otherwise select")
	}
}

func TestActionTool_ProtectedStateRiskJJTerminal(t *testing.T) {
	requireBinary(t, "jj")
	requireBinary(t, "git")
	root := t.TempDir()
	config := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(config, []byte("[user]\nname = \"codemeld\"\nemail = \"codemeld@example.test\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("JJ_CONFIG", config)
	runIn(t, root, "jj", "git", "init")
	settings := writeSettings(t, root, "permissions: []\n")
	protected := fixedProtected(settings)

	if !terminalRisk(t, "jj", "restore-file", root, map[string]any{"path": ".codemeld/settings.yaml"}, protected) {
		t.Fatal("restore was allowed while the working-copy commit holds a settings change")
	}
	if terminalRisk(t, "jj", "restore-file", root, map[string]any{"path": "README.md"}, protected) {
		t.Fatal("restore of an unrelated file was refused; the settings change is not that file")
	}
	runIn(t, root, "jj", "bookmark", "create", "base", "-r", "@")
	runIn(t, root, "jj", "new")
	if terminalRisk(t, "jj", "restore-file", root, map[string]any{"path": ".codemeld/settings.yaml"}, protected) {
		t.Fatal("restore was refused while the working-copy commit changes nothing")
	}
	if terminalRisk(t, "jj", "branch-switch", root, map[string]any{"branch": "base"}, protected) {
		t.Fatal("edit of a revision holding identical settings bytes was refused")
	}
	for _, action := range []string{"stash", "stash-pop", "add", "commit", "status", "diff"} {
		args := map[string]any{"path": ".codemeld/settings.yaml", "message": "m"}
		if terminalRisk(t, "jj", action, root, args, protected) {
			t.Fatalf("%s was refused; it cannot rewrite a checked-out file", action)
		}
	}
	writeSettings(t, root, "permissions: [\"grant\"]\n")
	if !terminalRisk(t, "jj", "branch-switch", root, map[string]any{"branch": "base"}, protected) {
		t.Fatal("edit of a revision holding different settings bytes was allowed")
	}
	if !terminalRisk(t, "jj", "restore-file", root, map[string]any{"path": ".codemeld"}, protected) {
		t.Fatal("restore of the enclosing directory was allowed while the working copy holds a settings change")
	}
	if !terminalRisk(t, "jj", "restore-file", root, map[string]any{"path": "all()"}, protected) {
		t.Fatal("restore of a Jujutsu fileset expression was allowed")
	}
	secrets := filepath.Join(root, "secrets")
	if err := os.MkdirAll(secrets, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "k"), []byte("key\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !terminalRisk(t, "jj", "restore-file", root, map[string]any{"path": "secrets/k"}, fixedProtected(secrets)) {
		t.Fatal("restore of a file inside a protected folder was allowed while the working copy holds a change under it")
	}
}
