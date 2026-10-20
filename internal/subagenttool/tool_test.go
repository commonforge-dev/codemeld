package subagenttool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/ssestream"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/subagent"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/internal/vcs"
)

func contentChunk(text string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":%q},"finish_reason":""}]}`, text))
}

func finishChunk() []byte {
	return []byte(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`)
}

func toolCallChunk(id, name string) []byte { return indexedToolCallChunk(0, id, name) }

func toolCallChunkWithArgs(id, name, arguments string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":%q,"arguments":%q}}]},"finish_reason":"tool_calls"}]}`, id, name, arguments))
}

// Byte-identical consecutive calls would trip the turn's repeat check before the step cap.
func alternatingEmptyArgs(i int) string {
	if i%2 == 0 {
		return "{}"
	}
	return "{ }"
}

// The tool_calls index is what the stream assembler keys a call on, so a round carrying more
// than one call must number them; reusing index 0 would collapse them into a single call.
func indexedToolCallChunk(index int, id, name string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":%d,"id":%q,"type":"function","function":{"name":%q,"arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`, index, id, name))
}

type sliceDecoder struct {
	events [][]byte
	i      int
	cur    ssestream.Event
}

func (d *sliceDecoder) Next() bool {
	if d.i >= len(d.events) {
		return false
	}
	d.cur = ssestream.Event{Data: d.events[d.i]}
	d.i++
	return true
}
func (d *sliceDecoder) Event() ssestream.Event { return d.cur }
func (d *sliceDecoder) Close() error           { return nil }
func (d *sliceDecoder) Err() error             { return nil }

func streamRound(chunks ...[]byte) func() (provider.Response, error) {
	return func() (provider.Response, error) {
		dec := &sliceDecoder{events: chunks}
		return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
	}
}

type scriptedClient struct {
	rounds   []func() (provider.Response, error)
	requests []provider.Request
}

func (c *scriptedClient) ChatCompletion(_ context.Context, req provider.Request) (provider.Response, error) {
	c.requests = append(c.requests, req)
	if i := len(c.requests) - 1; i < len(c.rounds) {
		return c.rounds[i]()
	}
	return streamRound(contentChunk("done"), finishChunk())()
}

// stubDispatcher stands in for the parent's production dispatcher — the one the child really
// runs on. planned/dispatched record what reached it, so a test can assert a confined-away
// name never arrives rather than only that it was left unadvertised.
type stubDispatcher struct {
	planned    []string
	dispatched []string
}

func (d *stubDispatcher) Plan(calls []turn.AssembledToolCall, _ int) turn.ToolPlan {
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	for i, call := range calls {
		d.planned = append(d.planned, call.Name)
		plan.Units[i] = turn.PlannedToolCall{
			Call: call,
			Run:  func(ctx context.Context) (turn.ToolResult, error) { return d.Dispatch(ctx, call) },
		}
	}
	return plan
}

func (d *stubDispatcher) Dispatch(_ context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	d.dispatched = append(d.dispatched, call.Name)
	return turn.ToolResult{Content: "ok"}, nil
}

const parentPrompt = "you are the parent\n<environment>cwd=/repo</environment>"

// parentToolSurface is deliberately wider than the child's pinned set, so a filter that
// forwarded the parent's advertised tools unchanged would fail the pinned-set test. extra
// stands in for the registry-derived names a real parent advertises beside the fixed ones.
func parentToolSurface(extra ...string) []provider.ToolDefinition {
	names := []string{
		"ask_user", "bash", "create", ToolName, "delete", "edit", "file_count", "glob",
		"grep", "list", "mkdir", "move", "read", "read_image", "suggest_followup", "tree",
		"web_fetch", "web_search",
	}
	names = append(names, extra...)
	slices.Sort(names)
	names = slices.Compact(names)
	defs := make([]provider.ToolDefinition, 0, len(names))
	for _, n := range names {
		defs = append(defs, provider.ToolDefinition{Name: n, Description: n})
	}
	return defs
}

func registeredNames(registered []tools.Tool) []string {
	out := make([]string, 0, len(registered))
	for _, t := range registered {
		out = append(out, t.Name())
	}
	return out
}

type harness struct {
	deps        Deps
	dir         string
	client      *scriptedClient
	snapshotted int
	modeCtxs    []permissions.ModeContext
	dispatcher  *stubDispatcher
	dispatchers []*stubDispatcher
	snapshotOK  bool
	registered  []tools.Tool
	// override replaces the stub dispatcher so a test can run the child on the real structured
	// file tools and observe what the journal does with their writes.
	override    func(permissions.ModeContext) turn.ToolDispatcher
	sessionPath string
	session     *sessions.Session
	store       *sessions.Store
	storeCalls  int
	// storeAt is nil for a wired store; a test that needs an append failure returns nil for a
	// chosen call index instead.
	storeAt func(call int) *sessions.Store
}

func newHarness(t *testing.T, rounds ...func() (provider.Response, error)) *harness {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	h := &harness{dir: dir, client: &scriptedClient{rounds: rounds}, snapshotOK: true}
	h.sessionPath = filepath.Join(t.TempDir(), "session.json")
	h.session = &sessions.Session{Metadata: sessions.Metadata{
		ID:            "01890000-0000-7000-8000-000000000001",
		Folder:        dir,
		StartedAt:     sessionStart,
		UpdatedAt:     sessionStart,
		SchemaVersion: sessions.CurrentSchemaVersion,
	}}
	h.store = sessions.New(h.sessionPath, h.session)
	h.deps = Deps{
		Home:        t.TempDir(),
		LaunchDir:   dir,
		ProjectRoot: dir,
		Store: func() *sessions.Store {
			h.storeCalls++
			if h.storeAt != nil {
				return h.storeAt(h.storeCalls)
			}
			return h.store
		},
		Snapshot: func() (Snapshot, bool) {
			h.snapshotted++
			if !h.snapshotOK {
				return Snapshot{}, false
			}
			return Snapshot{
				Mode:            "auto_edits",
				Model:           model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: "high"},
				ModelSource:     model.SourceProject,
				SupportedEffort: func(string, string) []string { return []string{"high"} },
				SystemPrompt:    parentPrompt,
				Client:          h.client,
				Tools:           parentToolSurface(registeredNames(h.registered)...),
				Registered:      h.registered,
			}, true
		},
		NewDispatcher: func(mc permissions.ModeContext) turn.ToolDispatcher {
			h.modeCtxs = append(h.modeCtxs, mc)
			if h.override != nil {
				return h.override(mc)
			}
			h.dispatcher = &stubDispatcher{}
			h.dispatchers = append(h.dispatchers, h.dispatcher)
			return h.dispatcher
		},
	}
	return h
}

func (h *harness) tool() *Tool { return New(h.deps) }

var sessionStart = time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC)

// childRecords reads the child lifecycle records back out of the flushed session file rather
// than the store's memory, so a test sees what a later reader of the session would.
func (h *harness) childRecords(t *testing.T) (starts []events.ChildAgentStart, ends []events.ChildAgentEnd, raw []byte) {
	t.Helper()
	if _, _, err := h.store.Flush(context.Background()); err != nil {
		t.Fatalf("Store.Flush() error = %v", err)
	}
	raw, err := os.ReadFile(h.sessionPath)
	if err != nil {
		t.Fatalf("session file not written: %v", err)
	}
	loaded, err := sessions.Unmarshal(raw)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	for _, rec := range loaded.Records {
		ev, ok := rec.(sessions.Event)
		if !ok {
			continue
		}
		switch ev.Kind {
		case events.KindChildAgentStart:
			var p events.ChildAgentStart
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatalf("unmarshal child_agent_start: %v", err)
			}
			starts = append(starts, p)
		case events.KindChildAgentEnd:
			var p events.ChildAgentEnd
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatalf("unmarshal child_agent_end: %v", err)
			}
			ends = append(ends, p)
		}
	}
	return starts, ends, raw
}

// onePair asserts the session holds exactly one start and one end sharing an invocation id.
func (h *harness) onePair(t *testing.T) (events.ChildAgentStart, events.ChildAgentEnd, []byte) {
	t.Helper()
	starts, ends, raw := h.childRecords(t)
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("persisted records = %d start / %d end, want exactly one of each", len(starts), len(ends))
	}
	if starts[0].InvocationID != ends[0].InvocationID {
		t.Fatalf("end invocation_id = %q, want the start's %q", ends[0].InvocationID, starts[0].InvocationID)
	}
	return starts[0], ends[0], raw
}

func callArgs(instruction string, files ...string) map[string]any {
	list := make([]any, 0, len(files))
	for _, f := range files {
		list = append(list, f)
	}
	return map[string]any{instructionsArg: instruction, filesArg: list}
}

func declareArgs(instruction string, write, remove []string) map[string]any {
	args := map[string]any{instructionsArg: instruction}
	if write != nil {
		args[filesArg] = anyList(write)
	}
	if remove != nil {
		args[filesDeleteArg] = anyList(remove)
	}
	return args
}

func mkdirDeclareArgs(instruction string, write []string, dirs ...any) map[string]any {
	args := declareArgs(instruction, write, nil)
	args[filesMkdirArg] = append([]any{}, dirs...)
	return args
}

func anyList(paths []string) []any {
	list := make([]any, 0, len(paths))
	for _, p := range paths {
		list = append(list, p)
	}
	return list
}

func TestDelegate_AdvertiseMetadata(t *testing.T) {
	tool := newHarness(t).tool()

	if tool.Name() != "delegate" {
		t.Fatalf("Name() = %q, want delegate", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = true, want false (starting a child agent mutates)")
	}
	if md.Noncredential {
		t.Fatal("Advertise().Noncredential = true, want false so delegate never joins a concurrent read batch")
	}
	if !strings.Contains(md.Description, "no shell") {
		t.Fatalf("Description = %q, want it to state that no shell interprets the instructions", md.Description)
	}
	if md.Parameters["type"] != "object" {
		t.Fatalf("Parameters.type = %v, want object", md.Parameters["type"])
	}
	if md.Parameters["additionalProperties"] != false {
		t.Fatalf("Parameters.additionalProperties = %v, want false", md.Parameters["additionalProperties"])
	}
	required, ok := md.Parameters["required"].([]string)
	if !ok || !reflect.DeepEqual(required, []string{"instructions"}) {
		t.Fatalf("Parameters.required = %v, want [instructions] — files, files_delete, files_move and files_mkdir are each optional", md.Parameters["required"])
	}
	props, ok := md.Parameters["properties"].(map[string]any)
	if !ok || len(props) != 5 {
		t.Fatalf("Parameters.properties = %v, want exactly instructions, files, files_delete, files_move and files_mkdir", md.Parameters["properties"])
	}
	for name := range props {
		if _, accepted := allowedArgs[name]; !accepted {
			t.Fatalf("advertised property %q is not an accepted argument", name)
		}
	}
	if len(allowedArgs) != len(props) {
		t.Fatalf("accepted arguments %v differ from the advertised properties %v", allowedArgs, props)
	}
	rule := "At least one of files, files_delete, files_move, or files_mkdir must name a path"
	if !strings.Contains(md.Description, rule) {
		t.Fatalf("Description = %q, want it to state the four-form rule %q", md.Description, rule)
	}
	if !strings.Contains(md.Description, "create only the exact directories listed in files_mkdir, which grant nothing inside them") {
		t.Fatalf("Description = %q, want it to state that files_mkdir grants exact directory creation only", md.Description)
	}
	for name, others := range map[string]string{
		"files":        "files_delete, files_move, or files_mkdir",
		"files_delete": "files, files_move, or files_mkdir",
		"files_move":   "files, files_delete, or files_mkdir",
		"files_mkdir":  "files, files_delete, or files_move",
	} {
		form, _ := props[name].(map[string]any)
		if desc, _ := form["description"].(string); !strings.Contains(desc, "Optional when "+others+" names a path.") {
			t.Fatalf("%s description = %q, want it optional when %s names a path", name, desc, others)
		}
	}
	mkdirs, _ := props["files_mkdir"].(map[string]any)
	if desc, _ := mkdirs["description"].(string); !strings.Contains(desc, "A listed directory authorizes nothing inside it") {
		t.Fatalf("files_mkdir description = %q, want it to say a listed directory grants nothing inside it", desc)
	}
	moves, ok := props["files_move"].(map[string]any)
	if !ok || moves["type"] != "array" {
		t.Fatalf("files_move property = %v, want an array", props["files_move"])
	}
	pair, ok := moves["items"].(map[string]any)
	if !ok || pair["type"] != "object" || pair["additionalProperties"] != false || !reflect.DeepEqual(pair["required"], []string{"source", "destination"}) {
		t.Fatalf("files_move.items = %v, want a closed object requiring source and destination", moves["items"])
	}
	instructions, ok := props["instructions"].(map[string]any)
	if !ok || instructions["type"] != "string" {
		t.Fatalf("instructions property = %v, want a string", props["instructions"])
	}
	for _, name := range []string{"files", "files_delete", "files_mkdir"} {
		list, ok := props[name].(map[string]any)
		if !ok || list["type"] != "array" {
			t.Fatalf("%s property = %v, want an array", name, props[name])
		}
		items, ok := list["items"].(map[string]any)
		if !ok || items["type"] != "string" {
			t.Fatalf("%s.items = %v, want string items", name, list["items"])
		}
	}
}

// TestDelegate_RefusesMalformedCallsBeforeAnyChildTurn proves every argument fault is
// decided before the child exists: no snapshot is taken, so no provider request is issued.
func TestDelegate_RefusesMalformedCallsBeforeAnyChildTurn(t *testing.T) {
	dir := func(t *testing.T) string {
		t.Helper()
		d, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		return d
	}

	cases := []struct {
		name string
		args func(root string) map[string]any
		seed func(t *testing.T, root string)
		want string
	}{
		{name: "empty instruction", args: func(string) map[string]any { return callArgs("", "a.txt") }, want: "must not be empty"},
		{name: "whitespace instruction", args: func(string) map[string]any { return callArgs("  \n\t ", "a.txt") }, want: "must not be empty"},
		{name: "missing instruction", args: func(string) map[string]any {
			return map[string]any{filesArg: []any{"a.txt"}}
		}, want: `missing required argument "instructions"`},
		{name: "non-string instruction", args: func(string) map[string]any {
			return map[string]any{instructionsArg: 7, filesArg: []any{"a.txt"}}
		}, want: `argument "instructions" must be a string`},
		{name: "unknown argument key", args: func(string) map[string]any {
			args := callArgs("do it", "a.txt")
			args["model"] = "sonnet"
			return args
		}, want: `unexpected argument "model"; only instructions, files, files_delete, files_move and files_mkdir are accepted`},
		{name: "files_mkdir not an array", args: func(string) map[string]any {
			args := callArgs("do it", "a.txt")
			args[filesMkdirArg] = "made"
			return args
		}, want: `argument "files_mkdir" must be an array of strings`},
		{name: "non-string files_mkdir entry", args: func(string) map[string]any {
			return mkdirDeclareArgs("do it", []string{"a.txt"}, "made", 3)
		}, want: `argument "files_mkdir"[1] must be a string`},
		{name: "empty files_mkdir entry", args: func(string) map[string]any {
			return mkdirDeclareArgs("do it", []string{"a.txt"}, "")
		}, want: `argument "files_mkdir"[0] must not be empty`},
		{name: "whitespace-only files_mkdir entry", args: func(string) map[string]any {
			return mkdirDeclareArgs("do it", []string{"a.txt"}, "made", " \t")
		}, want: `argument "files_mkdir"[1] must not be empty`},
		{name: "~user files_mkdir entry", args: func(string) map[string]any {
			return mkdirDeclareArgs("do it", []string{"a.txt"}, "~root/made")
		}, want: "unsupported ~user path form"},
		{name: "files_mkdir naming the project root as .", args: func(string) map[string]any {
			return mkdirDeclareArgs("do it", []string{"a.txt"}, ".")
		}, want: "not inside the project below its root"},
		{name: "files_mkdir naming the absolute project root", args: func(root string) map[string]any {
			return mkdirDeclareArgs("do it", []string{"a.txt"}, root+"/")
		}, want: "not inside the project below its root"},
		{name: "files_mkdir naming the project root through traversal", args: func(string) map[string]any {
			return mkdirDeclareArgs("do it", []string{"a.txt"}, "made/..")
		}, want: "not inside the project below its root"},
		{
			name: "files_mkdir naming the project root through a symlink alias",
			seed: func(t *testing.T, root string) {
				if err := os.Symlink(root, filepath.Join(root, "self")); err != nil {
					t.Fatalf("seed symlink: %v", err)
				}
			},
			args: func(string) map[string]any { return mkdirDeclareArgs("do it", []string{"a.txt"}, "self") },
			want: "not inside the project below its root",
		},
		{name: "relative files_mkdir entry outside the project", args: func(string) map[string]any {
			return mkdirDeclareArgs("do it", []string{"a.txt"}, "../escape")
		}, want: "not inside the project below its root"},
		{name: "absolute files_mkdir entry outside the project", args: func(root string) map[string]any {
			return mkdirDeclareArgs("do it", []string{"a.txt"}, filepath.Join(filepath.Dir(root), "escape"))
		}, want: "not inside the project below its root"},
		{name: "home-relative files_mkdir entry outside the project", args: func(string) map[string]any {
			return mkdirDeclareArgs("do it", []string{"a.txt"}, "~/made")
		}, want: "not inside the project below its root"},
		{
			name: "files_mkdir entry escaping through an in-project symlink",
			seed: func(t *testing.T, root string) {
				if err := os.Symlink(t.TempDir(), filepath.Join(root, "outlink")); err != nil {
					t.Fatalf("seed symlink: %v", err)
				}
			},
			args: func(string) map[string]any { return mkdirDeclareArgs("do it", []string{"a.txt"}, "outlink/made") },
			want: "not inside the project below its root",
		},
		{
			name: "unresolvable files_mkdir entry",
			seed: func(t *testing.T, root string) {
				if err := os.WriteFile(filepath.Join(root, "blocker"), []byte("x"), 0o644); err != nil {
					t.Fatalf("seed blocker: %v", err)
				}
			},
			args: func(string) map[string]any { return mkdirDeclareArgs("do it", []string{"a.txt"}, "blocker/made") },
			want: "an existing path component is not a directory",
		},
		{name: "an escaping files_mkdir entry refuses valid files and files_delete lists with it", args: func(string) map[string]any {
			args := mkdirDeclareArgs("do it", []string{"a.txt"}, "made", "../escape")
			args[filesDeleteArg] = []any{"b.txt"}
			return args
		}, want: `argument "files_mkdir"[1]`},
		{name: "no path in any of the four forms", args: func(string) map[string]any {
			return mkdirDeclareArgs("do it", []string{})
		}, want: `arguments "files", "files_delete", "files_move" and "files_mkdir" must name at least one path between them`},
		{name: "missing both path lists", args: func(string) map[string]any {
			return map[string]any{instructionsArg: "do it"}
		}, want: "at least one path"},
		{name: "empty files and files_delete arrays", args: func(string) map[string]any {
			return declareArgs("do it", []string{}, []string{})
		}, want: "at least one path"},
		{name: "files_delete not an array", args: func(string) map[string]any {
			return map[string]any{instructionsArg: "do it", filesDeleteArg: "a.txt"}
		}, want: `argument "files_delete" must be an array of strings`},
		{name: "non-string files_delete entry", args: func(string) map[string]any {
			return map[string]any{instructionsArg: "do it", filesDeleteArg: []any{"a.txt", 3}}
		}, want: `argument "files_delete"[1] must be a string`},
		{name: "empty files_delete entry", args: func(string) map[string]any {
			return declareArgs("do it", nil, []string{" \t"})
		}, want: `argument "files_delete"[0] must not be empty`},
		{name: "~user files_delete entry", args: func(string) map[string]any {
			return declareArgs("do it", nil, []string{"~root/a.txt"})
		}, want: "unsupported ~user form"},
		{name: "relative files_delete entry outside the project", args: func(string) map[string]any {
			return declareArgs("do it", nil, []string{"../escape.txt"})
		}, want: "outside the project"},
		{name: "absolute files_delete entry outside the project", args: func(root string) map[string]any {
			return declareArgs("do it", nil, []string{filepath.Join(filepath.Dir(root), "escape.txt")})
		}, want: "outside the project"},
		{name: "home-relative files_delete entry outside the project", args: func(string) map[string]any {
			return declareArgs("do it", nil, []string{"~/secrets.txt"})
		}, want: "outside the project"},
		{name: "an escaping files_delete entry refuses a valid files list with it", args: func(string) map[string]any {
			return declareArgs("do it", []string{"a.txt"}, []string{"../escape.txt"})
		}, want: "outside the project"},
		{
			name: "unresolvable files_delete entry",
			seed: func(t *testing.T, root string) {
				if err := os.WriteFile(filepath.Join(root, "blocker"), []byte("x"), 0o644); err != nil {
					t.Fatalf("seed blocker: %v", err)
				}
			},
			args: func(string) map[string]any { return declareArgs("do it", nil, []string{"blocker/child.txt"}) },
			want: `declared path "blocker/child.txt"`,
		},
		{name: "files not an array", args: func(string) map[string]any {
			return map[string]any{instructionsArg: "do it", filesArg: "a.txt"}
		}, want: `argument "files" must be an array of strings`},
		{name: "non-string file entry", args: func(string) map[string]any {
			return map[string]any{instructionsArg: "do it", filesArg: []any{"a.txt", 3}}
		}, want: `argument "files"[1] must be a string`},
		{name: "empty files array", args: func(string) map[string]any { return callArgs("do it") }, want: "at least one path"},
		{name: "empty file entry", args: func(string) map[string]any { return callArgs("do it", "  ") }, want: `argument "files"[0] must not be empty`},
		{name: "absolute file entry", args: func(string) map[string]any { return callArgs("do it", "/etc/passwd") }, want: "must be relative"},
		{name: "home-relative file entry", args: func(string) map[string]any { return callArgs("do it", "~/secrets.txt") }, want: "must not be home-relative"},
		{name: "out-of-project file entry", args: func(string) map[string]any { return callArgs("do it", "../escape.txt") }, want: "outside the project"},
		{
			name: "unresolvable file entry",
			seed: func(t *testing.T, root string) {
				if err := os.WriteFile(filepath.Join(root, "blocker"), []byte("x"), 0o644); err != nil {
					t.Fatalf("seed blocker: %v", err)
				}
			},
			args: func(string) map[string]any { return callArgs("do it", "blocker/child.txt") },
			want: "an existing path component is not a directory",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := dir(t)
			if tc.seed != nil {
				tc.seed(t, root)
			}
			h := newHarness(t)
			h.deps.LaunchDir, h.deps.ProjectRoot = root, root

			res, err := h.tool().Invoke(t.Context(), tc.args(root))
			if err != nil {
				t.Fatalf("Invoke error = %v, want nil (a bad call surfaces in-band)", err)
			}
			if res.ExitCode == 0 {
				t.Fatalf("ExitCode = 0, want non-zero; stdout=%q", res.Stdout)
			}
			if !strings.Contains(string(res.Stderr), tc.want) {
				t.Fatalf("stderr = %q, want it to contain %q", res.Stderr, tc.want)
			}
			if h.snapshotted != 0 {
				t.Fatalf("parent state snapshotted %d times, want 0 — the child must not start", h.snapshotted)
			}
			if len(h.client.requests) != 0 {
				t.Fatalf("provider requests = %d, want 0 before any validated call", len(h.client.requests))
			}
		})
	}
}

// TestDelegate_InstructionReachesTheChildByteIdentical pins the reason delegate takes
// structured arguments: shell metacharacters survive because no shell is in the path.
func TestDelegate_PrepareCanonicalizesWithoutStartingAChild(t *testing.T) {
	h := newHarness(t)

	instruction, declared, remove, _, _, targets, err := h.tool().PrepareDelegate(callArgs("do it", "a.txt", "dir/sub/b.txt"))
	if err != nil {
		t.Fatalf("PrepareDelegate error = %v, want nil", err)
	}
	if remove != nil {
		t.Fatalf("prepared delete declaration = %#v, want nil for an omitted files_delete", remove)
	}
	if instruction != "do it" {
		t.Fatalf("prepared instruction = %q, want the tool argument", instruction)
	}
	want := map[string]bool{
		filepath.Join(h.dir, "a.txt"):               true,
		filepath.Join(h.dir, "dir", "sub", "b.txt"): true,
	}
	if !reflect.DeepEqual(declared, want) {
		t.Fatalf("prepared declaration = %v, want the canonical launch-dir-anchored targets %v", declared, want)
	}
	wantTargets := []string{
		filepath.Join(h.dir, "a.txt"),
		filepath.Join(h.dir, "dir"),
		filepath.Join(h.dir, "dir", "sub"),
		filepath.Join(h.dir, "dir", "sub", "b.txt"),
	}
	if !slices.Equal(targets, wantTargets) {
		t.Fatalf("scheduler targets = %v, want the leaves plus every missing create parent %v", targets, wantTargets)
	}
	if h.snapshotted != 0 || len(h.modeCtxs) != 0 {
		t.Fatalf("snapshots = %d, dispatchers = %d, want none — preparation starts no child", h.snapshotted, len(h.modeCtxs))
	}
}

// Two leaves that share a missing parent both mutate that directory, so the shared parent has to
// appear in each child's targets even though the declared leaves are disjoint.
func TestDelegate_PrepareSharesTheMissingParentOfDisjointLeaves(t *testing.T) {
	h := newHarness(t)

	_, declaredA, _, _, _, targetsA, err := h.tool().PrepareDelegate(callArgs("first", "shared/a.txt"))
	if err != nil {
		t.Fatalf("PrepareDelegate error = %v, want nil", err)
	}
	_, declaredB, _, _, _, targetsB, err := h.tool().PrepareDelegate(callArgs("second", "shared/b.txt"))
	if err != nil {
		t.Fatalf("PrepareDelegate error = %v, want nil", err)
	}

	shared := filepath.Join(h.dir, "shared")
	if !slices.Contains(targetsA, shared) || !slices.Contains(targetsB, shared) {
		t.Fatalf("targets %v and %v do not both carry the shared missing parent %q", targetsA, targetsB, shared)
	}
	if declaredA[shared] || declaredB[shared] {
		t.Fatalf("declarations %v / %v carry the implicit parent %q, want the leaves alone", declaredA, declaredB, shared)
	}

	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	_, _, _, _, _, targetsExisting, err := h.tool().PrepareDelegate(callArgs("third", "shared/c.txt"))
	if err != nil {
		t.Fatalf("PrepareDelegate error = %v, want nil", err)
	}
	if slices.Contains(targetsExisting, shared) {
		t.Fatalf("targets %v carry the existing parent %q, want only parents a create would make", targetsExisting, shared)
	}
}

func TestDelegate_PreparedTargetsAreNotSharedBetweenCalls(t *testing.T) {
	h := newHarness(t)

	_, _, _, _, _, first, err := h.tool().PrepareDelegate(callArgs("do it", "dir/sub/b.txt"))
	if err != nil {
		t.Fatalf("PrepareDelegate error = %v, want nil", err)
	}
	original := slices.Clone(first)
	for i := range first {
		first[i] = filepath.Join(h.dir, "elsewhere.txt")
	}
	_, _, _, _, _, second, err := h.tool().PrepareDelegate(callArgs("do it", "dir/sub/b.txt"))
	if err != nil {
		t.Fatalf("PrepareDelegate error = %v, want nil", err)
	}
	if !slices.Equal(second, original) {
		t.Fatalf("second preparation = %v, want the same targets %v", second, original)
	}
}

func TestDelegate_PreparationRefusalCarriesTheInBandCorrective(t *testing.T) {
	h := newHarness(t)

	_, _, _, _, _, _, err := h.tool().PrepareDelegate(callArgs("do it"))
	var refusal *PreparationError
	if !errors.As(err, &refusal) {
		t.Fatalf("PrepareDelegate error = %v, want a *PreparationError", err)
	}
	if !strings.Contains(refusal.Error(), ToolName) || !strings.Contains(refusal.Error(), "at least one path") {
		t.Fatalf("error = %q, want it to name the tool and the fault", refusal.Error())
	}

	direct, ierr := h.tool().Invoke(t.Context(), callArgs("do it"))
	if ierr != nil {
		t.Fatalf("Invoke error = %v, want nil", ierr)
	}
	if !reflect.DeepEqual(refusal.Result(), direct) {
		t.Fatalf("prepared refusal = %+v, want the same result Invoke returns %+v", refusal.Result(), direct)
	}
	if h.snapshotted != 0 {
		t.Fatalf("parent state snapshotted %d times, want 0", h.snapshotted)
	}
}

// The child's ceiling is the set handed to invocation, never one re-derived from a declaration the
// filesystem may have moved since.
func TestDelegate_InvokeFromAPreparedDeclarationSkipsTheRawArguments(t *testing.T) {
	h := newHarness(t, streamRound(contentChunk("done"), finishChunk()))
	prepared := map[string]bool{filepath.Join(h.dir, "a.txt"): true}

	res, err := h.tool().InvokeWithPreparedDelegate(t.Context(), "narrow the fix", prepared, nil, nil, nil)
	if err != nil {
		t.Fatalf("InvokeWithPreparedDelegate error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if len(h.modeCtxs) != 1 {
		t.Fatalf("child dispatchers built = %d, want 1", len(h.modeCtxs))
	}
	mc := h.modeCtxs[0]
	if !mc.ChildAgent || !reflect.DeepEqual(mc.DeclaredWrite, prepared) {
		t.Fatalf("child ceiling = %+v, want the prepared declaration %v marked as a child", mc, prepared)
	}
	msgs := h.client.requests[0].Messages
	if msgs[len(msgs)-1].Content != "narrow the fix"+subagent.InstructionSuffix {
		t.Fatalf("child instruction = %q, want the prepared instruction", msgs[len(msgs)-1].Content)
	}
}

func TestDelegate_InstructionReachesTheChildByteIdentical(t *testing.T) {
	instruction := "run `make test` and $(echo hi)\nthen write \"the report\"\n\ttrailing tab"
	h := newHarness(t, streamRound(contentChunk("done"), finishChunk()))

	res, err := h.tool().Invoke(t.Context(), callArgs(instruction, "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if len(h.client.requests) == 0 {
		t.Fatal("the child issued no provider request")
	}
	msgs := h.client.requests[0].Messages
	if len(msgs) != 2 || msgs[1].Role != "user" {
		t.Fatalf("child's first round = %+v, want a system prompt and one user message", msgs)
	}
	if msgs[1].Content != instruction+subagent.InstructionSuffix {
		t.Fatalf("child instruction = %q, want the tool argument byte for byte %q followed by the fixed suffix", msgs[1].Content, instruction)
	}
}

func TestDelegate_ChildAdvertisesOnlyThePinnedToolSet(t *testing.T) {
	h := newHarness(t, streamRound(contentChunk("done"), finishChunk()))

	if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}

	var got []string
	for _, def := range h.client.requests[0].Tools {
		got = append(got, def.Name)
	}
	slices.Sort(got)
	if !reflect.DeepEqual(got, pinnedChildTools) {
		t.Fatalf("child tools = %v, want exactly %v", got, pinnedChildTools)
	}
}

// fakeTool carries metadata the VCS layer would never produce, so the child filter can be
// exercised on a read-only claim that is missing the noncredential half and on a non-VCS tool
// that advertises both.
type fakeTool struct {
	name string
	meta tools.Metadata
}

func (f fakeTool) Name() string              { return f.name }
func (f fakeTool) SubjectKind() string       { return "tool" }
func (f fakeTool) Advertise() tools.Metadata { return f.meta }
func (f fakeTool) Invoke(context.Context, map[string]any) (tools.Result, error) {
	return tools.Result{}, nil
}

func gitTemplate(source string, reference bool, actions map[string]vcs.ActionSpec) *vcs.Template {
	return &vcs.Template{Name: "git", Source: source, BuiltinReferenceCopy: reference, Actions: actions}
}

// vcsTools realizes real ActionTools so each case's read-only and noncredential metadata is the
// one the VCS layer binds at registration, not a value the test asserts into existence.
func vcsTools(t *testing.T, tmpl *vcs.Template, trustExplicitClasses bool) []tools.Tool {
	t.Helper()
	register := vcs.RegisterActions
	if trustExplicitClasses {
		register = vcs.RegisterActionsWithTrustedClasses
	}
	reg := tools.NewRegistry()
	if err := register(reg, tmpl, t.TempDir(), nil, nil, 4096); err != nil {
		t.Fatalf("register VCS actions: %v", err)
	}
	return reg.List()
}

var builtinGitActions = map[string]vcs.ActionSpec{
	"status": {Argv: []string{"git", "status", "--short"}},
	"diff":   {Argv: []string{"git", "diff"}},
	"commit": {Argv: []string{"git", "commit", "-m", "{message}"}},
}

func declaredReadOnly(spec vcs.ActionSpec) vcs.ActionSpec {
	spec.Class = vcs.ClassReadOnly
	return spec
}

var pinnedChildTools = []string{
	"create", "delegate", "delete", "edit", "file_count", "glob", "grep", "list", "mkdir", "move",
	"read", "read_image", "tree",
}

func vcsChildCases(t *testing.T) []struct {
	name       string
	registered []tools.Tool
	wantVCS    []string
} {
	t.Helper()
	project := filepath.Join(t.TempDir(), ".codemeld", "vcs", "git.yaml")
	global := filepath.Join(t.TempDir(), "global", "vcs", "git.yaml")
	return []struct {
		name       string
		registered []tools.Tool
		wantVCS    []string
	}{
		{"no active VCS", nil, nil},
		{
			"byte-identical project reference copy",
			vcsTools(t, gitTemplate(project, true, builtinGitActions), false),
			[]string{"vcs_diff", "vcs_status"},
		},
		{
			"trusted global read-only declaration over the product argv",
			vcsTools(t, gitTemplate(global, false, map[string]vcs.ActionSpec{
				"status": declaredReadOnly(builtinGitActions["status"]),
				"commit": builtinGitActions["commit"],
			}), true),
			[]string{"vcs_status"},
		},
		{
			"untrusted project template",
			vcsTools(t, gitTemplate(project, false, builtinGitActions), false),
			nil,
		},
		{
			"trusted read-only declaration over a changed argv",
			vcsTools(t, gitTemplate(global, false, map[string]vcs.ActionSpec{
				"status": declaredReadOnly(vcs.ActionSpec{Argv: []string{"git", "log", "-p"}}),
			}), true),
			nil,
		},
		{
			"malformed metadata",
			[]tools.Tool{
				fakeTool{name: "vcs_status", meta: tools.Metadata{ReadOnly: true}},
				fakeTool{name: "vcs_diff", meta: tools.Metadata{Noncredential: true}},
				fakeTool{name: "web_search", meta: tools.Metadata{ReadOnly: true, Noncredential: true}},
			},
			nil,
		},
	}
}

// The child's VCS surface is whatever the realized registry classifies as read-only and
// noncredential — nothing is admitted from the vcs_ name, the action, or the template's source.
func TestDelegate_ChildVCSSurfaceFollowsRealizedRegistryMetadata(t *testing.T) {
	for _, tc := range vcsChildCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, streamRound(contentChunk("done"), finishChunk()))
			h.registered = tc.registered

			if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
				t.Fatalf("Invoke error = %v, want nil", err)
			}

			var got []string
			for _, def := range h.client.requests[0].Tools {
				got = append(got, def.Name)
			}
			want := append(slices.Clone(pinnedChildTools), tc.wantVCS...)
			slices.Sort(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("child tools = %v, want exactly %v in name order", got, want)
			}
			if slices.Contains(got, "bash") {
				t.Fatalf("child tools = %v, want no bash", got)
			}
		})
	}
}

// Advertising and execution read the one derived set, so a case that leaves an action
// unadvertised must also keep it away from the parent's real dispatcher.
func TestDelegate_ChildVCSCallsReachTheParentDispatcherOnlyWhenAdmitted(t *testing.T) {
	for _, tc := range vcsChildCases(t) {
		for _, name := range []string{"vcs_status", "vcs_diff", "vcs_commit"} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				h := newHarness(t,
					streamRound(toolCallChunk("call-1", name)),
					streamRound(contentChunk("done"), finishChunk()),
				)
				h.registered = tc.registered

				if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
					t.Fatalf("Invoke error = %v, want nil", err)
				}
				admitted := slices.Contains(tc.wantVCS, name)
				if got := slices.Contains(h.dispatcher.dispatched, name); got != admitted {
					t.Fatalf("%q dispatched on the parent dispatcher = %v, want %v; dispatched=%v", name, got, admitted, h.dispatcher.dispatched)
				}
				if !admitted && slices.Contains(h.dispatcher.planned, name) {
					t.Fatalf("%q reached the parent planner; planned=%v", name, h.dispatcher.planned)
				}
				if admitted {
					return
				}
				msgs := h.client.requests[1].Messages
				last := msgs[len(msgs)-1]
				if last.Role != "tool" || !strings.Contains(last.Content, "not available to a child agent") {
					t.Fatalf("child's tool result = %+v, want an in-band refusal naming the tool", last)
				}
			})
		}
	}
}

// The advertised set is only a suggestion to the provider. A child that emits a tool name it
// was never offered must be refused by the dispatcher rather than reaching the parent's real
// one, where the call would be judged on the parent's permissions alone.
func TestDelegate_ChildCallingAnUnadvertisedToolNeverReachesTheParentDispatcher(t *testing.T) {
	for _, name := range []string{"bash", "vcs_commit", "web_fetch", "ask_user", "web_search"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t,
				streamRound(toolCallChunk("call-1", name)),
				streamRound(contentChunk("done"), finishChunk()),
			)

			if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
				t.Fatalf("Invoke error = %v, want nil", err)
			}
			if slices.Contains(h.dispatcher.planned, name) {
				t.Fatalf("%q was planned on the parent dispatcher; planned=%v", name, h.dispatcher.planned)
			}
			if slices.Contains(h.dispatcher.dispatched, name) {
				t.Fatalf("%q was dispatched on the parent dispatcher; dispatched=%v", name, h.dispatcher.dispatched)
			}
			if len(h.client.requests) < 2 {
				t.Fatalf("child rounds = %d, want the refusal fed back for a second round", len(h.client.requests))
			}
			msgs := h.client.requests[1].Messages
			last := msgs[len(msgs)-1]
			if last.Role != "tool" || !strings.Contains(last.Content, "not available to a child agent") {
				t.Fatalf("child's tool result = %+v, want an in-band refusal naming the tool", last)
			}
		})
	}
}

// Confinement narrows a mixed round rather than failing it: the permitted call beside a refused
// one still reaches the parent dispatcher. This asserts reachability only, not the plan's
// ordering or unit metadata.
func TestDelegate_ConfinementLeavesPermittedCallsInTheSameRoundIntact(t *testing.T) {
	h := newHarness(t,
		streamRound(indexedToolCallChunk(0, "call-1", "read"), indexedToolCallChunk(1, "call-2", "bash")),
		streamRound(contentChunk("done"), finishChunk()),
	)

	if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if !slices.Contains(h.dispatcher.dispatched, "read") {
		t.Fatalf("read did not reach the parent dispatcher; dispatched=%v", h.dispatcher.dispatched)
	}
	if slices.Contains(h.dispatcher.planned, "bash") {
		t.Fatalf("bash reached the parent planner; planned=%v", h.dispatcher.planned)
	}
}

// turn's loop reaches a dispatcher only through the units Plan returns, so Dispatch's own guard
// is defense in depth against a future caller that does not go through Plan. Exercise it
// directly, since no loop-level test can.
func TestConfinedDispatcher_DispatchRefusesANonPinnedNameDirectly(t *testing.T) {
	inner := &stubDispatcher{}
	d := &confinedDispatcher{inner: inner, permitted: childPermittedTools(nil)}

	res, err := d.Dispatch(t.Context(), turn.AssembledToolCall{ID: "call-1", Name: "bash"})
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if !strings.Contains(res.Content, "not available to a child agent") {
		t.Fatalf("Content = %q, want an in-band refusal", res.Content)
	}
	if len(inner.dispatched) != 0 {
		t.Fatalf("inner dispatched = %v, want nothing", inner.dispatched)
	}

	if _, err := d.Dispatch(t.Context(), turn.AssembledToolCall{ID: "call-2", Name: "read"}); err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if !slices.Equal(inner.dispatched, []string{"read"}) {
		t.Fatalf("inner dispatched = %v, want only the pinned read", inner.dispatched)
	}
}

func TestDelegate_CarriesInheritedModeAndDeclaredWriteIntoAuthorization(t *testing.T) {
	h := newHarness(t, streamRound(contentChunk("done"), finishChunk()))

	if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt", "dir/sub/b.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if len(h.modeCtxs) != 1 {
		t.Fatalf("child dispatchers built = %d, want 1", len(h.modeCtxs))
	}
	mc := h.modeCtxs[0]
	if mc.Mode != "auto_edits" {
		t.Fatalf("child mode = %q, want the inherited parent mode", mc.Mode)
	}
	want := map[string]bool{
		filepath.Join(h.dir, "a.txt"):               true,
		filepath.Join(h.dir, "dir", "sub", "b.txt"): true,
	}
	if !reflect.DeepEqual(mc.DeclaredWrite, want) {
		t.Fatalf("DeclaredWrite = %v, want the canonical launch-dir-anchored targets %v", mc.DeclaredWrite, want)
	}
	if mc.DeclaredDelete != nil {
		t.Fatalf("DeclaredDelete = %#v, want nil — this call supplied no files_delete", mc.DeclaredDelete)
	}
	if !mc.ChildAgent {
		t.Fatal("ChildAgent = false, want the ceiling marked as a child declaration")
	}
	if len(mc.DelegateWrite) != 0 {
		t.Fatalf("DelegateWrite = %v, want empty — the child has made no delegate call of its own", mc.DelegateWrite)
	}
}

func TestDelegate_MutatingFileToolsReachAuthorizationInsteadOfBeingWithheld(t *testing.T) {
	for _, name := range []string{"delete", "mkdir", "move"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t,
				streamRound(toolCallChunk("call-1", name)),
				streamRound(contentChunk("done"), finishChunk()),
			)

			if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
				t.Fatalf("Invoke error = %v, want nil", err)
			}
			if !slices.Contains(h.dispatcher.dispatched, name) {
				t.Fatalf("%q did not reach the parent dispatcher; dispatched=%v", name, h.dispatcher.dispatched)
			}
			msgs := h.client.requests[1].Messages
			last := msgs[len(msgs)-1]
			if strings.Contains(last.Content, "not available to a child agent") {
				t.Fatalf("%q was refused as an unavailable tool: %+v", name, last)
			}
		})
	}
}

func TestDelegate_NestedCallIsAuthorizedAgainstTheChildsOwnDeclaration(t *testing.T) {
	h := newHarness(t,
		streamRound(toolCallChunkWithArgs("call-1", ToolName, `{"instructions":"narrower","files":["a.txt"]}`)),
		streamRound(contentChunk("done"), finishChunk()),
	)

	if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt", "b.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if len(h.dispatchers) != 2 || len(h.modeCtxs) != 2 {
		t.Fatalf("authorization contexts built = %d, want the child's own and the nested call's", len(h.modeCtxs))
	}
	own := h.dispatchers[0]
	if slices.Contains(own.planned, ToolName) || slices.Contains(own.dispatched, ToolName) {
		t.Fatalf("a nested delegate reached the child's ordinary dispatcher; planned=%v dispatched=%v",
			own.planned, own.dispatched)
	}
	if !slices.Contains(h.dispatchers[1].dispatched, ToolName) {
		t.Fatalf("the nested delegate never reached its own authorization; dispatched=%v", h.dispatchers[1].dispatched)
	}
	nested := h.modeCtxs[1]
	if !nested.ChildAgent {
		t.Fatal("nested ChildAgent = false, want the nested call judged as a child declaration")
	}
	wantParent := map[string]bool{
		filepath.Join(h.dir, "a.txt"): true,
		filepath.Join(h.dir, "b.txt"): true,
	}
	if !reflect.DeepEqual(nested.DeclaredWrite, wantParent) {
		t.Fatalf("nested DeclaredWrite = %v, want the calling child's own set %v", nested.DeclaredWrite, wantParent)
	}
	wantNested := map[string]bool{filepath.Join(h.dir, "a.txt"): true}
	if !reflect.DeepEqual(nested.DelegateWrite, wantNested) {
		t.Fatalf("nested DelegateWrite = %v, want the resolved nested declaration %v", nested.DelegateWrite, wantNested)
	}
}

// An empty nested scope is the fail-closed reading: the containment check refuses it, so a nested
// declaration the child garbled can never widen into an unbounded grandchild.
func TestDelegate_UnresolvableNestedDeclarationCarriesNoScope(t *testing.T) {
	tests := []struct {
		name string
		args string
	}{
		{"no arguments at all", `{}`},
		{"arguments that are not JSON", `not json`},
		{"an absolute path", `{"instructions":"x","files":["/etc/passwd"]}`},
		{"an empty file list", `{"instructions":"x","files":[]}`},
		{"a path outside the project", `{"instructions":"x","files":["../escape.txt"]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t,
				streamRound(toolCallChunkWithArgs("call-1", ToolName, tc.args)),
				streamRound(contentChunk("done"), finishChunk()),
			)

			if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
				t.Fatalf("Invoke error = %v, want nil", err)
			}
			if len(h.modeCtxs) != 2 {
				t.Fatalf("authorization contexts built = %d, want the child's own and the nested call's", len(h.modeCtxs))
			}
			if got := h.modeCtxs[1]; len(got.DelegateWrite) != 0 || len(got.DelegateDelete) != 0 {
				t.Fatalf("DelegateWrite = %v, DelegateDelete = %v, want both empty so the containment check refuses the call",
					got.DelegateWrite, got.DelegateDelete)
			}
		})
	}
}

func TestDelegate_ChildKeepsTheSnapshotPromptAndEffortOnEveryRound(t *testing.T) {
	h := newHarness(t,
		streamRound(toolCallChunk("call_1", "read")),
		streamRound(contentChunk("done"), finishChunk()),
	)

	if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if len(h.client.requests) != 2 {
		t.Fatalf("provider requests = %d, want an initial and a continuation round", len(h.client.requests))
	}
	for i, req := range h.client.requests {
		if req.Effort != "high" {
			t.Fatalf("round %d effort = %q, want the inherited non-default %q", i+1, req.Effort, "high")
		}
		if len(req.Messages) == 0 || req.Messages[0].Role != "system" || req.Messages[0].Content != parentPrompt {
			t.Fatalf("round %d does not lead with the parent's assembled prompt: %+v", i+1, req.Messages)
		}
		if req.Model != "gpt-5.5" {
			t.Fatalf("round %d model = %q, want the snapshotted parent model", i+1, req.Model)
		}
	}
	if h.snapshotted != 1 {
		t.Fatalf("parent state snapshotted %d times, want once per delegate call", h.snapshotted)
	}
}

func TestDelegate_RendersTheChildReplyAndTerminalReason(t *testing.T) {
	h := newHarness(t, streamRound(contentChunk("the answer is 42"), finishChunk()))

	res, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	out := string(res.Stdout)
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 for a completed child; out=%q", res.ExitCode, out)
	}
	if !strings.Contains(out, "the answer is 42") {
		t.Fatalf("result = %q, want the child's final reply", out)
	}
	if !strings.Contains(out, string(subagent.ReasonCompleted)) {
		t.Fatalf("result = %q, want the terminal reason", out)
	}
	if !strings.Contains(out, "1 provider request") {
		t.Fatalf("result = %q, want the child's step count", out)
	}
}

func TestDelegate_RendersATruncationNoticeAndANonTerminalReason(t *testing.T) {
	long := strings.Repeat("x", 17<<10)
	rounds := make([]func() (provider.Response, error), subagent.DefaultStepCap)
	for i := range rounds {
		rounds[i] = streamRound(contentChunk(long), toolCallChunkWithArgs(fmt.Sprintf("call_%d", i+1), "read", alternatingEmptyArgs(i)))
	}
	h := newHarness(t, rounds...)

	res, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	out := string(res.Stdout)
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want non-zero for a child that did not complete; out=%q", out[:80])
	}
	if !strings.Contains(out, string(subagent.ReasonStepCap)) {
		t.Fatalf("result does not report the step cap: %q", out[:80])
	}
	if !strings.Contains(out, "truncated") {
		t.Fatalf("result does not report the truncated reply: %q", out[:80])
	}
	if len(h.client.requests) != subagent.DefaultStepCap {
		t.Fatalf("provider requests = %d, want the step cap %d", len(h.client.requests), subagent.DefaultStepCap)
	}
}

func TestDelegate_RendersACancelledChildWithANonZeroExit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h := newHarness(t, func() (provider.Response, error) {
		cancel()
		return streamRound(contentChunk("partial"), toolCallChunk("call_1", "read"))()
	})

	res, err := h.tool().Invoke(ctx, callArgs("do it", "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	out := string(res.Stdout)
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want non-zero for a cancelled child; out=%q", out)
	}
	if !strings.Contains(out, "child agent "+string(subagent.ReasonCancelled)) {
		t.Fatalf("result = %q, want it to state the cancelled terminal reason", out)
	}
	if len(h.client.requests) != 1 {
		t.Fatalf("provider requests = %d, want the cancellation to stop the child after the first", len(h.client.requests))
	}
}

func TestDelegate_WithoutAResolvableParentStartsNoChild(t *testing.T) {
	h := newHarness(t)
	h.snapshotOK = false

	res, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want non-zero when no parent model resolves; stdout=%q", res.Stdout)
	}
	if len(h.modeCtxs) != 0 {
		t.Fatalf("child dispatchers built = %d, want 0", len(h.modeCtxs))
	}
	if len(h.client.requests) != 0 {
		t.Fatalf("provider requests = %d, want 0", len(h.client.requests))
	}
}

// writingDispatcher runs the child's create calls on the real structured create tool, so the journal
// is exercised through the publish seam a delegated child actually reaches.
type writingDispatcher struct {
	create   *filetools.CreateTool
	remove   *filetools.DeleteTool
	move     *filetools.MoveTool
	mkdir    *filetools.MkdirTool
	onCall   func()
	onSeeCtx func(context.Context)
}

func (d *writingDispatcher) Plan(calls []turn.AssembledToolCall, _ int) turn.ToolPlan {
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	for i, call := range calls {
		plan.Units[i] = turn.PlannedToolCall{
			Call: call,
			Run:  func(ctx context.Context) (turn.ToolResult, error) { return d.Dispatch(ctx, call) },
		}
	}
	return plan
}

func (d *writingDispatcher) Dispatch(ctx context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	if d.onSeeCtx != nil {
		d.onSeeCtx(ctx)
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
		return turn.ToolResult{Content: "bad arguments"}, nil
	}
	target, _ := args["path"].(string)
	invoke, written, deleted := d.create.InvokeWithResolvedTarget, target, ""
	var moved turn.MoveTarget
	switch call.Name {
	case filetools.DeleteToolName:
		invoke, written, deleted = d.remove.InvokeWithResolvedTarget, "", target
	case filetools.MoveToolName:
		source, _ := args["source"].(string)
		destination, _ := args["destination"].(string)
		invoke = func(ctx context.Context, _ map[string]any, _ string) (tools.Result, error) {
			return d.move.InvokeWithResolvedMove(ctx, filetools.ResolvedMove{Source: source, Destination: destination})
		}
		written = ""
		moved = turn.MoveTarget{Source: source, Destination: destination}
	case filetools.MkdirToolName:
		invoke, written = d.mkdir.InvokeWithResolvedTarget, ""
	}
	res, err := invoke(ctx, args, target)
	if err != nil {
		return turn.ToolResult{}, err
	}
	if d.onCall != nil {
		d.onCall()
	}
	return turn.ToolResult{Content: string(res.Stdout) + string(res.Stderr), WriteTarget: written, DeleteTarget: deleted, MoveTarget: moved}, nil
}

func TestDelegate_UndoesTheWritesOfAChildThatDidNotComplete(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	h := newHarness(t)
	target := filepath.Join(h.dir, "a.txt")
	createArgs := fmt.Sprintf(`{"path":%q,"content":"CHILD MADE THIS\n"}`, target)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", "create", createArgs)),
		streamRound(contentChunk("never reached"), finishChunk()),
	}
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{
			create: filetools.NewCreateTool(h.deps.Home, h.dir, h.dir),
			onCall: cancel,
		}
	}

	res, err := h.tool().Invoke(ctx, callArgs("write the report", "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	out := string(res.Stdout)
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want non-zero for a child that did not complete; out=%q", out)
	}
	if !strings.Contains(out, "its changes were undone") {
		t.Fatalf("result = %q, want it to say the child's work was undone", out)
	}
	if !strings.Contains(out, target) {
		t.Fatalf("result = %q, want it to name the restored path", out)
	}
	if _, serr := os.Lstat(target); !os.IsNotExist(serr) {
		t.Fatalf("%s still exists (err=%v), want the child's create rolled back", target, serr)
	}
	if entries, rerr := os.ReadDir(filepath.Join(h.deps.Home, ".codemeld")); rerr == nil && len(entries) > 0 {
		if _, serr := os.Stat(filepath.Join(h.deps.Home, ".codemeld", "journals")); serr == nil {
			leftovers, _ := os.ReadDir(filepath.Join(h.deps.Home, ".codemeld", "journals"))
			for _, folder := range leftovers {
				inner, _ := os.ReadDir(filepath.Join(h.deps.Home, ".codemeld", "journals", folder.Name()))
				if len(inner) != 0 {
					t.Fatalf("journal storage left behind: %v", inner)
				}
			}
		}
	}
}

func TestDelegate_KeepsTheWorkOfACompletedChild(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.dir, "a.txt")
	createArgs := fmt.Sprintf(`{"path":%q,"content":"CHILD MADE THIS\n"}`, target)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", "create", createArgs)),
		streamRound(contentChunk("wrote the report"), finishChunk()),
	}
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{create: filetools.NewCreateTool(h.deps.Home, h.dir, h.dir)}
	}

	res, err := h.tool().Invoke(t.Context(), callArgs("write the report", "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	out := string(res.Stdout)
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 for a completed child; out=%q", res.ExitCode, out)
	}
	if strings.Contains(out, "undone") || strings.Contains(out, "retained") {
		t.Fatalf("result = %q, want a completion to claim no rollback", out)
	}
	data, rerr := os.ReadFile(target)
	if rerr != nil || string(data) != "CHILD MADE THIS\n" {
		t.Fatalf("%s = %q (err=%v), want the child's result kept", target, data, rerr)
	}
}

func TestDelegate_StartsNoChildWhenTheJournalWouldLandInsideTheProject(t *testing.T) {
	for _, tc := range []struct {
		name string
		home func(t *testing.T, h *harness) string
	}{
		{
			name: "the project is the home",
			home: func(_ *testing.T, h *harness) string { return h.dir },
		},
		{
			name: "the home sits inside the project alongside its sessions",
			home: func(t *testing.T, h *harness) string {
				home := filepath.Join(h.dir, "user")
				if err := os.MkdirAll(filepath.Join(home, ".codemeld", "sessions"), 0o700); err != nil {
					t.Fatalf("seed the in-project home: %v", err)
				}
				return home
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.deps.Home = tc.home(t, h)

			res, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt"))
			if err != nil {
				t.Fatalf("Invoke error = %v, want nil", err)
			}
			if res.ExitCode == 0 {
				t.Fatalf("ExitCode = 0, want a refusal when the journal cannot be kept out of the working copy")
			}
			if len(h.client.requests) != 0 {
				t.Fatalf("provider requests = %d, want no child started", len(h.client.requests))
			}
			if _, serr := os.Stat(filepath.Join(h.deps.Home, ".codemeld", "journals")); !os.IsNotExist(serr) {
				t.Fatalf("journal storage was created inside the project (err=%v)", serr)
			}
		})
	}
}

// TestDelegate_BindsItsJournalToTheChildsDispatchContext pins the handoff a nested delegate depends
// on: openJournal reads the parent journal out of the dispatch context it is given, so a nested
// child that cannot see it there would open an unlinked journal its parent never absorbs.
func TestDelegate_BindsItsJournalToTheChildsDispatchContext(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.dir, "a.txt")
	createArgs := fmt.Sprintf(`{"path":%q,"content":"CHILD MADE THIS\n"}`, target)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", "create", createArgs)),
		streamRound(contentChunk("wrote the report"), finishChunk()),
	}
	var seen filetools.WriteJournal
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{
			create:   filetools.NewCreateTool(h.deps.Home, h.dir, h.dir),
			onSeeCtx: func(ctx context.Context) { seen = filetools.WriteJournalFromContext(ctx) },
		}
	}

	if _, err := h.tool().Invoke(t.Context(), callArgs("write the report", "a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}

	journal, ok := seen.(*subagent.Journal)
	if !ok {
		t.Fatalf("dispatch context journal = %T, want the *subagent.Journal a nested delegate links to", seen)
	}
	if !journal.Covers(target) {
		t.Fatalf("the bound journal does not cover the declared path %s", target)
	}
}

func TestDelegate_PrepareAcceptsEveryDeleteDeclarationForm(t *testing.T) {
	h := newHarness(t)
	home := filepath.Join(h.dir, "home")
	if err := os.MkdirAll(filepath.Join(home, "sub"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	h.deps.Home = home

	tests := []struct {
		name   string
		remove string
		want   string
	}{
		{"relative", "old.txt", filepath.Join(h.dir, "old.txt")},
		{"absolute under a missing parent", filepath.Join(h.dir, "gone", "old.txt"), filepath.Join(h.dir, "gone", "old.txt")},
		{"the home directory itself", "~", home},
		{"home-relative", "~/sub/old.txt", filepath.Join(home, "sub", "old.txt")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, write, remove, _, _, targets, err := h.tool().PrepareDelegate(declareArgs("do it", nil, []string{tc.remove}))
			if err != nil {
				t.Fatalf("PrepareDelegate error = %v, want a delete-only declaration accepted", err)
			}
			if write != nil {
				t.Fatalf("write declaration = %#v, want nil for an omitted files list", write)
			}
			if want := map[string]bool{tc.want: true}; !reflect.DeepEqual(remove, want) {
				t.Fatalf("delete declaration = %v, want the canonical in-project target %v", remove, want)
			}
			if !slices.Contains(targets, tc.want) {
				t.Fatalf("scheduler targets = %v, want them to carry the delete target %s", targets, tc.want)
			}
		})
	}
	if h.snapshotted != 0 {
		t.Fatalf("parent state snapshotted %d times, want 0 — preparation starts no child", h.snapshotted)
	}
}

func TestDelegate_OmittedAndSuppliedEmptyListsStayDistinct(t *testing.T) {
	tests := []struct {
		name                string
		args                map[string]any
		writeNil, removeNil bool
	}{
		{"files_delete omitted", declareArgs("do it", []string{"a.txt"}, nil), false, true},
		{"files_delete supplied empty", declareArgs("do it", []string{"a.txt"}, []string{}), false, false},
		{"files omitted", declareArgs("do it", nil, []string{"a.txt"}), true, false},
		{"files supplied empty", declareArgs("do it", []string{}, []string{"a.txt"}), false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, write, remove, _, _, _, err := newHarness(t).tool().PrepareDelegate(tc.args)
			if err != nil {
				t.Fatalf("PrepareDelegate error = %v, want nil", err)
			}
			if (write == nil) != tc.writeNil || (remove == nil) != tc.removeNil {
				t.Fatalf("write = %#v, remove = %#v; want nil write=%v, nil remove=%v", write, remove, tc.writeNil, tc.removeNil)
			}
		})
	}
}

func TestDelegate_SchedulerTargetsCoverTheWriteAndDeleteUnionOnce(t *testing.T) {
	h := newHarness(t)

	_, _, _, _, _, targets, err := h.tool().PrepareDelegate(declareArgs("do it", []string{"both.txt", "dir/new.txt"}, []string{"both.txt", "gone.txt"}))
	if err != nil {
		t.Fatalf("PrepareDelegate error = %v, want nil", err)
	}
	want := []string{
		filepath.Join(h.dir, "both.txt"),
		filepath.Join(h.dir, "dir"),
		filepath.Join(h.dir, "dir", "new.txt"),
		filepath.Join(h.dir, "gone.txt"),
	}
	if !slices.Equal(targets, want) {
		t.Fatalf("scheduler targets = %v, want the deduplicated write and delete union %v", targets, want)
	}
}

func TestDelegate_CarriesTheDeleteDeclarationIntoTheChildAndItsNestedCalls(t *testing.T) {
	h := newHarness(t,
		streamRound(toolCallChunkWithArgs("call-1", ToolName, `{"instructions":"narrower","files_delete":["old.txt"]}`)),
		streamRound(contentChunk("done"), finishChunk()),
	)

	if _, err := h.tool().Invoke(t.Context(), declareArgs("do it", []string{"a.txt"}, []string{"old.txt"})); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if len(h.modeCtxs) != 2 {
		t.Fatalf("authorization contexts built = %d, want the child's own and the nested call's", len(h.modeCtxs))
	}
	want := map[string]bool{filepath.Join(h.dir, "old.txt"): true}
	for i, mc := range h.modeCtxs {
		if !reflect.DeepEqual(mc.DeclaredDelete, want) {
			t.Fatalf("authorization context %d DeclaredDelete = %v, want the child's delete declaration %v", i, mc.DeclaredDelete, want)
		}
	}
}

func TestDelegate_NestedDeleteOnlyDeclarationIsJudgedAgainstTheImmediateParentsDeleteSet(t *testing.T) {
	tests := []struct {
		name       string
		nested     string
		wantDenied bool
	}{
		{"a delete inside the parent's delete set is admitted", "old.txt", false},
		{"a delete outside the parent's delete set is refused", "other.txt", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t,
				streamRound(toolCallChunkWithArgs("call-1", ToolName, fmt.Sprintf(`{"instructions":"narrower","files_delete":[%q]}`, tc.nested))),
				streamRound(contentChunk("done"), finishChunk()),
			)

			if _, err := h.tool().Invoke(t.Context(), declareArgs("do it", []string{"a.txt"}, []string{"old.txt"})); err != nil {
				t.Fatalf("Invoke error = %v, want nil", err)
			}
			if len(h.modeCtxs) != 2 {
				t.Fatalf("authorization contexts built = %d, want the child's own and the nested call's", len(h.modeCtxs))
			}
			nested := h.modeCtxs[1]
			if want := map[string]bool{filepath.Join(h.dir, tc.nested): true}; !reflect.DeepEqual(nested.DelegateDelete, want) {
				t.Fatalf("nested DelegateDelete = %v, want the resolved nested delete declaration %v", nested.DelegateDelete, want)
			}
			if nested.DelegateWrite != nil {
				t.Fatalf("nested DelegateWrite = %#v, want nil — the nested call supplied no files", nested.DelegateWrite)
			}

			nested.ToolName = ToolName
			d, err := permissions.Authorize(t.Context(), permissions.MatchRequest{Kind: "tool", Subject: ToolName}, nested,
				permissions.AuthorizeDeps{EmitMatched: func(string, string, string, string, string, string, string, string, string) error { return nil }})
			if err != nil {
				t.Fatalf("Authorize error = %v, want nil", err)
			}
			if denied := d.DenialSource == permissions.OutcomeSourceDeclaredScope; denied != tc.wantDenied || (!denied && d.Outcome != "once") {
				t.Fatalf("decision = %+v, want declared-scope denied=%v", d, tc.wantDenied)
			}
		})
	}
}

func writeWithMode(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod %s: %v", path, err)
	}
}

func deleteCallArgs(path string) string { return fmt.Sprintf(`{"path":%q}`, path) }

func journalsLeft(t *testing.T, home string) []string {
	t.Helper()
	root := filepath.Join(home, ".codemeld", "journals")
	folders, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("ReadDir %s: %v", root, err)
	}
	var left []string
	for _, folder := range folders {
		inner, rerr := os.ReadDir(filepath.Join(root, folder.Name()))
		if rerr != nil {
			t.Fatalf("ReadDir %s: %v", folder.Name(), rerr)
		}
		for _, entry := range inner {
			left = append(left, entry.Name())
		}
	}
	return left
}

func TestDelegate_UndoesTheDeletesOfAChildThatDidNotComplete(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	h := newHarness(t)
	first := filepath.Join(h.dir, "first.txt")
	second := filepath.Join(h.dir, "second.sh")
	writeWithMode(t, first, "FIRST ORIGINAL\n", 0o640)
	writeWithMode(t, second, "#!/bin/sh\necho second\n", 0o755)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", filetools.DeleteToolName, deleteCallArgs(first))),
		streamRound(toolCallChunkWithArgs("call_2", filetools.DeleteToolName, deleteCallArgs(second))),
		streamRound(contentChunk("never reached"), finishChunk()),
	}
	var removed []string
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{
			create: filetools.NewCreateTool(h.deps.Home, h.dir, h.dir),
			remove: filetools.NewDeleteTool(h.deps.Home, h.dir, h.dir),
			onCall: func() {
				for _, path := range []string{first, second} {
					if _, err := os.Lstat(path); os.IsNotExist(err) && !slices.Contains(removed, path) {
						removed = append(removed, path)
					}
				}
				if len(removed) == 2 {
					cancel()
				}
			},
		}
	}

	res, err := h.tool().Invoke(ctx, declareArgs("tidy up", []string{"report.txt"}, []string{"first.txt", "second.sh"}))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if len(removed) != 2 {
		t.Fatalf("files the child deleted = %v, want both gone before the cancel", removed)
	}
	out := string(res.Stdout)
	if res.ExitCode == 0 || !strings.Contains(out, "its changes were undone") {
		t.Fatalf("result = %q (exit %d), want a non-zero exit that says the child's work was undone", out, res.ExitCode)
	}
	for _, tc := range []struct {
		path, content string
		mode          os.FileMode
	}{
		{first, "FIRST ORIGINAL\n", 0o640},
		{second, "#!/bin/sh\necho second\n", 0o755},
	} {
		data, rerr := os.ReadFile(tc.path)
		if rerr != nil || string(data) != tc.content {
			t.Fatalf("%s = %q (err=%v), want its pre-run bytes %q", tc.path, data, rerr, tc.content)
		}
		info, serr := os.Lstat(tc.path)
		if serr != nil || info.Mode().Perm() != tc.mode {
			t.Fatalf("%s mode = %v (err=%v), want %o", tc.path, info, serr, tc.mode)
		}
		if !strings.Contains(out, tc.path) {
			t.Fatalf("result = %q, want it to name the restored %s", out, tc.path)
		}
	}
	if left := journalsLeft(t, h.deps.Home); len(left) != 0 {
		t.Fatalf("journal storage left behind: %v", left)
	}
}

func TestDelegate_KeepsTheDeleteOfACompletedChild(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.dir, "old.txt")
	writeWithMode(t, target, "OLD\n", 0o644)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", filetools.DeleteToolName, deleteCallArgs(target))),
		streamRound(contentChunk("removed it"), finishChunk()),
	}
	var seen filetools.WriteJournal
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{
			create:   filetools.NewCreateTool(h.deps.Home, h.dir, h.dir),
			remove:   filetools.NewDeleteTool(h.deps.Home, h.dir, h.dir),
			onSeeCtx: func(ctx context.Context) { seen = filetools.WriteJournalFromContext(ctx) },
		}
	}

	res, err := h.tool().Invoke(t.Context(), declareArgs("remove it", []string{"report.txt"}, []string{"old.txt"}))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	out := string(res.Stdout)
	if res.ExitCode != 0 || strings.Contains(out, "undone") || strings.Contains(out, "retained") {
		t.Fatalf("result = %q (exit %d), want a clean completion", out, res.ExitCode)
	}
	if seen == nil || !seen.Covers(target) {
		t.Fatalf("the child's dispatch journal %v does not cover the delete-declared path %s", seen, target)
	}
	if _, serr := os.Lstat(target); !os.IsNotExist(serr) {
		t.Fatalf("%s still exists (err=%v), want the completed child's delete kept", target, serr)
	}
	if left := journalsLeft(t, h.deps.Home); len(left) != 0 {
		t.Fatalf("journal storage left behind: %v", left)
	}
}

func TestRender_NamesRestoredAndRetainedOutcomes(t *testing.T) {
	undone := render(subagent.Result{
		Reason:        subagent.ReasonCancelled,
		RestoredPaths: []string{"/repo/a.txt", "/repo/b.txt"},
	})
	out := string(undone.Stdout)
	if undone.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want non-zero for a rolled-back child")
	}
	if !strings.Contains(out, "its changes were undone") || !strings.Contains(out, "/repo/a.txt") || !strings.Contains(out, "/repo/b.txt") {
		t.Fatalf("result = %q, want it to say the work was undone and name every restored path", out)
	}

	retained := render(subagent.Result{
		Reason:          subagent.ReasonCompleted,
		Unrecovered:     []string{"/repo/c.txt: it was changed outside the child agent's journalled writes"},
		RetainedJournal: "/home/u/.codemeld/journals/proj/inv",
	})
	out = string(retained.Stdout)
	if retained.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want non-zero for a retained journal")
	}
	if !strings.Contains(out, "/home/u/.codemeld/journals/proj/inv") || !strings.Contains(out, "/repo/c.txt") {
		t.Fatalf("result = %q, want it to name the retained journal and paths", out)
	}
	if strings.Contains(out, "its changes were undone") {
		t.Fatalf("result = %q, want an unrecovered outcome not to claim a rollback", out)
	}
}

func TestRender_ListsRefusedOperationsWhateverTheReplySays(t *testing.T) {
	refusalHeader := "refused operations: targets are shown as the child gave them, not as resolved paths; " +
		"a refusal grants nothing, so retry one only through ordinary authorization, and a guard refusal cannot be approved\n"
	completed := render(subagent.Result{
		Reason:           subagent.ReasonCompleted,
		ProviderRequests: 2,
		Reply:            "all done",
		Refusals: []subagent.Refusal{
			{Operation: "Read ../secret.txt", DeniedBy: "guard", Reason: "blocked path"},
			{Operation: "read_image pic.png", DeniedBy: "unknown"},
		},
		RefusalTotal: 5,
	})
	want := "child agent completed after 2 provider request(s)\nall done\n" + refusalHeader +
		"  Read ../secret.txt (denied_by guard): blocked path\n  read_image pic.png (denied_by unknown)\n  and 3 more\n"
	if got := string(completed.Stdout); got != want || completed.ExitCode != 0 {
		t.Fatalf("result = %q (exit %d), want %q with exit 0", got, completed.ExitCode, want)
	}

	failed := render(subagent.Result{
		Reason:           subagent.ReasonFailed,
		ProviderRequests: 1,
		Refusals:         []subagent.Refusal{{Operation: "Edit other.txt", DeniedBy: "unattended", Reason: "outside the declared scope"}},
		RefusalTotal:     1,
		RestoredPaths:    []string{"/repo/a.txt"},
	})
	want = "child agent failed after 1 provider request(s)\n" + refusalHeader +
		"  Edit other.txt (denied_by unattended): outside the declared scope\n" +
		"the child agent did not complete, so its changes were undone; restored:\n  /repo/a.txt\n"
	if got := string(failed.Stdout); got != want || failed.ExitCode != 1 {
		t.Fatalf("result = %q (exit %d), want %q with exit 1", got, failed.ExitCode, want)
	}

	none := render(subagent.Result{Reason: subagent.ReasonCompleted, ProviderRequests: 1, Reply: "done"})
	if got := string(none.Stdout); got != "child agent completed after 1 provider request(s)\ndone\n" {
		t.Fatalf("result = %q, want no refused operations section", got)
	}
}

func TestDelegate_RecordsACompletedChildAsOneStartAndOneEnd(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.dir, "a.txt")
	createArgs := fmt.Sprintf(`{"path":%q,"content":"CHILD MADE THIS\n"}`, target)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", "create", createArgs)),
		streamRound(contentChunk("wrote the report"), finishChunk()),
	}
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{create: filetools.NewCreateTool(h.deps.Home, h.dir, h.dir)}
	}

	const instruction = "write the quarterly report"
	res, err := h.tool().Invoke(t.Context(), callArgs(instruction, "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}

	start, end, raw := h.onePair(t)
	if start.ProviderID != "openai" || start.ModelID != "gpt-5.5" {
		t.Errorf("start model = %q/%q, want the snapshot's openai/gpt-5.5", start.ProviderID, start.ModelID)
	}
	if !reflect.DeepEqual(start.DeclaredPaths, []string{target}) {
		t.Errorf("start declared_paths = %v, want %v", start.DeclaredPaths, []string{target})
	}
	if start.StepCap != int64(subagent.DefaultStepCap) {
		t.Errorf("start step_cap = %d, want %d", start.StepCap, subagent.DefaultStepCap)
	}
	if start.InstructionBytes != int64(len(instruction)) || start.InstructionDigest != events.ChildInstructionDigest(instruction) {
		t.Errorf("start instruction_bytes/digest = %d/%q, want %d and the instruction's digest",
			start.InstructionBytes, start.InstructionDigest, len(instruction))
	}
	if end.Reason != events.ChildAgentReasonCompleted || end.RollbackOutcome != events.ChildRollbackNotNeeded {
		t.Errorf("end reason/rollback = %q/%q, want completed/not_needed", end.Reason, end.RollbackOutcome)
	}
	if end.Steps != int64(len(h.client.requests)) {
		t.Errorf("end steps = %d, want the %d provider requests the child made", end.Steps, len(h.client.requests))
	}
	if !reflect.DeepEqual(end.WrittenPaths, []string{target}) {
		t.Errorf("end written_paths = %v, want %v", end.WrittenPaths, []string{target})
	}
	if end.ReplyTruncated {
		t.Error("end reply_truncated = true, want false for a short reply")
	}
	if len(start.DeclaredDeletePaths) != 0 || len(end.DeletedPaths) != 0 || end.DeletedPathsTotal != 0 {
		t.Errorf("delete fields = %v / %v (total %d), want none for a write-only child", start.DeclaredDeletePaths, end.DeletedPaths, end.DeletedPathsTotal)
	}

	for _, forbidden := range []string{instruction, "wrote the report", "CHILD MADE THIS", "declared_delete_paths", "deleted_paths"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("session file carries %q, which the records must not hold", forbidden)
		}
	}
}

func TestDelegate_RecordsADeleteOnlyChildWithoutWriteAuthority(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.dir, "old.txt")
	writeWithMode(t, target, "OLD\n", 0o644)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", filetools.DeleteToolName, deleteCallArgs(target))),
		streamRound(contentChunk("removed it"), finishChunk()),
	}
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{
			create: filetools.NewCreateTool(h.deps.Home, h.dir, h.dir),
			remove: filetools.NewDeleteTool(h.deps.Home, h.dir, h.dir),
		}
	}

	res, err := h.tool().Invoke(t.Context(), declareArgs("remove it", nil, []string{"old.txt"}))
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Invoke = exit %d, err %v; stderr=%q, want a clean completion", res.ExitCode, err, res.Stderr)
	}

	start, end, _ := h.onePair(t)
	if len(start.DeclaredPaths) != 0 {
		t.Errorf("start declared_paths = %v, want no write authority for a delete-only child", start.DeclaredPaths)
	}
	if !reflect.DeepEqual(start.DeclaredDeletePaths, []string{target}) {
		t.Errorf("start declared_delete_paths = %v, want %v", start.DeclaredDeletePaths, []string{target})
	}
	if len(end.WrittenPaths) != 0 {
		t.Errorf("end written_paths = %v, want a delete never recorded as a write", end.WrittenPaths)
	}
	if !reflect.DeepEqual(end.DeletedPaths, []string{target}) {
		t.Errorf("end deleted_paths = %v, want %v", end.DeletedPaths, []string{target})
	}
}

func TestDelegate_RecordsWritesAndDeletesInSeparateFields(t *testing.T) {
	h := newHarness(t)
	created := filepath.Join(h.dir, "a.txt")
	removed := filepath.Join(h.dir, "old.txt")
	writeWithMode(t, removed, "OLD\n", 0o644)
	createArgs := fmt.Sprintf(`{"path":%q,"content":"NEW\n"}`, created)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", filetools.CreateToolName, createArgs)),
		streamRound(toolCallChunkWithArgs("call_2", filetools.DeleteToolName, deleteCallArgs(removed))),
		streamRound(contentChunk("tidied up"), finishChunk()),
	}
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{
			create: filetools.NewCreateTool(h.deps.Home, h.dir, h.dir),
			remove: filetools.NewDeleteTool(h.deps.Home, h.dir, h.dir),
		}
	}

	res, err := h.tool().Invoke(t.Context(), declareArgs("tidy up", []string{"a.txt"}, []string{"old.txt"}))
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Invoke = exit %d, err %v; stderr=%q, want a clean completion", res.ExitCode, err, res.Stderr)
	}

	start, end, _ := h.onePair(t)
	if !reflect.DeepEqual(start.DeclaredPaths, []string{created}) || !reflect.DeepEqual(start.DeclaredDeletePaths, []string{removed}) {
		t.Errorf("start declared_paths/declared_delete_paths = %v / %v, want %v / %v", start.DeclaredPaths, start.DeclaredDeletePaths, []string{created}, []string{removed})
	}
	if !reflect.DeepEqual(end.WrittenPaths, []string{created}) || !reflect.DeepEqual(end.DeletedPaths, []string{removed}) {
		t.Errorf("end written_paths/deleted_paths = %v / %v, want %v / %v", end.WrittenPaths, end.DeletedPaths, []string{created}, []string{removed})
	}
}

func TestDelegate_RecordsASymlinkDeclaredInBothFormsAsItsTwoTargets(t *testing.T) {
	h := newHarness(t, streamRound(contentChunk("nothing to do"), finishChunk()))
	target := filepath.Join(h.dir, "target.txt")
	link := filepath.Join(h.dir, "link.txt")
	writeWithMode(t, target, "BODY\n", 0o644)
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if _, err := h.tool().Invoke(t.Context(), declareArgs("look", []string{"link.txt"}, []string{"link.txt"})); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}

	start, _, _ := h.onePair(t)
	if !reflect.DeepEqual(start.DeclaredPaths, []string{target}) {
		t.Errorf("start declared_paths = %v, want the write declaration to follow the link to %s", start.DeclaredPaths, target)
	}
	if !reflect.DeepEqual(start.DeclaredDeletePaths, []string{link}) {
		t.Errorf("start declared_delete_paths = %v, want the delete declaration to keep the link entry %s", start.DeclaredDeletePaths, link)
	}
}

func TestDelegate_RecordsACancelledChildWithItsRolledBackWrites(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.dir, "a.txt")
	createArgs := fmt.Sprintf(`{"path":%q,"content":"HALF DONE\n"}`, target)
	ctx, cancel := context.WithCancel(t.Context())
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", "create", createArgs)),
		streamRound(contentChunk("never arrives"), finishChunk()),
	}
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{create: filetools.NewCreateTool(h.deps.Home, h.dir, h.dir), onCall: cancel}
	}

	if _, err := h.tool().Invoke(ctx, callArgs("start the report", "a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}

	_, end, _ := h.onePair(t)
	if end.Reason != events.ChildAgentReasonCancelled {
		t.Fatalf("end reason = %q, want cancelled", end.Reason)
	}
	if end.RollbackOutcome != events.ChildRollbackRolledBack {
		t.Fatalf("end rollback_outcome = %q, want rolled_back", end.RollbackOutcome)
	}
	if !reflect.DeepEqual(end.WrittenPaths, []string{target}) {
		t.Fatalf("end written_paths = %v, want the path the child wrote before it was cancelled", end.WrittenPaths)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("os.Stat(%s) err = %v, want the cancelled child's write undone", target, err)
	}
}

func TestDelegate_RecordsStepCapAndFailureTerminalReasons(t *testing.T) {
	tests := []struct {
		name       string
		rounds     []func() (provider.Response, error)
		wantReason string
	}{
		{"step_cap", func() []func() (provider.Response, error) {
			rounds := make([]func() (provider.Response, error), subagent.DefaultStepCap)
			for i := range rounds {
				rounds[i] = streamRound(toolCallChunkWithArgs(fmt.Sprintf("call_%d", i), "read", alternatingEmptyArgs(i)))
			}
			return rounds
		}(), events.ChildAgentReasonStepCap},
		{"failed", []func() (provider.Response, error){
			func() (provider.Response, error) { return provider.Response{}, errors.New("provider is down") },
		}, events.ChildAgentReasonFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.rounds...)

			if _, err := h.tool().Invoke(t.Context(), callArgs("try it", "a.txt")); err != nil {
				t.Fatalf("Invoke error = %v, want nil", err)
			}
			_, end, _ := h.onePair(t)
			if end.Reason != tc.wantReason {
				t.Fatalf("end reason = %q, want %q", end.Reason, tc.wantReason)
			}
			if end.RollbackOutcome != events.ChildRollbackRolledBack {
				t.Fatalf("end rollback_outcome = %q, want rolled_back for a non-completed child", end.RollbackOutcome)
			}
			if len(end.WrittenPaths) != 0 {
				t.Fatalf("end written_paths = %v, want none for a child that wrote nothing", end.WrittenPaths)
			}
		})
	}
}

func TestRollbackOutcome_DerivesFromTheJournalReportBeforeTheReason(t *testing.T) {
	tests := []struct {
		name string
		res  subagent.Result
		want string
	}{
		{"completed", subagent.Result{Reason: subagent.ReasonCompleted}, events.ChildRollbackNotNeeded},
		{"cancelled and restored", subagent.Result{Reason: subagent.ReasonCancelled, RestoredPaths: []string{"/p/a.txt"}}, events.ChildRollbackRolledBack},
		{"step cap, nothing to restore", subagent.Result{Reason: subagent.ReasonStepCap}, events.ChildRollbackRolledBack},
		{"failed restore", subagent.Result{
			Reason:          subagent.ReasonCancelled,
			Unrecovered:     []string{"/p/a.txt: could not be restored"},
			RetainedJournal: "/home/u/.codemeld/journal.json",
		}, events.ChildRollbackUnrecovered},
		{"completed but the journal survived", subagent.Result{
			Reason:          subagent.ReasonCompleted,
			RetainedJournal: "/home/u/.codemeld/journal.json",
		}, events.ChildRollbackUnrecovered},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rollbackOutcome(tc.res); got != tc.want {
				t.Fatalf("rollbackOutcome() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDelegate_AStartAppendFailureStartsNoChild(t *testing.T) {
	h := newHarness(t, streamRound(contentChunk("done"), finishChunk()))
	h.storeAt = func(int) *sessions.Store { return nil }

	res, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want a failure when the child could not be recorded")
	}
	if !strings.Contains(string(res.Stderr), "no child agent started") {
		t.Fatalf("stderr = %q, want it to say no child agent started", res.Stderr)
	}
	if len(h.client.requests) != 0 {
		t.Fatalf("provider requests = %d, want 0: the child must not begin its first round", len(h.client.requests))
	}
	starts, ends, _ := h.childRecords(t)
	if len(starts) != 0 || len(ends) != 0 {
		t.Fatalf("persisted records = %d start / %d end, want none", len(starts), len(ends))
	}
}

// A store accessor that stops answering mid-run must not strand an appended start: the pair is
// written against the one store resolved before the start, so the end is never left to a second
// lookup that can fail on its own.
func TestDelegate_AStoreThatStopsAnsweringStillClosesTheLifecyclePair(t *testing.T) {
	h := newHarness(t, streamRound(contentChunk("done"), finishChunk()))
	h.storeAt = func(call int) *sessions.Store {
		if call == 1 {
			return h.store
		}
		return nil
	}

	res, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0: nothing failed once the store is resolved once; stderr=%q", res.ExitCode, res.Stderr)
	}
	starts, ends, raw := h.childRecords(t)
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("persisted records = %d start / %d end, want 1/1 (an unclosed start): %s", len(starts), len(ends), raw)
	}
	if starts[0].InvocationID != ends[0].InvocationID {
		t.Fatalf("invocation ids = %q/%q, want the end to close the start it belongs to", starts[0].InvocationID, ends[0].InvocationID)
	}
}

func TestDelegate_GivesEachChildItsOwnInvocationIDOnEveryAttributedPath(t *testing.T) {
	h := newHarness(t)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(contentChunk("first"), finishChunk()),
		streamRound(contentChunk("second"), finishChunk()),
	}
	tool := h.tool()

	for range 2 {
		if _, err := tool.Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
			t.Fatalf("Invoke error = %v, want nil", err)
		}
	}

	starts, ends, _ := h.childRecords(t)
	if len(starts) != 2 || len(ends) != 2 {
		t.Fatalf("persisted records = %d start / %d end, want two of each", len(starts), len(ends))
	}
	if starts[0].InvocationID == starts[1].InvocationID {
		t.Fatalf("both children recorded invocation id %q, want distinct ids", starts[0].InvocationID)
	}
	for i := range starts {
		if ends[i].InvocationID != starts[i].InvocationID {
			t.Errorf("end %d invocation_id = %q, want its start's %q", i, ends[i].InvocationID, starts[i].InvocationID)
		}
		if h.modeCtxs[i].ChildInvocationID != starts[i].InvocationID {
			t.Errorf("child %d dispatcher carried %q, want the recorded %q",
				i, h.modeCtxs[i].ChildInvocationID, starts[i].InvocationID)
		}
	}
}

func TestDelegate_ANestedCallCarriesTheIssuingChildsInvocationID(t *testing.T) {
	h := newHarness(t,
		streamRound(toolCallChunkWithArgs("call_1", ToolName, `{"instructions":"nested work","files":["a.txt"]}`)),
		streamRound(contentChunk("done"), finishChunk()),
	)

	if _, err := h.tool().Invoke(t.Context(), callArgs("delegate onward", "a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if len(h.modeCtxs) != 2 {
		t.Fatalf("dispatchers built = %d, want 2 (the child and its nested call)", len(h.modeCtxs))
	}
	start, _, _ := h.onePair(t)
	if h.modeCtxs[1].ChildInvocationID != start.InvocationID {
		t.Fatalf("nested call carried %q, want the issuing child's %q", h.modeCtxs[1].ChildInvocationID, start.InvocationID)
	}
}

func TestDelegate_RecordsUnrecoveredWhenTheRollbackFails(t *testing.T) {
	h := newHarness(t)
	sub := filepath.Join(h.dir, "reports")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(sub, "a.txt")
	createArgs := fmt.Sprintf(`{"path":%q,"content":"HALF DONE\n"}`, target)
	ctx, cancel := context.WithCancel(t.Context())
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", "create", createArgs)),
		streamRound(contentChunk("never arrives"), finishChunk()),
	}
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{create: filetools.NewCreateTool(h.deps.Home, h.dir, h.dir), onCall: func() {
			// A directory the child may no longer write is what makes the restore fail rather
			// than merely find nothing to undo.
			if err := os.Chmod(sub, 0o500); err != nil {
				t.Errorf("Chmod: %v", err)
			}
			cancel()
		}}
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })

	if _, err := h.tool().Invoke(ctx, callArgs("start the report", "reports/a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}

	_, end, _ := h.onePair(t)
	if end.Reason != events.ChildAgentReasonCancelled {
		t.Fatalf("end reason = %q, want cancelled", end.Reason)
	}
	if end.RollbackOutcome != events.ChildRollbackUnrecovered {
		t.Fatalf("end rollback_outcome = %q, want unrecovered: the child's write is still on disk", end.RollbackOutcome)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("os.Stat(%s) err = %v, want the unrestorable write still present", target, err)
	}
}

// liveActivity records the child lifecycle in arrival order, so a test can assert not only
// what the surface was told but when relative to the child's own work.
type liveActivity struct {
	log        []string
	starts     []events.ChildAgentStart
	ends       []events.ChildAgentEnd
	invocation []string
}

func (a *liveActivity) ChildAgentStarted(start events.ChildAgentStart) {
	a.starts = append(a.starts, start)
	a.log = append(a.log, "start:"+start.InvocationID)
}

func (a *liveActivity) ChildAgentCalls(invocation string, lines []string) {
	a.invocation = append(a.invocation, invocation)
	a.log = append(a.log, "calls:"+invocation+":"+strings.Join(lines, ","))
}

func (a *liveActivity) ChildAgentEnded(end events.ChildAgentEnd) {
	a.ends = append(a.ends, end)
	a.log = append(a.log, "end:"+end.InvocationID+":"+end.Reason)
}

// loggingDispatcher marks the point a child tool call actually runs, which is after the round
// that call belongs to has been reported.
type loggingDispatcher struct {
	inner *stubDispatcher
	log   *[]string
}

func (d *loggingDispatcher) Plan(calls []turn.AssembledToolCall, maxConcurrency int) turn.ToolPlan {
	plan := d.inner.Plan(calls, maxConcurrency)
	for i := range plan.Units {
		inner := plan.Units[i].Run
		call := plan.Units[i].Call
		plan.Units[i].Run = func(ctx context.Context) (turn.ToolResult, error) {
			*d.log = append(*d.log, "run:"+call.Name)
			return inner(ctx)
		}
	}
	return plan
}

func (d *loggingDispatcher) Dispatch(ctx context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	return d.inner.Dispatch(ctx, call)
}

// The surface learns the child exists before it does any work, sees each of its tool rounds
// while it is still running, and is closed with the recorded outcome — all under the one
// invocation id the session records.
func TestDelegate_ReportsTheChildLifecycleWhileItRuns(t *testing.T) {
	h := newHarness(t,
		streamRound(contentChunk("looking"), toolCallChunk("call_1", "read")),
		streamRound(contentChunk("done"), finishChunk()),
	)
	sink := &liveActivity{}
	h.deps.Activity = sink
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &loggingDispatcher{inner: &stubDispatcher{}, log: &sink.log}
	}

	if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}

	start, end, _ := h.onePair(t)
	want := []string{
		"start:" + start.InvocationID,
		"calls:" + start.InvocationID + ":read",
		"run:read",
		"end:" + end.InvocationID + ":" + string(subagent.ReasonCompleted),
	}
	if !slices.Equal(sink.log, want) {
		t.Fatalf("surface saw %v, want %v", sink.log, want)
	}
	if len(sink.starts) != 1 || !reflect.DeepEqual(sink.starts[0], start) {
		t.Fatalf("reported start = %+v, want the recorded %+v", sink.starts, start)
	}
	if len(sink.ends) != 1 || sink.ends[0].Steps != end.Steps || sink.ends[0].RollbackOutcome != end.RollbackOutcome {
		t.Fatalf("reported end = %+v, want the recorded %+v", sink.ends, end)
	}
}

// A child that never calls a tool still opens and closes its block, so a delegate that only
// answers is not left showing as running.
func TestDelegate_ReportsAChildThatMakesNoToolCalls(t *testing.T) {
	h := newHarness(t, streamRound(contentChunk("done"), finishChunk()))
	sink := &liveActivity{}
	h.deps.Activity = sink

	if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}

	start, end, _ := h.onePair(t)
	want := []string{"start:" + start.InvocationID, "end:" + end.InvocationID + ":" + string(subagent.ReasonCompleted)}
	if !slices.Equal(sink.log, want) {
		t.Fatalf("surface saw %v, want %v", sink.log, want)
	}
}

// Every precondition failure returns before the child's first round, so nothing may open a
// block for a child that never ran.
func TestDelegate_AChildThatNeverStartsReportsNothing(t *testing.T) {
	h := newHarness(t, streamRound(contentChunk("done"), finishChunk()))
	h.storeAt = func(int) *sessions.Store { return nil }
	sink := &liveActivity{}
	h.deps.Activity = sink

	if _, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if len(sink.log) != 0 {
		t.Fatalf("surface saw %v, want nothing for a child that never started", sink.log)
	}
}

// writeTargetDispatcher reports a write the child never declared, which is what an end record
// refuses: it is the one way to leave a start recorded with no end beside it.
type writeTargetDispatcher struct{ target string }

func (d writeTargetDispatcher) Plan(calls []turn.AssembledToolCall, _ int) turn.ToolPlan {
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	for i, call := range calls {
		plan.Units[i] = turn.PlannedToolCall{
			Call: call,
			Run:  func(ctx context.Context) (turn.ToolResult, error) { return d.Dispatch(ctx, call) },
		}
	}
	return plan
}

func (d writeTargetDispatcher) Dispatch(context.Context, turn.AssembledToolCall) (turn.ToolResult, error) {
	return turn.ToolResult{Content: "ok", WriteTarget: d.target}, nil
}

// An end record that could not be appended leaves the lifecycle unclosed in the session, but
// the block still closes from the in-process outcome rather than showing a child forever.
func TestDelegate_ClosesTheLiveBlockWhenTheEndRecordCannotBeAppended(t *testing.T) {
	h := newHarness(t,
		streamRound(toolCallChunk("call_1", "create")),
		streamRound(contentChunk("done"), finishChunk()),
	)
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return writeTargetDispatcher{target: filepath.Join(t.TempDir(), "outside.txt")}
	}
	sink := &liveActivity{}
	h.deps.Activity = sink

	res, err := h.tool().Invoke(t.Context(), callArgs("do it", "a.txt"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if !strings.Contains(string(res.Stderr), "could not be recorded in the session") {
		t.Fatalf("stderr = %q, want it to report the unrecorded outcome", res.Stderr)
	}
	starts, ends, _ := h.childRecords(t)
	if len(starts) != 1 || len(ends) != 0 {
		t.Fatalf("persisted records = %d start / %d end, want an unclosed start", len(starts), len(ends))
	}
	if len(sink.ends) != 1 {
		t.Fatalf("surface saw %d end notifications, want exactly one from the in-process outcome", len(sink.ends))
	}
	if sink.ends[0].Reason != string(subagent.ReasonCompleted) {
		t.Fatalf("reported reason = %q, want the in-process %q", sink.ends[0].Reason, subagent.ReasonCompleted)
	}
}

// A round in which the child delegates onward is still the issuing child's round, so it is
// reported under the issuing child's invocation id rather than the parent's.
func TestDelegate_ChildRoundsCarryTheIssuingChildsInvocationID(t *testing.T) {
	h := newHarness(t,
		streamRound(toolCallChunkWithArgs("call_1", ToolName, `{"instructions":"nested work","files":["a.txt"]}`)),
		streamRound(contentChunk("done"), finishChunk()),
	)
	sink := &liveActivity{}
	h.deps.Activity = sink

	if _, err := h.tool().Invoke(t.Context(), callArgs("delegate onward", "a.txt")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}

	start, _, _ := h.onePair(t)
	if len(sink.invocation) == 0 {
		t.Fatal("surface saw no child tool rounds")
	}
	for i, id := range sink.invocation {
		if id != start.InvocationID {
			t.Errorf("round %d carried %q, want the issuing child's %q", i, id, start.InvocationID)
		}
	}
}

func moveDeclareArgs(instruction string, write []string, pairs ...[2]string) map[string]any {
	args := declareArgs(instruction, write, nil)
	list := make([]any, 0, len(pairs))
	for _, pair := range pairs {
		list = append(list, map[string]any{sourceKey: pair[0], destinationKey: pair[1]})
	}
	args[filesMoveArg] = list
	return args
}

func moveCallArgs(source, destination string) string {
	return fmt.Sprintf(`{"source":%q,"destination":%q}`, source, destination)
}

func TestDelegate_PrepareResolvesMovePairsByTheMoveToolsEndpointContract(t *testing.T) {
	h := newHarness(t)
	home := filepath.Join(h.dir, "home")
	if err := os.MkdirAll(filepath.Join(home, "sub"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	h.deps.Home = home
	writeWithMode(t, filepath.Join(h.dir, "a.txt"), "A\n", 0o644)
	writeWithMode(t, filepath.Join(home, "sub", "b.txt"), "B\n", 0o644)

	tests := []struct {
		name string
		pair [2]string
		want permissions.MovePair
	}{
		{"relative", [2]string{"a.txt", "renamed.txt"}, permissions.MovePair{Source: filepath.Join(h.dir, "a.txt"), Destination: filepath.Join(h.dir, "renamed.txt")}},
		{"absolute", [2]string{filepath.Join(h.dir, "a.txt"), filepath.Join(h.dir, "renamed.txt")}, permissions.MovePair{Source: filepath.Join(h.dir, "a.txt"), Destination: filepath.Join(h.dir, "renamed.txt")}},
		{"home-relative", [2]string{"~/sub/b.txt", "~/sub/c.txt"}, permissions.MovePair{Source: filepath.Join(home, "sub", "b.txt"), Destination: filepath.Join(home, "sub", "c.txt")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, moves, _, targets, err := h.tool().PrepareDelegate(moveDeclareArgs("do it", nil, tc.pair))
			if err != nil {
				t.Fatalf("PrepareDelegate error = %v, want a move-only declaration accepted", err)
			}
			if want := map[permissions.MovePair]bool{tc.want: true}; !reflect.DeepEqual(moves, want) {
				t.Fatalf("move declaration = %v, want the canonical pair %v", moves, want)
			}
			if !slices.Contains(targets, tc.want.Source) || !slices.Contains(targets, tc.want.Destination) {
				t.Fatalf("scheduler targets = %v, want both endpoints of %v", targets, tc.want)
			}
		})
	}

	_, _, _, omitted, _, _, err := h.tool().PrepareDelegate(declareArgs("do it", []string{"a.txt"}, nil))
	if err != nil || omitted != nil {
		t.Fatalf("omitted files_move = %#v (err=%v), want nil", omitted, err)
	}
	_, _, _, empty, _, _, err := h.tool().PrepareDelegate(moveDeclareArgs("do it", []string{"a.txt"}))
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("supplied empty files_move = %#v (err=%v), want a non-nil empty set", empty, err)
	}
	if h.snapshotted != 0 {
		t.Fatalf("parent state snapshotted %d times, want 0 — preparation starts no child", h.snapshotted)
	}
}

func TestDelegate_RefusesAMoveDeclarationItCannotResolveBeforeAChildStarts(t *testing.T) {
	withExtraField := declareArgs("do it", nil, nil)
	withExtraField[filesMoveArg] = []any{map[string]any{sourceKey: "a.txt", destinationKey: "b.txt", "mode": "fast"}}
	notAnObject := declareArgs("do it", nil, nil)
	notAnObject[filesMoveArg] = []any{"a.txt"}
	tests := []struct {
		name string
		args map[string]any
		want string
	}{
		{"a destination that is another pair's source", moveDeclareArgs("do it", nil, [2]string{"a.txt", "b.txt"}, [2]string{"c.txt", "a.txt"}), "destination already exists"},
		{"a source that is another pair's destination", moveDeclareArgs("do it", nil, [2]string{"a.txt", "b.txt"}, [2]string{"b.txt", "d.txt"}), "source does not exist"},
		{"an existing destination", moveDeclareArgs("do it", nil, [2]string{"a.txt", "c.txt"}), "destination already exists"},
		{"a symlink source", moveDeclareArgs("do it", nil, [2]string{"link.txt", "b.txt"}), "symlink"},
		{"a destination outside the project", moveDeclareArgs("do it", nil, [2]string{"a.txt", "../outside.txt"}), "outside the project"},
		{"an empty source", moveDeclareArgs("do it", nil, [2]string{"  ", "b.txt"}), "must be non-empty"},
		{"an unsupported ~user form", moveDeclareArgs("do it", nil, [2]string{"~nobody/a.txt", "b.txt"}), "~user"},
		{"a pair with an extra field", withExtraField, "exactly the string fields"},
		{"a pair that is not an object", notAnObject, "exactly the string fields"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			writeWithMode(t, filepath.Join(h.dir, "a.txt"), "A\n", 0o644)
			writeWithMode(t, filepath.Join(h.dir, "c.txt"), "C\n", 0o644)
			if err := os.Symlink("a.txt", filepath.Join(h.dir, "link.txt")); err != nil {
				t.Fatalf("Symlink: %v", err)
			}

			res, err := h.tool().Invoke(t.Context(), tc.args)
			if err != nil {
				t.Fatalf("Invoke error = %v, want an in-band refusal", err)
			}
			if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), tc.want) {
				t.Fatalf("result = %+v (stderr %q), want a refusal naming %q", res, res.Stderr, tc.want)
			}
			if h.snapshotted != 0 || len(h.client.requests) != 0 {
				t.Fatalf("snapshots = %d, provider requests = %d; want no child started", h.snapshotted, len(h.client.requests))
			}
			if data, rerr := os.ReadFile(filepath.Join(h.dir, "a.txt")); rerr != nil || string(data) != "A\n" {
				t.Fatalf("a.txt = %q (err=%v), want it untouched", data, rerr)
			}
			if left := journalsLeft(t, h.deps.Home); len(left) != 0 {
				t.Fatalf("journal storage created for a refused declaration: %v", left)
			}
		})
	}
}

func TestDelegate_CarriesTheMoveDeclarationIntoTheChildAndItsNestedCalls(t *testing.T) {
	h := newHarness(t,
		streamRound(toolCallChunkWithArgs("call-1", ToolName, `{"instructions":"narrower","files_move":[{"source":"a.txt","destination":"b.txt"}]}`)),
		streamRound(contentChunk("done"), finishChunk()),
	)
	writeWithMode(t, filepath.Join(h.dir, "a.txt"), "A\n", 0o644)

	if _, err := h.tool().Invoke(t.Context(), moveDeclareArgs("do it", []string{"report.txt"}, [2]string{"a.txt", "b.txt"})); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if len(h.modeCtxs) != 2 {
		t.Fatalf("authorization contexts built = %d, want the child's own and the nested call's", len(h.modeCtxs))
	}
	want := map[permissions.MovePair]bool{{Source: filepath.Join(h.dir, "a.txt"), Destination: filepath.Join(h.dir, "b.txt")}: true}
	for i, mc := range h.modeCtxs {
		if !reflect.DeepEqual(mc.DeclaredMoves, want) {
			t.Fatalf("authorization context %d DeclaredMoves = %v, want the child's move pairs %v", i, mc.DeclaredMoves, want)
		}
	}
	if !reflect.DeepEqual(h.modeCtxs[1].DelegateMoves, want) {
		t.Fatalf("nested DelegateMoves = %v, want the resolved nested move pairs %v", h.modeCtxs[1].DelegateMoves, want)
	}
}

func TestDelegate_RecordsAMoveOnlyChildWithoutWriteOrDeleteAuthority(t *testing.T) {
	h := newHarness(t)
	source := filepath.Join(h.dir, "old.txt")
	destination := filepath.Join(h.dir, "new.txt")
	writeWithMode(t, source, "OLD\n", 0o644)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", filetools.MoveToolName, moveCallArgs(source, destination))),
		streamRound(contentChunk("renamed it"), finishChunk()),
	}
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{move: filetools.NewMoveTool(h.deps.Home, h.dir, h.dir)}
	}

	res, err := h.tool().Invoke(t.Context(), moveDeclareArgs("rename it", nil, [2]string{"old.txt", "new.txt"}))
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Invoke = exit %d, err %v; stderr=%q, want a clean completion", res.ExitCode, err, res.Stderr)
	}
	if data, rerr := os.ReadFile(destination); rerr != nil || string(data) != "OLD\n" {
		t.Fatalf("%s = %q (err=%v), want the moved file", destination, data, rerr)
	}

	start, end, _ := h.onePair(t)
	if len(start.DeclaredPaths) != 0 || len(start.DeclaredDeletePaths) != 0 {
		t.Errorf("start declared_paths/declared_delete_paths = %v / %v, want no write or delete authority for a move-only child", start.DeclaredPaths, start.DeclaredDeletePaths)
	}
	if len(end.WrittenPaths) != 0 || len(end.DeletedPaths) != 0 {
		t.Errorf("end written_paths/deleted_paths = %v / %v, want a move never recorded as a write or a delete", end.WrittenPaths, end.DeletedPaths)
	}
	wantPairs := []events.ChildMovePair{{Source: source, Destination: destination}}
	if !reflect.DeepEqual(start.DeclaredMovePairs, wantPairs) {
		t.Errorf("start declared_move_pairs = %v, want %v", start.DeclaredMovePairs, wantPairs)
	}
	if !reflect.DeepEqual(end.MovedPairs, wantPairs) {
		t.Errorf("end moved_pairs = %v, want %v", end.MovedPairs, wantPairs)
	}
}

func TestDelegate_UndoesTheMovesOfAChildThatDidNotComplete(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	h := newHarness(t)
	first := filepath.Join(h.dir, "first.txt")
	second := filepath.Join(h.dir, "second.sh")
	firstTo := filepath.Join(h.dir, "first-renamed.txt")
	secondTo := filepath.Join(h.dir, "second-renamed.sh")
	writeWithMode(t, first, "FIRST ORIGINAL\n", 0o640)
	writeWithMode(t, second, "#!/bin/sh\necho second\n", 0o755)
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", filetools.MoveToolName, moveCallArgs(first, firstTo))),
		streamRound(toolCallChunkWithArgs("call_2", filetools.MoveToolName, moveCallArgs(second, secondTo))),
		streamRound(contentChunk("never reached"), finishChunk()),
	}
	moved := 0
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{
			move: filetools.NewMoveTool(h.deps.Home, h.dir, h.dir),
			onCall: func() {
				moved = 0
				for _, path := range []string{firstTo, secondTo} {
					if _, err := os.Lstat(path); err == nil {
						moved++
					}
				}
				if moved == 2 {
					cancel()
				}
			},
		}
	}

	res, err := h.tool().Invoke(ctx, moveDeclareArgs("rename both", []string{"report.txt"}, [2]string{"first.txt", "first-renamed.txt"}, [2]string{"second.sh", "second-renamed.sh"}))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if moved != 2 {
		t.Fatalf("destinations the child moved into place = %d, want both before the cancel", moved)
	}
	out := string(res.Stdout)
	if res.ExitCode == 0 || !strings.Contains(out, "its changes were undone") {
		t.Fatalf("result = %q (exit %d), want a non-zero exit that says the child's work was undone", out, res.ExitCode)
	}
	for _, tc := range []struct {
		path, content string
		mode          os.FileMode
	}{
		{first, "FIRST ORIGINAL\n", 0o640},
		{second, "#!/bin/sh\necho second\n", 0o755},
	} {
		data, rerr := os.ReadFile(tc.path)
		if rerr != nil || string(data) != tc.content {
			t.Fatalf("%s = %q (err=%v), want its pre-run bytes %q", tc.path, data, rerr, tc.content)
		}
		info, serr := os.Lstat(tc.path)
		if serr != nil || info.Mode().Perm() != tc.mode {
			t.Fatalf("%s mode = %v (err=%v), want %o", tc.path, info, serr, tc.mode)
		}
	}
	for _, path := range []string{firstTo, secondTo} {
		if _, serr := os.Lstat(path); !os.IsNotExist(serr) {
			t.Fatalf("%s still exists (err=%v), want the destination absent as it was before the child", path, serr)
		}
	}
	for _, path := range []string{first, firstTo, second, secondTo} {
		if !strings.Contains(out, path) {
			t.Fatalf("result = %q, want it to name the restored endpoint %s", out, path)
		}
	}
	if left := journalsLeft(t, h.deps.Home); len(left) != 0 {
		t.Fatalf("journal storage left behind: %v", left)
	}
}

func TestDelegate_PrepareResolvesEveryDirectorySpellingToItsCanonicalTarget(t *testing.T) {
	h := newHarness(t)
	home := filepath.Join(h.dir, "home")
	for _, dir := range []string{home, filepath.Join(h.dir, "work")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	if err := os.Symlink(filepath.Join(h.dir, "work"), filepath.Join(h.dir, "worklink")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	h.deps.Home = home
	made := filepath.Join(h.dir, "made", "sub")

	tests := []struct {
		name, spelling, want string
	}{
		{"relative", "made/sub", made},
		{"normalized with a trailing separator", "./made/./sub/", made},
		{"traversal", "work/../made/sub", made},
		{"absolute", made, made},
		{"in-project symlink alias", "worklink/sub", filepath.Join(h.dir, "work", "sub")},
		{"home-relative", "~/made", filepath.Join(home, "made")},
		{"home itself", "~", home},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, dirs, targets, err := h.tool().PrepareDelegate(mkdirDeclareArgs("do it", []string{"a.txt"}, tc.spelling))
			if err != nil {
				t.Fatalf("PrepareDelegate error = %v, want the directory accepted", err)
			}
			if want := map[string]bool{tc.want: true}; !reflect.DeepEqual(dirs, want) {
				t.Fatalf("directory declaration = %v, want the canonical target %v", dirs, want)
			}
			if !slices.Contains(targets, tc.want) {
				t.Fatalf("scheduler targets = %v, want the directory %s", targets, tc.want)
			}
		})
	}

	_, _, _, _, dirs, _, err := h.tool().PrepareDelegate(mkdirDeclareArgs("do it", []string{"a.txt"}, "made/sub", "./made/sub/", made))
	if err != nil || !reflect.DeepEqual(dirs, map[string]bool{made: true}) {
		t.Fatalf("equivalent spellings = %v (err=%v), want one canonical entry %s", dirs, err, made)
	}
	_, _, _, _, omitted, _, err := h.tool().PrepareDelegate(declareArgs("do it", []string{"a.txt"}, nil))
	if err != nil || omitted != nil {
		t.Fatalf("omitted files_mkdir = %#v (err=%v), want nil", omitted, err)
	}
	_, _, _, _, empty, _, err := h.tool().PrepareDelegate(mkdirDeclareArgs("do it", []string{"a.txt"}))
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("supplied empty files_mkdir = %#v (err=%v), want a non-nil empty set", empty, err)
	}
	if h.snapshotted != 0 {
		t.Fatalf("parent state snapshotted %d times, want 0 — preparation starts no child", h.snapshotted)
	}
}

func TestDelegate_SchedulerTargetsAddTheMissingParentsOfDeclaredDirectoriesAsOrderingOnly(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(filepath.Join(h.dir, "work"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	_, _, _, _, dirs, targets, err := h.tool().PrepareDelegate(mkdirDeclareArgs("do it", []string{"a.txt"}, "x/y", "x/z", "work/new"))
	if err != nil {
		t.Fatalf("PrepareDelegate error = %v, want nil", err)
	}
	want := []string{filepath.Join(h.dir, "a.txt"), filepath.Join(h.dir, "work", "new"), filepath.Join(h.dir, "x"), filepath.Join(h.dir, "x", "y"), filepath.Join(h.dir, "x", "z")}
	if !slices.Equal(targets, want) {
		t.Fatalf("scheduler targets = %v, want %v", targets, want)
	}
	if dirs[filepath.Join(h.dir, "x")] {
		t.Fatalf("directory declaration = %v, want the shared missing parent kept out of the ceiling", dirs)
	}
}

func TestDelegate_CarriesTheDirectoryDeclarationIntoTheChildAndItsNestedCalls(t *testing.T) {
	h := newHarness(t,
		streamRound(toolCallChunkWithArgs("call-1", ToolName, `{"instructions":"narrower","files":["report.txt"],"files_mkdir":["made"]}`)),
		streamRound(contentChunk("done"), finishChunk()),
	)

	if _, err := h.tool().Invoke(t.Context(), mkdirDeclareArgs("do it", []string{"report.txt"}, "made")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if len(h.modeCtxs) != 2 {
		t.Fatalf("authorization contexts built = %d, want the child's own and the nested call's", len(h.modeCtxs))
	}
	want := map[string]bool{filepath.Join(h.dir, "made"): true}
	for i, mc := range h.modeCtxs {
		if !reflect.DeepEqual(mc.DeclaredDirs, want) {
			t.Fatalf("authorization context %d DeclaredDirs = %v, want the child's directories %v", i, mc.DeclaredDirs, want)
		}
	}
	if !reflect.DeepEqual(h.modeCtxs[1].DelegateDirs, want) {
		t.Fatalf("nested DelegateDirs = %v, want the resolved nested directories %v", h.modeCtxs[1].DelegateDirs, want)
	}

	for _, tc := range []struct {
		name    string
		args    map[string]any
		wantNil bool
	}{
		{"omitted", declareArgs("do it", []string{"report.txt"}, nil), true},
		{"supplied empty", mkdirDeclareArgs("do it", []string{"report.txt"}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, streamRound(contentChunk("done"), finishChunk()))
			if _, err := h.tool().Invoke(t.Context(), tc.args); err != nil {
				t.Fatalf("Invoke error = %v, want nil", err)
			}
			if got := h.modeCtxs[0].DeclaredDirs; (got == nil) != tc.wantNil || len(got) != 0 {
				t.Fatalf("child DeclaredDirs = %#v, want nil=%v and empty", got, tc.wantNil)
			}
		})
	}
}

func TestDelegate_KeepsTheDeclaredDirectoryOfACompletedChild(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.dir, "made", "sub")
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", filetools.MkdirToolName, fmt.Sprintf(`{"path":%q}`, target))),
		streamRound(contentChunk("made it"), finishChunk()),
	}
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{mkdir: filetools.NewMkdirTool(h.deps.Home, h.dir, h.dir)}
	}

	res, err := h.tool().Invoke(t.Context(), mkdirDeclareArgs("make it", []string{"report.txt"}, "made/sub"))
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Invoke = exit %d, err %v; stdout=%q stderr=%q, want a clean completion", res.ExitCode, err, res.Stdout, res.Stderr)
	}
	if info, serr := os.Stat(target); serr != nil || !info.IsDir() {
		t.Fatalf("%s = %v (err=%v), want the child's directory kept", target, info, serr)
	}
	if left := journalsLeft(t, h.deps.Home); len(left) != 0 {
		t.Fatalf("journal storage left behind: %v", left)
	}
}

func TestDelegate_UndoesTheDeclaredDirectoryOfAChildThatDidNotComplete(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	h := newHarness(t)
	target := filepath.Join(h.dir, "made", "sub")
	h.client.rounds = []func() (provider.Response, error){
		streamRound(toolCallChunkWithArgs("call_1", filetools.MkdirToolName, fmt.Sprintf(`{"path":%q}`, target))),
		streamRound(contentChunk("never reached"), finishChunk()),
	}
	h.override = func(permissions.ModeContext) turn.ToolDispatcher {
		return &writingDispatcher{mkdir: filetools.NewMkdirTool(h.deps.Home, h.dir, h.dir), onCall: cancel}
	}

	res, err := h.tool().Invoke(ctx, mkdirDeclareArgs("make it", []string{"report.txt"}, "made/sub"))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want non-zero for a child that did not complete; stdout=%q", res.Stdout)
	}
	if _, serr := os.Lstat(filepath.Join(h.dir, "made")); !os.IsNotExist(serr) {
		t.Fatalf("made still exists (err=%v), want the declared directory and its created parent removed", serr)
	}
	if left := journalsLeft(t, h.deps.Home); len(left) != 0 {
		t.Fatalf("journal storage left behind: %v", left)
	}
}

func TestDelegate_StartsADirectoryOnlyChildAndRecordsItsDirectories(t *testing.T) {
	for _, tc := range []struct {
		name     string
		complete bool
	}{
		{"completed child keeps the directory", true},
		{"cancelled child has the directory rolled back", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h := newHarness(t)
			target := filepath.Join(h.dir, "made", "sub")
			h.client.rounds = []func() (provider.Response, error){
				streamRound(toolCallChunkWithArgs("call_1", filetools.MkdirToolName, fmt.Sprintf(`{"path":%q}`, target))),
				streamRound(contentChunk("made it"), finishChunk()),
			}
			var bound filetools.WriteJournal
			h.override = func(permissions.ModeContext) turn.ToolDispatcher {
				d := &writingDispatcher{
					mkdir:    filetools.NewMkdirTool(h.deps.Home, h.dir, h.dir),
					onSeeCtx: func(ctx context.Context) { bound = filetools.WriteJournalFromContext(ctx) },
				}
				if !tc.complete {
					d.onCall = cancel
				}
				return d
			}

			instruction, write, remove, moves, dirs, _, err := h.tool().PrepareDelegate(mkdirDeclareArgs("make it", nil, "made/sub"))
			if err != nil {
				t.Fatalf("PrepareDelegate error = %v, want a directory-only delegate admitted", err)
			}
			want := map[string]bool{target: true}
			if !reflect.DeepEqual(dirs, want) {
				t.Fatalf("prepared directories = %v, want %v", dirs, want)
			}
			res, err := h.tool().InvokeWithPreparedDelegate(ctx, instruction, write, remove, moves, dirs)
			if err != nil {
				t.Fatalf("Invoke error = %v, want nil", err)
			}
			if (res.ExitCode == 0) != tc.complete {
				t.Fatalf("ExitCode = %d, want success only for a completed child; stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
			}
			if !reflect.DeepEqual(h.modeCtxs[0].DeclaredDirs, want) {
				t.Fatalf("child DeclaredDirs = %v, want %v", h.modeCtxs[0].DeclaredDirs, want)
			}
			if _, ok := bound.(*subagent.Journal); !ok {
				t.Fatalf("dispatch context journal = %T, want the child's *subagent.Journal", bound)
			}
			_, serr := os.Lstat(filepath.Join(h.dir, "made"))
			if tc.complete && serr != nil {
				t.Fatalf("made = %v, want the completed child's directory kept", serr)
			}
			if !tc.complete && !os.IsNotExist(serr) {
				t.Fatalf("made still exists (err=%v), want the cancelled child's directory removed", serr)
			}

			start, _, _ := h.onePair(t)
			if !reflect.DeepEqual(start.DeclaredDirs, []string{target}) {
				t.Errorf("start declared_dirs = %v, want [%s]", start.DeclaredDirs, target)
			}
			if len(start.DeclaredPaths)+len(start.DeclaredDeletePaths)+len(start.DeclaredMovePairs) != 0 {
				t.Errorf("start carries write/delete/move authority %v / %v / %v, want none", start.DeclaredPaths, start.DeclaredDeletePaths, start.DeclaredMovePairs)
			}
		})
	}
}

func TestDelegate_CarriesADirectoryOnlyDeclarationIntoANestedCall(t *testing.T) {
	h := newHarness(t,
		streamRound(toolCallChunkWithArgs("call-1", ToolName, `{"instructions":"narrower","files_mkdir":["made"]}`)),
		streamRound(contentChunk("done"), finishChunk()),
	)

	if _, err := h.tool().Invoke(t.Context(), mkdirDeclareArgs("do it", nil, "made")); err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if len(h.modeCtxs) != 2 {
		t.Fatalf("authorization contexts built = %d, want the child's own and the nested call's", len(h.modeCtxs))
	}
	want := map[string]bool{filepath.Join(h.dir, "made"): true}
	if !reflect.DeepEqual(h.modeCtxs[1].DeclaredDirs, want) || !reflect.DeepEqual(h.modeCtxs[1].DelegateDirs, want) {
		t.Fatalf("nested DeclaredDirs/DelegateDirs = %v / %v, want %v for both", h.modeCtxs[1].DeclaredDirs, h.modeCtxs[1].DelegateDirs, want)
	}
}

func TestDelegate_AnOverCapDirectoryDeclarationStartsNoChild(t *testing.T) {
	h := newHarness(t)
	dirs := make([]any, 33)
	for i := range dirs {
		dirs[i] = fmt.Sprintf("d%02d", i)
	}
	res, err := h.tool().Invoke(t.Context(), mkdirDeclareArgs("make them", nil, dirs...))
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "no child agent started") {
		t.Fatalf("Invoke = exit %d stdout=%q stderr=%q, want the over-cap directory list refused", res.ExitCode, res.Stdout, res.Stderr)
	}
	if len(h.client.requests) != 0 {
		t.Fatalf("provider requests = %d, want no child turn", len(h.client.requests))
	}
}
