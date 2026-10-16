// Tests for the /connect handler: reserved-provider and unknown-provider
// rejection with retained input and a durable slash_command{outcome:error}, the
// masked-prompt path recording slash_command{connect,success} only after the submitted
// key's write succeeds, a cancelled prompt recording nothing, the failed-write path
// recording a durable slash_command{connect,error} (never a success), and the guarantee
// that neither the entered key nor a deps-owned secret reaches any notice or event —
// all driven through an injected ConnectDeps fake whose PromptAPIKey stands in for the
// masked prompt.
package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// connectDepsFake is an in-memory ConnectDeps. known lists the ids IsProvider
// accepts. PromptAPIKey stands in for the masked prompt: unless cancel is set it
// hands submitKey to onSubmit synchronously (so the whole connect completes inside the
// dispatch call), else it runs onCancel. connectErr is returned by Connect. When host
// is set, Connect snapshots the notice/event counts at call time so ordering (append
// after the write and after any visible notice) can be asserted. secret is a value
// that must never surface in a notice or event.
type connectDepsFake struct {
	known            map[string]bool
	connectable      []ConnectProviderOption
	pickerCalls      int
	pickerOptions    []ConnectProviderOption
	pickerSelect     func(id string)
	manualKey        bool
	submitKey        string
	cancel           bool
	connectErr       error
	promptCalls      int
	promptedID       string
	connectCalls     int
	gotID            string
	gotKey           string
	host             *fakeHost
	eventsAtConnect  int
	noticesAtConnect int
	secret           string
	deferConnect     bool
	completeConnect  func()
}

func (f *connectDepsFake) IsProvider(id string) bool { return f.known != nil && f.known[id] }

func (f *connectDepsFake) ConnectableProviders() []ConnectProviderOption { return f.connectable }

func (f *connectDepsFake) OpenConnectPicker(options []ConnectProviderOption, onSelect func(id string)) {
	f.pickerCalls++
	f.pickerOptions = append([]ConnectProviderOption(nil), options...)
	f.pickerSelect = onSelect
}

func (f *connectDepsFake) NeedsManualKey(string) bool { return f.manualKey }

func (f *connectDepsFake) PromptAPIKey(id string, onSubmit func(string), onCancel func()) {
	f.promptCalls++
	f.promptedID = id
	if f.cancel {
		if onCancel != nil {
			onCancel()
		}
		return
	}
	onSubmit(f.submitKey)
}

func (f *connectDepsFake) Connect(id, key string, onComplete func(error)) {
	f.connectCalls++
	f.gotID = id
	f.gotKey = key
	if f.host != nil {
		f.eventsAtConnect = len(f.host.events())
		f.noticesAtConnect = len(f.host.notices)
	}
	if f.deferConnect {
		f.completeConnect = func() { onComplete(f.connectErr) }
		return
	}
	onComplete(f.connectErr)
}

// dispatchConnect builds a one-command registry for /connect and dispatches input,
// wiring the host into the fake so Connect can observe ordering.
func dispatchConnect(t *testing.T, deps *connectDepsFake, input string) (*fakeHost, DispatchResult) {
	t.Helper()
	host := newFakeHost()
	deps.host = host
	reg, err := NewRegistry([]Command{
		{Name: "connect", Description: "Set up a provider by entering its API key", ArgSig: ArgOneOptional, Phase: PhaseTwo, Handler: NewConnectHandler(deps)},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return host, reg.DispatchSlashInput(input, host)
}

func TestConnectProgressDrawsBeforeBackgroundWork(t *testing.T) {
	a := New(nil)
	screen := tcell.NewSimulationScreen("UTF-8")
	a.newScreen = func() (tcell.Screen, error) { return screen, nil }
	errC := make(chan error, 1)
	go func() { errC <- a.Run() }()
	waitLoopRunning(t, a)

	rendered := make(chan string, 1)
	release := make(chan struct{})
	completed := make(chan struct{})
	a.app.QueueUpdateDraw(func() {
		a.Notice("checking the venice API key by loading its models...")
		a.RunBackgroundAfterDraw(func() error {
			rendered <- screenText(screen)
			<-release
			return nil
		}, func(error) { close(completed) })
	})

	select {
	case got := <-rendered:
		if !strings.Contains(got, "checking the venice API key by loading its models") {
			close(release)
			a.Stop()
			t.Fatalf("screen before background work = %q, want Venice progress", got)
		}
	case <-time.After(2 * time.Second):
		close(release)
		a.Stop()
		t.Fatal("background connect work did not start")
	}
	close(release)
	select {
	case <-completed:
	case <-time.After(2 * time.Second):
		a.Stop()
		t.Fatal("background connect completion did not return to the event loop")
	}
	a.Stop()
	if err := <-errC; err != nil {
		t.Fatalf("App.Run: %v", err)
	}
}

func TestConnectHandler_SuccessEventOrder(t *testing.T) {
	const key = "key-entered-at-the-prompt"
	deps := &connectDepsFake{known: map[string]bool{"openai": true}, submitKey: key, deferConnect: true}
	host, res := dispatchConnect(t, deps, "/connect openai")

	if res.Status != StatusHandled || res.Canonical != "connect" || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/connect/nil-err", res)
	}
	if res.RetainInput {
		t.Error("RetainInput = true on success, want false (the prompt path never retains)")
	}
	if deps.promptCalls != 1 || deps.promptedID != "openai" {
		t.Errorf("PromptAPIKey calls=%d id=%q, want 1 call for %q", deps.promptCalls, deps.promptedID, "openai")
	}
	if deps.connectCalls != 1 || deps.gotID != "openai" || deps.gotKey != key {
		t.Errorf("Connect calls=%d id=%q key=%q, want 1 call with %q and the entered key", deps.connectCalls, deps.gotID, deps.gotKey, "openai")
	}
	// No event and no notice exist at the write: the success event is recorded only
	// after Connect returns nil, so a failed write can never leave a success record
	// behind for a later flush to make durable.
	if deps.eventsAtConnect != 0 {
		t.Errorf("events at Connect = %d, want 0 (success recorded only after the write)", deps.eventsAtConnect)
	}
	if deps.noticesAtConnect != 1 {
		t.Errorf("notices at Connect = %d, want 1 (immediate progress feedback before the write)", deps.noticesAtConnect)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Fatalf("events before Connect completion = %v, want none", evs)
	}
	deps.completeConnect()
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "connect" || p.Outcome != "success" || p.ErrorDetail != "" || !equalStrings(p.Args, []string{"openai"}) {
		t.Errorf("event = %+v, want name=connect args=[openai] outcome=success error_detail=\"\"", p)
	}
	if host.flushes != 1 {
		t.Errorf("FlushActive called %d times, want 1 (success event flushed durable)", host.flushes)
	}
	if len(host.notices) != 2 || !strings.Contains(host.notices[0], "connecting provider openai") || !strings.Contains(host.notices[1], "connected provider openai") {
		t.Errorf("notices = %v, want an immediate progress notice then a connected-provider notice", host.notices)
	}
	// The key entered at the prompt reaches only deps.Connect: it must appear in no
	// event payload and no notice.
	for _, ev := range evs {
		if strings.Contains(string(ev.Payload), key) {
			t.Error("an event payload leaks the entered API key")
		}
	}
	for _, n := range host.notices {
		if strings.Contains(n, key) {
			t.Error("a notice leaks the entered API key")
		}
	}
}

// TestConnectHandler_PersistFailureRecordsError drives a submitted key whose Connect
// fails: no success event is appended before the write, exactly one durable
// slash_command{connect,error} is recorded (flushed, non-empty detail), and no false
// success can be flushed later. The failure surfaces on the event-loop callback after
// dispatch returned, so it is reported through the recorded event, not res.Err.
func TestConnectHandler_PersistFailureRecordsError(t *testing.T) {
	deps := &connectDepsFake{known: map[string]bool{"openai": true}, submitKey: "k", connectErr: errors.New("write blew up")}
	host, res := dispatchConnect(t, deps, "/connect openai")

	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled with nil err (the write failure is reported via the recorded event, not res.Err)", res)
	}
	if deps.connectCalls != 1 {
		t.Errorf("Connect calls = %d, want 1 (the submitted key was written)", deps.connectCalls)
	}
	// The success would be appended only after a successful write, so a failed write
	// leaves no false success for a later flush to make durable.
	if deps.eventsAtConnect != 0 {
		t.Errorf("events at Connect = %d, want 0 (no success appended before the write)", deps.eventsAtConnect)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want exactly 1 error event", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "connect" || p.Outcome != "error" || p.ErrorDetail == "" {
		t.Errorf("event = %+v, want name=connect outcome=error with a non-empty error_detail", p)
	}
	if host.flushes != 1 {
		t.Errorf("FlushActive called %d times, want 1 (error event flushed durable)", host.flushes)
	}
}

// TestConnectHandler_PromptCancel drives a cancelled prompt: no key is submitted, so
// deps.Connect is never called, no slash_command event is recorded, nothing is
// flushed, and the user sees a single static cancellation notice. A cancelled prompt
// claims no connection.
func TestConnectHandler_PromptCancel(t *testing.T) {
	deps := &connectDepsFake{known: map[string]bool{"openai": true}, cancel: true, secret: "sk-typed-then-cancelled"}
	host, res := dispatchConnect(t, deps, "/connect openai")

	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled with nil err", res)
	}
	if deps.promptCalls != 1 {
		t.Errorf("PromptAPIKey calls = %d, want 1", deps.promptCalls)
	}
	if deps.connectCalls != 0 {
		t.Errorf("Connect calls = %d, want 0 on cancel (no connection attempted)", deps.connectCalls)
	}
	if len(host.events()) != 0 {
		t.Errorf("appended %d slash_command events on cancel, want 0 (no false success or error)", len(host.events()))
	}
	if host.flushes != 0 {
		t.Errorf("FlushActive called %d times on cancel, want 0", host.flushes)
	}
	if len(host.notices) != 1 || !strings.Contains(host.notices[0], "cancelled") {
		t.Errorf("notices = %v, want one cancellation notice", host.notices)
	}
}

func TestConnectHandler_ReservedProviderRejected(t *testing.T) {
	deps := &connectDepsFake{known: map[string]bool{reservedConnectProviderID: true}}
	host, res := dispatchConnect(t, deps, "/connect "+reservedConnectProviderID)

	if !res.RetainInput {
		t.Error("RetainInput = false, want true so the typed input is retained on rejection")
	}
	if deps.promptCalls != 0 {
		t.Errorf("PromptAPIKey called %d times for the reserved provider, want 0 (rejected before any prompt)", deps.promptCalls)
	}
	if deps.connectCalls != 0 {
		t.Errorf("Connect called %d times for the reserved provider, want 0", deps.connectCalls)
	}
	if len(host.notices) != 1 || !strings.Contains(host.notices[0], reservedConnectProviderID) {
		t.Errorf("notices = %v, want one mentioning the reserved provider", host.notices)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1 error event", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Outcome != "error" || p.ErrorDetail == "" {
		t.Errorf("event = %+v, want outcome=error with a non-empty error_detail", p)
	}
	if host.flushes != 1 {
		t.Errorf("FlushActive called %d times, want 1 (error event flushed before return)", host.flushes)
	}
}

func TestConnectHandler_UnknownProviderRejected(t *testing.T) {
	deps := &connectDepsFake{known: map[string]bool{"openai": true}}
	host, res := dispatchConnect(t, deps, "/connect bogus")

	if !res.RetainInput {
		t.Error("RetainInput = false, want true so the typed input is retained on rejection")
	}
	if deps.promptCalls != 0 {
		t.Errorf("PromptAPIKey called %d times for an unknown provider, want 0 (rejected before any prompt)", deps.promptCalls)
	}
	if deps.connectCalls != 0 {
		t.Errorf("Connect called %d times for an unknown provider, want 0", deps.connectCalls)
	}
	// The notice is static: it must not echo the typed id, so a secret-shaped
	// argument cannot leak into it.
	if len(host.notices) != 1 || strings.Contains(host.notices[0], "bogus") {
		t.Errorf("notices = %v, want one static notice that does not echo the typed id", host.notices)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1 error event", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "connect" || p.Outcome != "error" || p.ErrorDetail == "" || len(p.Args) != 0 {
		t.Errorf("event = %+v, want name=connect outcome=error, non-empty error_detail, no args", p)
	}
	if host.flushes != 1 {
		t.Errorf("FlushActive called %d times, want 1 (error event flushed before return)", host.flushes)
	}
}

// TestConnectHandler_BareOpensPickerThenSelectionRunsDirectFlow drives a bare
// /connect: it reaches the handler, opens the provider picker with secret-free rows,
// and records nothing until a row is selected. Selection then runs the same direct
// connect flow as /connect <provider>, including the selected provider id in the event.
func TestConnectHandler_BareOpensPickerThenSelectionRunsDirectFlow(t *testing.T) {
	deps := &connectDepsFake{
		known:       map[string]bool{"openai": true, "venice": true},
		submitKey:   "sk-picker-selection",
		connectable: []ConnectProviderOption{{ID: "openai", Label: "openai"}, {ID: "venice", Label: "venice"}},
	}
	host, res := dispatchConnect(t, deps, "/connect")

	if res.Status != StatusHandled || res.Canonical != "connect" || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/connect/nil-err (bare path reaches the handler)", res)
	}
	if res.RetainInput {
		t.Error("RetainInput = true, want false so the bare command clears after opening the picker")
	}
	if deps.pickerCalls != 1 || deps.pickerSelect == nil {
		t.Fatalf("picker calls=%d select nil=%v, want one picker open with a selection callback", deps.pickerCalls, deps.pickerSelect == nil)
	}
	if len(deps.pickerOptions) != 2 || deps.pickerOptions[0].ID != "openai" || deps.pickerOptions[1].ID != "venice" {
		t.Fatalf("picker options = %+v, want openai then venice", deps.pickerOptions)
	}
	if deps.promptCalls != 0 || deps.connectCalls != 0 {
		t.Errorf("prompt=%d connect=%d before selection, want 0/0", deps.promptCalls, deps.connectCalls)
	}
	if len(host.events()) != 0 {
		t.Errorf("appended %d slash_command events before selection, want 0", len(host.events()))
	}
	if host.flushes != 0 {
		t.Errorf("FlushActive called %d times before selection, want 0", host.flushes)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices before selection = %v, want none", host.notices)
	}

	deps.pickerSelect("venice")

	if deps.promptCalls != 1 || deps.promptedID != "venice" {
		t.Errorf("PromptAPIKey calls=%d id=%q, want one prompt for venice", deps.promptCalls, deps.promptedID)
	}
	if deps.connectCalls != 1 || deps.gotID != "venice" || deps.gotKey != "sk-picker-selection" {
		t.Errorf("Connect calls=%d id=%q key=%q, want one connect for venice with submitted key", deps.connectCalls, deps.gotID, deps.gotKey)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events after selection, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "connect" || p.Outcome != "success" || !equalStrings(p.Args, []string{"venice"}) {
		t.Errorf("event = %+v, want name=connect args=[venice] outcome=success", p)
	}
}

// TestConnectHandler_BarePickerCancelNoSideEffects proves merely opening and then
// abandoning the picker records nothing: no prompt, no Connect call, no event, no flush,
// and no notice.
func TestConnectHandler_BarePickerCancelNoSideEffects(t *testing.T) {
	deps := &connectDepsFake{
		known:       map[string]bool{"openai": true, "venice": true},
		connectable: []ConnectProviderOption{{ID: "openai", Label: "openai"}, {ID: "venice", Label: "venice"}},
	}
	host, res := dispatchConnect(t, deps, "/connect")

	if res.Status != StatusHandled || res.Canonical != "connect" || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/connect/nil-err (bare path reaches the handler)", res)
	}
	if res.RetainInput {
		t.Error("RetainInput = true, want false after opening the picker")
	}
	if deps.pickerCalls != 1 || deps.pickerSelect == nil {
		t.Fatalf("picker calls=%d select nil=%v, want one picker open", deps.pickerCalls, deps.pickerSelect == nil)
	}
	// Do not invoke pickerSelect: this simulates ESC/cancel at the picker layer.
	if deps.promptCalls != 0 || deps.connectCalls != 0 {
		t.Errorf("prompt=%d connect=%d, want 0/0 when the picker is cancelled", deps.promptCalls, deps.connectCalls)
	}
	if len(host.events()) != 0 {
		t.Errorf("appended %d slash_command events, want 0 on picker cancel", len(host.events()))
	}
	if host.flushes != 0 {
		t.Errorf("FlushActive called %d times, want 0 on picker cancel", host.flushes)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none on picker cancel", host.notices)
	}
}

func TestConnectHandler_BarePickerSelectionFailureRecordsError(t *testing.T) {
	const secret = "sk-picker-failure-secret"
	deps := &connectDepsFake{
		known:       map[string]bool{"venice": true},
		connectable: []ConnectProviderOption{{ID: "venice", Label: "venice"}},
		submitKey:   secret,
		connectErr:  errors.New(secret),
	}
	host, res := dispatchConnect(t, deps, "/connect")
	if res.Status != StatusHandled || res.Err != nil || deps.pickerSelect == nil {
		t.Fatalf("dispatch = %+v pickerSelect nil=%v, want picker-open handled path", res, deps.pickerSelect == nil)
	}

	deps.pickerSelect("venice")

	if deps.connectCalls != 1 || deps.gotKey != secret {
		t.Fatalf("Connect calls=%d key=%q, want one call with submitted secret", deps.connectCalls, deps.gotKey)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want one error event", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "connect" || p.Outcome != "error" || p.ErrorDetail != errConnectFailed.Error() || !equalStrings(p.Args, []string{"venice"}) {
		t.Errorf("event = %+v, want connect [venice] error with static detail", p)
	}
	for _, ev := range evs {
		if strings.Contains(string(ev.Payload), secret) {
			t.Error("an event payload leaks the submitted secret")
		}
	}
}

// TestConnect_WrongArityRejected checks the registered /connect metadata: a multi-arg
// invocation is rejected pre-handler with retained input and no event, against the
// real BuildRegistry. Bare /connect is no longer wrong arity — it now reaches the
// handler (see TestConnectHandler_BareOpensPickerThenSelectionRunsDirectFlow).
func TestConnect_WrongArityRejected(t *testing.T) {
	host := newFakeHost()
	res := BuildRegistry(nil).DispatchSlashInput("/connect a b", host)
	if res.Status != StatusWrongArity || res.Canonical != "connect" || !res.RetainInput {
		t.Errorf("dispatch = %+v, want WrongArity/connect/retain", res)
	}
	if len(host.events()) != 0 {
		t.Errorf("dispatch appended %d events, want 0", len(host.events()))
	}
}

// TestConnectPlaceholder_NoSuccess drives the production BuildRegistry(nil), whose
// /connect is the unbound placeholder until real deps are wired. A valid-arity
// /connect must not record a success event or clear input; it shows a notice and
// retains the typed input so it never pretends a provider was connected.
func TestConnectPlaceholder_NoSuccess(t *testing.T) {
	host := newFakeHost()
	res := BuildRegistry(nil).DispatchSlashInput("/connect openai", host)

	if res.Status != StatusHandled || res.Canonical != "connect" {
		t.Errorf("dispatch = %+v, want Handled/connect", res)
	}
	if !res.RetainInput {
		t.Error("RetainInput = false, want true (unbound placeholder keeps the typed input)")
	}
	if len(host.events()) != 0 {
		t.Errorf("placeholder appended %d events, want 0 (no success recorded)", len(host.events()))
	}
	if len(host.notices) != 1 {
		t.Errorf("notices = %v, want one unavailable notice", host.notices)
	}
}

// TestConnectHandler_NoSecretLeak submits the secret sentinel as the entered key to a
// fake whose Connect also fails with a secret-shaped error; neither the key nor the
// failure text may reach any notice or recorded event. The failure surfaces via the
// recorded error event (the static errConnectFailed detail), not res.Err.
func TestConnectHandler_NoSecretLeak(t *testing.T) {
	const secret = "sk-live-SUPERSECRET-should-never-render"
	deps := &connectDepsFake{
		known:      map[string]bool{"openai": true},
		submitKey:  secret,
		connectErr: errors.New(secret),
		secret:     secret,
	}
	host, _ := dispatchConnect(t, deps, "/connect openai")

	if deps.gotKey != secret {
		t.Errorf("Connect got key %q, want the entered secret (the key must reach only deps)", deps.gotKey)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1 error event", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Outcome != "error" || p.ErrorDetail != errConnectFailed.Error() {
		t.Errorf("event = %+v, want outcome=error carrying the static errConnectFailed text", p)
	}
	for _, n := range host.notices {
		if strings.Contains(n, secret) {
			t.Error("a notice leaks the secret sentinel")
		}
	}
	for _, ev := range evs {
		if strings.Contains(string(ev.Payload), secret) {
			t.Error("an event payload leaks the secret sentinel")
		}
	}
}

// TestConnectHandler_UnknownProviderNoSecretLeak drives a secret-shaped argument
// down the unknown-provider rejection path: a pasted key must not surface in the
// returned error, any notice, or any event payload.
func TestConnectHandler_UnknownProviderNoSecretLeak(t *testing.T) {
	const secret = "sk-live-SUPERSECRET-should-never-render"
	deps := &connectDepsFake{known: map[string]bool{"openai": true}, secret: secret}
	host, res := dispatchConnect(t, deps, "/connect "+secret)

	if !res.RetainInput {
		t.Error("RetainInput = false, want true so the typed input is retained on rejection")
	}
	if deps.connectCalls != 0 {
		t.Errorf("Connect called %d times for an unknown provider, want 0", deps.connectCalls)
	}
	if res.Err != nil && strings.Contains(res.Err.Error(), secret) {
		t.Error("the returned error string leaks the secret sentinel")
	}
	if len(host.notices) != 1 {
		t.Fatalf("notices = %d, want 1", len(host.notices))
	}
	for _, n := range host.notices {
		if strings.Contains(n, secret) {
			t.Error("a notice leaks the secret sentinel")
		}
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1 error event", len(evs))
	}
	for _, ev := range evs {
		if strings.Contains(string(ev.Payload), secret) {
			t.Error("an event payload leaks the secret sentinel")
		}
	}
	if p := decodeSlash(t, evs[0]); p.Outcome != "error" {
		t.Errorf("event outcome = %q, want error", p.Outcome)
	}
}
