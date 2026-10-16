// /connect <provider> command: validate the supplied provider id, reject the
// reserved browser-login provider and unknown ids with a one-line notice, and on a
// supported id open the masked API-key prompt and record
// slash_command{connect,success} only after the submitted key's persistence write is
// durable — all kept behind ConnectDeps so internal/tui imports neither
// internal/config nor internal/provider. A cancelled prompt records nothing; a failed
// write records a durable, secret-free slash_command{connect,error} instead, so no
// success record can outlive a write that never happened, and the entered key reaches
// only deps.Connect — never an event, notice, or error string.
package tui

import (
	"errors"
	"fmt"

	"codemeld.dev/codemeld/internal/events"
)

// reservedConnectProviderID is the browser-login (ChatGPT subscription) provider
// id, which is connected via `codemeld auth login`, not /connect. It mirrors
// chatGPTProviderID in internal/cli/auth.go by value: internal/cli imports
// internal/tui, so importing the constant back would be a package cycle.
const reservedConnectProviderID = "openai-chatgpt"

// errConnectFailed is the static error /connect returns when the persistence seam
// fails, and doubles as the durable slash_command{connect,error} detail on that
// path. The underlying deps error is deliberately dropped rather than wrapped: a
// provider-connection write can carry a file path or key material, and this handler
// must keep secrets out of every error, notice, and event string.
var errConnectFailed = errors.New("connect: recording the provider connection failed")

// ConnectProviderOption is one connectable provider a bare /connect offers: a
// provider id and a user-facing display label, both secret-free. It carries no
// endpoint, key, or settings detail, so the provider list cannot leak deps internals
// into internal/tui. A bare /connect presents these choices in the provider picker.
type ConnectProviderOption struct {
	ID    string
	Label string
}

// ConnectDeps is the injectable seam /connect closes over so the handler can be
// driven end-to-end with a fake, keeping internal/tui free of internal/config and
// internal/provider. The production implementation lives in internal/bootstrap (its
// PromptAPIKey backed by the masked prompt, its Connect by the provider-entry
// writer); this slice binds none.
type ConnectDeps interface {
	// ConnectableProviders returns the providers a bare /connect can offer, in a
	// stable user-facing order, as id/label pairs. It carries no secret, endpoint, or
	// scaffold detail and performs no network I/O.
	ConnectableProviders() []ConnectProviderOption
	// OpenConnectPicker presents a non-blocking provider picker for a bare /connect.
	// Selecting a row invokes onSelect with that row's id; cancelling invokes no
	// callback and records no command event.
	OpenConnectPicker(options []ConnectProviderOption, onSelect func(id string))
	// IsProvider reports whether id names a known, connectable provider. It is the
	// lookup that separates an unknown id (rejected) from a supported one. It
	// returns only a bool so no deps-owned string can reach a user-facing notice.
	IsProvider(id string) bool
	NeedsManualKey(id string) bool
	// PromptAPIKey opens the masked API-key entry for the validated provider
	// id and invokes onSubmit with the entered key, or onCancel if the user dismisses
	// it. The production seam masks the key in the UI; the key reaches the handler
	// only as the onSubmit argument, so this seam records or echoes it nowhere. The
	// callbacks run on the event loop after the handler has returned to dispatch.
	PromptAPIKey(id string, onSubmit func(apiKey string), onCancel func())
	Connect(id, apiKey string, onComplete func(error))
}

// NewConnectHandler returns the /connect handler. It rejects the reserved
// browser-login provider and unknown ids synchronously with a one-line static notice
// (retaining the typed input and recording a flushed slash_command{outcome:error}).
// On a supported id it opens the masked API-key prompt and returns to dispatch at
// once; the connect completes in finishConnect on submit, or does nothing on cancel.
// Nothing is recorded until a key is submitted and its write lands, so a cancelled or
// unsubmitted prompt claims no connection. The rejection notices/events are fully
// static, and the post-submit path records only the id IsProvider vouched for plus the
// static errConnectFailed text — so no secret, key, or deps-returned value can leak
// into any notice, event, or error string.
func NewConnectHandler(deps ConnectDeps) HandlerFunc {
	return func(ctx CommandContext, args []string) error {
		// Dispatch enforces ArgOneOptional: zero or one argument. A bare /connect
		// names no provider yet, so it opens the picker and returns; selection below
		// re-enters the same direct provider path as typing /connect <provider>.
		if len(args) == 0 {
			options := deps.ConnectableProviders()
			deps.OpenConnectPicker(options, func(id string) {
				if err := connectProvider(ctx, deps, id); err != nil {
					ctx.Notice(err.Error())
				}
			})
			return nil
		}
		return connectProvider(ctx, deps, args[0])
	}
}

// connectProvider validates id, opens the masked API-key prompt for supported providers,
// and completes through finishConnect after submission. It is shared by typed
// `/connect <provider>` and picker selection so their validation, persistence, event,
// and notice sequencing stay identical.
func connectProvider(ctx CommandContext, deps ConnectDeps, id string) error {
	// The reserved browser-login provider is connected via `codemeld auth
	// login`, not /connect; an id deps does not recognize is unknown. The
	// reserved notice repeats only the fixed reservedConnectProviderID value,
	// and the unknown-provider notice is fully static, so no typed secret or
	// deps-returned value can leak.
	if id == reservedConnectProviderID {
		return rejectConnect(ctx, fmt.Sprintf("%s is connected with the browser login; run: codemeld auth login %s", id, id))
	}
	if !deps.IsProvider(id) {
		// Static copy only: the typed id is echoed nowhere, so a secret-shaped
		// argument (e.g. a pasted API key) cannot leak into the notice or the
		// slash_command error_detail.
		return rejectConnect(ctx, "unknown provider; supported providers are configured by codemeld")
	}

	// Supported provider: collect the key behind the masked prompt, then connect.
	// The prompt and the follow-on write run on the event loop after this handler
	// returns, so their outcome is reported through recorded events and notices,
	// not the synchronous dispatch result (mirroring /resume's picker). The typed
	// "/connect <id>" input has already been accepted, so the failure/cancel paths
	// no longer retain it — a retry is a fresh /connect.
	deps.PromptAPIKey(id,
		func(apiKey string) { finishConnect(ctx, deps, id, apiKey) },
		func() { ctx.Notice("connect cancelled; no provider was connected") },
	)
	return nil
}

// finishConnect runs after the user submits the masked API key: it performs the
// durable provider write through deps and records the slash_command event only after
// the write lands, so a failed connect can never leave a success record — in memory or
// on disk — that a later flush makes durable. It runs on the event loop after the
// handler returned to dispatch, so a residual internal failure it produces cannot flow
// back to the dispatch result; the notice surface is the only channel left (mirroring
// /resume's post-selection sequence). The failed-write event carries the static
// errConnectFailed text; deps.Connect renders the actionable, secret-free path/reason
// as its own notice. apiKey is handed to deps.Connect and dropped here — it reaches no
// event, notice, or error.
func finishConnect(ctx CommandContext, deps ConnectDeps, id, apiKey string) {
	ctx.Notice(fmt.Sprintf("connecting provider %s...", id))
	deps.Connect(id, apiKey, func(err error) {
		finishConnectResult(ctx, deps, id, err)
	})
}

func finishConnectResult(ctx CommandContext, deps ConnectDeps, id string, err error) {
	if err != nil {
		if aerr := appendConnectSlashCommand(ctx, id, OutcomeError, errConnectFailed.Error()); aerr != nil {
			ctx.Notice(aerr.Error())
			return
		}
		if ferr := ctx.FlushActive(); ferr != nil {
			ctx.Notice(ferr.Error())
		}
		return
	}
	// The provider entry is durable; record the success event and flush it so a
	// successful /connect leaves durable success evidence before the notice.
	if err := appendConnectSlashCommand(ctx, id, OutcomeSuccess, ""); err != nil {
		ctx.Notice(err.Error())
		return
	}
	if err := ctx.FlushActive(); err != nil {
		ctx.Notice(err.Error())
		return
	}
	if deps.NeedsManualKey(id) {
		ctx.Notice(fmt.Sprintf("connected provider %s; add its api_key in global settings to finish setup", id))
		return
	}
	ctx.Notice(fmt.Sprintf("connected provider %s; the API key validated and discovered models are ready to use", id))
}

func appendConnectSlashCommand(ctx CommandContext, id string, outcome Outcome, errorDetail string) error {
	_, err := events.Append(ctx.Store(), events.SlashCommand{
		Name:        "connect",
		Args:        []string{id},
		Outcome:     string(outcome),
		ErrorDetail: errorDetail,
	})
	return err
}

// rejectConnect renders the one-line notice, retains the typed input so the user
// can edit and retry, records the recognized command with outcome:error carrying
// the same text as error_detail, and flushes that record so the error event is
// durable before returning — validation rejects before any persistence, so there
// is no later flush. It mirrors /effort's rejectEffort; the two stay separate
// because this task owns only cmd_connect.go.
func rejectConnect(ctx CommandContext, notice string) error {
	ctx.Notice(notice)
	ctx.RetainInput()
	// Record the rejection with empty args, not via ctx.AppendSlashCommand: that
	// seam copies the raw typed args into the event, and a rejected /connect
	// argument is untrusted (a user may paste an API key where a provider id
	// belongs). The static notice is the only detail persisted, so no secret can
	// reach the session event.
	if _, err := events.Append(ctx.Store(), events.SlashCommand{
		Name:        "connect",
		Args:        []string{},
		Outcome:     string(OutcomeError),
		ErrorDetail: notice,
	}); err != nil {
		return err
	}
	return ctx.FlushActive()
}
