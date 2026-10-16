// `codemeld auth login` wiring: starts the OpenAI ChatGPT browser/device login
// flow and persists the resulting session under auth.openai-chatgpt only after
// upstream login succeeds, while refusing a ChatGPT login for the API-key-only
// `openai` provider.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"

	"codemeld.dev/codemeld/internal/authstate"
	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/openaiauth"
	"codemeld.dev/codemeld/internal/paths"
	"codemeld.dev/codemeld/internal/provider"
	ucli "github.com/urfave/cli/v3"
)

// Provider ids accepted by `auth login`. chatGPTProviderID is the browser-login
// ChatGPT subscription provider; platformProviderID is the OpenAI Platform
// API-key provider, which has no browser-login credential.
const (
	chatGPTProviderID  = "openai-chatgpt"
	platformProviderID = "openai"
)

// loginTimeout bounds how long the command waits for the user to complete the
// upstream sign-in before the context deadline turns the attempt into a typed
// timeout. It is generous because the user must switch to a browser.
const loginTimeout = 5 * time.Minute

// revokeTimeout bounds the best-effort upstream revocation during logout so the
// command cannot hang on a slow or unresponsive auth endpoint. Revocation is
// best-effort, so local deletion proceeds whatever this bound produces.
const revokeTimeout = 15 * time.Second

// discoverTimeout bounds the best-effort ChatGPT model-discovery call fired after a
// successful connect so a slow or hung endpoint cannot delay the already-completed
// login; exceeding it is a graceful discovery failure that leaves the last cached or
// seeded model list in place.
const discoverTimeout = 15 * time.Second

// Package-local seams so auth_test can drive the login command without a real
// TTY, real OpenAI network calls, or a real settings write. Production wires the
// real implementations: a TTY/CI interactivity check, the live openaiauth flow,
// and the authstate writer (the wiring this task owns).
var (
	isInteractiveContext = defaultIsInteractiveContext
	runChatGPTLoginFlow  = liveChatGPTLoginFlow
	storeChatGPTSession  = authstate.Write
	// refreshChatGPTModels runs login-time ChatGPT model discovery and persists the
	// sanitized result into the shared models.yaml store; auth_discovery_test replaces it
	// so the login tests stay offline. `auth status` never discovers.
	refreshChatGPTModels = liveRefreshChatGPTModels
)

// chatGPTDiscoverSource labels the models.yaml openai-chatgpt entry a login discovery
// writes, so the store records where the ids came from (secret-free advisory metadata).
const chatGPTDiscoverSource = "auth-login-chatgpt-discovery"

// liveRefreshChatGPTModels is the production discovery seam: it runs connect-time ChatGPT
// model discovery through the provider entry point and persists the sanitized result into
// the shared, system-owned models.yaml store under the openai-chatgpt provider entry.
// internal/config owns the store writer (internal/provider cannot import it without a
// cycle), so the provider hands back neutral records this closure maps onto the store's
// own record type. It is best-effort and connect-scoped; runChatGPTLogin swallows its
// error so a discovery or store-write failure never fails an already-completed login.
func liveRefreshChatGPTModels(ctx context.Context, cfg provider.ChatGPTClientConfig, modelsPath string) error {
	return provider.RefreshChatGPTModelCache(ctx, cfg, func(models []provider.ChatGPTStoreModel) error {
		return config.UpdateDiscoveredModelsProvider(modelsPath, chatGPTProviderID, chatGPTDiscoveredProvider(models))
	})
}

// chatGPTDiscoveredProvider adapts the provider package's neutral discovered-model records
// into the shared store's provider entry. The fields are already sanitized selection/
// capability metadata (the provider whitelist drops prompt-bearing and raw-response
// fields); the store write redacts secret-shaped values as a defensive backstop.
func chatGPTDiscoveredProvider(models []provider.ChatGPTStoreModel) config.DiscoveredProvider {
	out := make([]config.DiscoveredModel, len(models))
	for i, m := range models {
		out[i] = config.DiscoveredModel{
			ID:              m.ID,
			DisplayName:     m.DisplayName,
			ContextWindow:   m.ContextWindow,
			InputModalities: m.InputModalities,
			Capabilities:    m.Capabilities,
		}
	}
	return config.DiscoveredProvider{Source: chatGPTDiscoverSource, Models: out}
}

// Package-local seams so auth_test can drive the logout command without real
// OpenAI network calls or a real settings file. Production wires the real
// implementations: load classifies the stored session, revoke performs the
// best-effort upstream revocation (the wiring this task owns), and delete removes
// auth.openai-chatgpt through the shared settings lock and atomic rewrite.
var (
	loadChatGPTSession   = authstate.Load
	revokeChatGPTSession = liveRevokeChatGPTSession
	deleteChatGPTSession = authstate.Delete
	logoutNow            = time.Now
)

// authProviderCommand is the per-command data that distinguishes `auth login`
// from `auth logout`. Login and logout share the command-builder shape and the
// provider-argument dispatch but differ on purpose in their help text and their
// "openai" rejection wording (pinned by TestAuthHelp_AllFormsAtEveryLevel and the
// validation-error tests), so every distinct user-facing string is supplied here
// rather than derived from the command name.
type authProviderCommand struct {
	// verb is the subcommand name ("login"/"logout"). It is used only as the
	// command Name; every user-facing string is supplied explicitly below rather
	// than derived from it, so wording cannot drift if the verb is reused.
	verb string
	// usage, usageText, and description are the hand-written help fields.
	usage       string
	usageText   string
	description string
	// missingProvider is the usage-error message when no provider id is given.
	missingProvider string
	// tooManyArgs formats the usage-error message when more than one provider id is
	// given; n is the number of arguments received.
	tooManyArgs func(n int) string
	// unknownProvider formats the usage-error message for an unrecognized provider
	// id; provider is the rejected argument.
	unknownProvider func(provider string) string
	// openAIRejection is the message for the API-key-only "openai" provider id
	// login and logout explain the rejection differently.
	openAIRejection string
	// runChatGPT handles the openai-chatgpt provider for this command.
	runChatGPT func(context.Context, io.Writer) error
}

// newAuthProviderCommand builds an `auth login`/`auth logout` style subcommand
// from spec. Each takes a single provider-id positional argument; the action
// routes openai-chatgpt to spec.runChatGPT and rejects openai with the
// command-specific message.
func newAuthProviderCommand(stdout io.Writer, spec authProviderCommand) *ucli.Command {
	return &ucli.Command{
		Name:        spec.verb,
		Usage:       spec.usage,
		UsageText:   spec.usageText,
		ArgsUsage:   "<provider>",
		Description: spec.description,
		Action: func(ctx context.Context, c *ucli.Command) error {
			return runAuthProvider(ctx, spec, c.Args().Slice(), stdout)
		},
	}
}

// runAuthProvider dispatches an `auth login`/`auth logout` invocation. It requires
// exactly one provider id: openai-chatgpt runs spec.runChatGPT; openai is rejected
// with spec.openAIRejection; anything else is a usage error rendered with
// the caller-supplied spec.missingProvider / spec.tooManyArgs / spec.unknownProvider
// wording. All rejections exit non-zero and touch no storage.
func runAuthProvider(ctx context.Context, spec authProviderCommand, args []string, stdout io.Writer) error {
	switch len(args) {
	case 1:
		// handled below
	case 0:
		return ucli.Exit(spec.missingProvider, 2)
	default:
		return ucli.Exit(spec.tooManyArgs(len(args)), 2)
	}

	switch args[0] {
	case chatGPTProviderID:
		return spec.runChatGPT(ctx, stdout)
	case platformProviderID:
		// openai is the OpenAI Platform API-key provider id; it must not run
		// a ChatGPT login/logout. The command-specific message points the user at
		// API-key configuration instead.
		return ucli.Exit(spec.openAIRejection, 2)
	default:
		return ucli.Exit(spec.unknownProvider(args[0]), 2)
	}
}

// newAuthLoginCommand builds the `codemeld auth login <provider>` subcommand. It
// takes a single provider-id positional argument; the action routes
// openai-chatgpt to the login flow and rejects openai with an API-key message.
func newAuthLoginCommand(stdout io.Writer) *ucli.Command {
	return newAuthProviderCommand(stdout, authProviderCommand{
		verb:      "login",
		usage:     "sign in to a provider that supports browser login (openai-chatgpt)",
		usageText: "codemeld auth login openai-chatgpt",
		description: "Sign in to a provider that supports browser login. The only accepted\n" +
			"<provider> is openai-chatgpt, which opens a browser sign-in for your own\n" +
			"OpenAI ChatGPT account (codemeld is not affiliated with or endorsed by\n" +
			"OpenAI). The session is saved to the global settings file and used only when\n" +
			"the openai-chatgpt provider is selected.\n\n" +
			"The openai (OpenAI Platform) provider uses an API key, not a browser login,\n" +
			"so it is not a valid argument here; set OPENAI_API_KEY instead.",
		missingProvider: "codemeld: auth login requires a provider id; use 'codemeld auth login openai-chatgpt'",
		tooManyArgs: func(n int) string {
			return fmt.Sprintf("codemeld: auth login accepts exactly one provider id; got %d arguments", n)
		},
		unknownProvider: func(provider string) string {
			return fmt.Sprintf("codemeld: unknown login provider %q; use 'codemeld auth login openai-chatgpt'", provider)
		},
		openAIRejection: "codemeld: 'openai' is the OpenAI Platform provider and uses an OpenAI API key, not a browser login. " +
			"Set OPENAI_API_KEY or configure provider.openai in ~/.codemeld/global/settings.yaml. " +
			"To sign in with a ChatGPT subscription instead, run 'codemeld auth login openai-chatgpt'.",
		runChatGPT: runChatGPTLogin,
	})
}

// runChatGPTLogin runs the openai-chatgpt login: it gates on an interactive
// context, runs the upstream flow to completion, and only then
// persists the session under auth.openai-chatgpt. Any failure —
// non-interactive context, cancellation, timeout, unsupported host, upstream
// rejection, or a storage error — exits non-zero and leaves prior state
// unchanged, and no credential value is printed.
func runChatGPTLogin(ctx context.Context, stdout io.Writer) error {
	if !isInteractiveContext() {
		// never open a browser or device-code flow when we cannot safely
		// prompt; fail with an actionable message instead.
		return ucli.Exit(
			"codemeld: ChatGPT login needs an interactive terminal (a TTY with CI unset). "+
				"Run 'codemeld auth login openai-chatgpt' in an interactive shell, "+
				"or use the OpenAI Platform provider by setting OPENAI_API_KEY for 'openai'.",
			1,
		)
	}

	home, err := resolveHome()
	if err != nil {
		return ucli.Exit("codemeld: cannot resolve home directory: "+paths.FormatHomeError(err), 1)
	}
	settingsPath := bootstrap.SettingsPath(home)

	// present ChatGPT access as user-initiated and upstream-policy
	// dependent, and make no claim of official OpenAI approval.
	fmt.Fprintln(stdout, "Signing in to your own OpenAI ChatGPT account. codemeld is not affiliated with or")
	fmt.Fprintln(stdout, "endorsed by OpenAI; access depends on OpenAI's terms and may change or be revoked.")

	// Bound the wait so an abandoned sign-in becomes a typed timeout.
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	tok, err := runChatGPTLoginFlow(ctx, stdout)
	if err != nil {
		// No storage write has happened, so prior state is already untouched.
		return ucli.Exit(loginErrorMessage(err), 1)
	}

	// persist only after upstream login succeeds. A failed write must
	// not claim success; config.Persist leaves the existing file untouched on error.
	if _, _, werr := storeChatGPTSession(settingsPath, sessionFromToken(tok)); werr != nil {
		return ucli.Exit(
			"codemeld: signed in to OpenAI ChatGPT, but could not save the session to "+settingsPath+
				"; prior auth state is unchanged",
			1,
		)
	}

	fmt.Fprintln(stdout, "Signed in to OpenAI ChatGPT. The session is saved in")
	fmt.Fprintln(stdout, "  "+settingsPath)
	fmt.Fprintln(stdout, "and is used only when you select the openai-chatgpt provider.")

	// Refresh the discovered ChatGPT model list on a successful connect.
	// Best-effort — `auth status` never discovers, and the picker does only on a forced
	// refresh — so any failure (timeout, non-2xx, refused redirect, malformed body, store write) is
	// swallowed here: the existing store or the compiled seed stays usable and no
	// credential or response body reaches the user. It runs after the sign-in confirmation
	// so a slow model fetch never delays it. The result lands in the shared models.yaml
	// store beside global settings, not the legacy per-provider JSON sidecar.
	if modelsPath := config.DiscoveredModelsPath(settingsPath); modelsPath != "" {
		dctx, dcancel := context.WithTimeout(ctx, discoverTimeout)
		_ = refreshChatGPTModels(dctx, provider.ChatGPTClientConfig{
			AccessToken: tok.AccessToken,
			AccountID:   tok.AccountID,
		}, modelsPath)
		dcancel()
	}
	return nil
}

// newAuthLogoutCommand builds the `codemeld auth logout <provider>` subcommand. It
// takes a single provider-id positional argument; the action routes openai-chatgpt
// to the logout flow and rejects openai (the API-key provider) with guidance.
func newAuthLogoutCommand(stdout io.Writer) *ucli.Command {
	return newAuthProviderCommand(stdout, authProviderCommand{
		verb:      "logout",
		usage:     "sign out of a provider that supports browser login (openai-chatgpt)",
		usageText: "codemeld auth logout openai-chatgpt",
		description: "Sign out of a provider that supports browser login. The only accepted\n" +
			"<provider> is openai-chatgpt: it removes the locally stored ChatGPT session\n" +
			"(after a best-effort upstream revocation) and leaves your API keys,\n" +
			"permissions, model state, and other settings untouched. It is safe to run\n" +
			"when no session is stored.\n\n" +
			"The openai (OpenAI Platform) provider keeps no login session to remove, so\n" +
			"it is not a valid argument here.",
		missingProvider: "codemeld: auth logout requires a provider id; use 'codemeld auth logout openai-chatgpt'",
		tooManyArgs: func(n int) string {
			return fmt.Sprintf("codemeld: auth logout accepts exactly one provider id; got %d arguments", n)
		},
		unknownProvider: func(provider string) string {
			return fmt.Sprintf("codemeld: unknown logout provider %q; use 'codemeld auth logout openai-chatgpt'", provider)
		},
		// openai is the API-key provider; it has no stored login session
		// that logout manages. Point the user at API-key configuration instead.
		openAIRejection: "codemeld: 'openai' is the OpenAI Platform provider and has no stored login session to remove; " +
			"it uses an OpenAI API key (OPENAI_API_KEY or provider.openai in ~/.codemeld/global/settings.yaml). " +
			"To remove a ChatGPT subscription session, run 'codemeld auth logout openai-chatgpt'.",
		runChatGPT: runChatGPTLogout,
	})
}

// runChatGPTLogout removes local OpenAI ChatGPT auth state.
// It loads the stored session first: with none it reports that ChatGPT has no
// local session and exits 0 (idempotent). With a usable session it attempts
// a best-effort upstream revocation before deleting, but a revocation failure or an
// unsupported revocation never blocks local deletion. Deletion goes through
// the authstate delete helper, which removes only auth.openai-chatgpt under the
// settings sidecar lock and atomic 0600 rewrite, preserving configured API keys,
// permissions, model state, and unrelated settings. A deletion
// failure exits non-zero with prior state unchanged. No access token
// refresh token, account id, or cookie is ever printed.
func runChatGPTLogout(ctx context.Context, stdout io.Writer) error {
	home, err := resolveHome()
	if err != nil {
		return ucli.Exit("codemeld: cannot resolve home directory: "+paths.FormatHomeError(err), 1)
	}
	settingsPath := bootstrap.SettingsPath(home)

	// The load error is intentionally ignored: an unreadable/corrupted file is not a
	// usable session, so no revocation is attempted; whether any stored bytes can be
	// removed is decided by the delete call below. Field values are never inspected.
	sess, status, _ := loadChatGPTSession(settingsPath, logoutNow())
	if status == authstate.StatusNone {
		// nothing is stored, so there is nothing to revoke or delete.
		fmt.Fprintln(stdout, "OpenAI ChatGPT has no local session; nothing to remove.")
		return nil
	}

	// Attempt best-effort upstream revocation before local
	// deletion, but only when a session with a usable refresh token is present.
	// Corrupted/invalid state carries no usable token, so revocation is skipped and
	// only local deletion is attempted. Any revocation outcome is non-fatal.
	revocationAttempted, revocationFailed := false, false
	if status == authstate.StatusPresent || status == authstate.StatusExpired {
		revocationAttempted = true
		rctx, cancel := context.WithTimeout(ctx, revokeTimeout)
		revocationFailed = revokeChatGPTSession(rctx, sess.RefreshToken) != nil
		cancel()
	}

	// delete only auth.openai-chatgpt. On failure exit non-zero
	// config.Persist skips the write on a re-read/write error, so every prior
	// setting — API keys, permissions, model state, unrelated providers — is intact.
	if _, _, derr := deleteChatGPTSession(settingsPath); derr != nil {
		return ucli.Exit(
			"codemeld: could not remove the OpenAI ChatGPT session from "+settingsPath+
				"; no API keys, permissions, model state, or other settings were changed",
			1,
		)
	}

	if revocationAttempted && revocationFailed {
		// Local state is gone but the upstream grant may persist
		// say only local state was removed and point at OpenAI's own access controls.
		fmt.Fprintln(stdout, "Removed the local OpenAI ChatGPT session from")
		fmt.Fprintln(stdout, "  "+settingsPath)
		fmt.Fprintln(stdout, "Only local state was removed: the upstream session could not be revoked and may still be active.")
		fmt.Fprintln(stdout, "To revoke codemeld's access on OpenAI's side, review the connected apps and active sessions in")
		fmt.Fprintln(stdout, "your OpenAI ChatGPT account settings (https://chatgpt.com) and OpenAI account controls (https://platform.openai.com).")
		return nil
	}

	fmt.Fprintln(stdout, "Signed out of OpenAI ChatGPT. The local session was removed from")
	fmt.Fprintln(stdout, "  "+settingsPath)
	return nil
}

// liveRevokeChatGPTSession performs the production best-effort upstream revocation
// of a ChatGPT refresh token against the pinned OpenAI auth origin. It is the
// default revokeChatGPTSession seam; auth_test substitutes a fake to exercise the
// revoke-then-delete ordering without network access.
func liveRevokeChatGPTSession(ctx context.Context, refreshToken string) error {
	return openaiauth.NewFlow().Revoke(ctx, refreshToken)
}

// sessionFromToken maps the storage-deferred openaiauth payload onto the
// authstate session shape (Expiry is the RFC3339 string stored as ExpiresAt).
func sessionFromToken(t openaiauth.TokenResult) authstate.Session {
	return authstate.Session{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		ExpiresAt:    t.Expiry,
		AccountID:    t.AccountID,
	}
}

// loginErrorMessage renders a credential-free, actionable message for a login
// failure. openaiauth.Error.Detail is guaranteed free of tokens, codes, and
// account ids, so only its typed kind/detail reaches the user.
func loginErrorMessage(err error) string {
	var oe *openaiauth.Error
	if errors.As(err, &oe) {
		switch oe.Kind {
		case openaiauth.KindCanceled:
			return "codemeld: ChatGPT login canceled; no changes were made"
		case openaiauth.KindTimeout:
			return "codemeld: ChatGPT login timed out; no changes were made"
		case openaiauth.KindUnsupported:
			return "codemeld: this host cannot complete ChatGPT login (could not start the local sign-in helper); " +
				"no changes were made"
		default: // KindUpstream
			return "codemeld: ChatGPT login failed (" + oe.Detail + "); no changes were made"
		}
	}
	return "codemeld: ChatGPT login failed; no changes were made"
}

// defaultIsInteractiveContext reports whether codemeld may prompt for an
// interactive login: stdin and stdout must both be terminals and CI must be unset
// or empty. Browser availability is deliberately not consulted.
func defaultIsInteractiveContext() bool {
	if os.Getenv("CI") != "" {
		return false
	}
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// liveChatGPTLoginFlow runs the real OpenAI Codex login against the pinned auth
// origin and returns the storage-deferred token payload. It prefers the
// browser + fixed-loopback flow and falls back to the device-code flow only when
// the local loopback listener cannot bind (KindUnsupported). It prints user-facing
// guidance to out but never a token, account id, PKCE verifier, authorization
// code, or device code.
func liveChatGPTLoginFlow(ctx context.Context, out io.Writer) (openaiauth.TokenResult, error) {
	flow := openaiauth.NewFlow()

	pkce, err := openaiauth.GeneratePKCE()
	if err != nil {
		return openaiauth.TokenResult{}, err
	}
	state, err := openaiauth.GenerateState()
	if err != nil {
		return openaiauth.TokenResult{}, err
	}

	lb, err := flow.StartLoopback(state)
	if err != nil {
		var oe *openaiauth.Error
		if errors.As(err, &oe) && oe.Kind == openaiauth.KindUnsupported {
			return liveDeviceLoginFlow(ctx, flow, out)
		}
		return openaiauth.TokenResult{}, err
	}
	defer func() { _ = lb.Close() }()

	// The authorize URL carries only the PKCE challenge (a hash) and CSRF state,
	// never the verifier, so it is safe to display.
	fmt.Fprintln(out, "To sign in, open this URL in your browser:")
	fmt.Fprintln(out, "  "+flow.AuthorizeURL(state, pkce))
	fmt.Fprintln(out, "Waiting for you to finish sign-in… (Ctrl-C to cancel)")

	code, err := lb.Wait(ctx)
	if err != nil {
		return openaiauth.TokenResult{}, err
	}
	return flow.ExchangeCode(ctx, code, pkce.Verifier)
}

// liveDeviceLoginFlow runs the RFC 8628 device-code fallback when the loopback
// listener cannot bind. It shows the user code and verification URL (both meant
// for display) but never the device code (the polling credential).
func liveDeviceLoginFlow(ctx context.Context, flow *openaiauth.Flow, out io.Writer) (openaiauth.TokenResult, error) {
	da, err := flow.RequestDeviceCode(ctx)
	if err != nil {
		return openaiauth.TokenResult{}, err
	}
	fmt.Fprintln(out, "Browser sign-in is unavailable on this host. To sign in to OpenAI ChatGPT:")
	fmt.Fprintf(out, "  1. Open %s\n", da.VerificationURI)
	fmt.Fprintf(out, "  2. Enter the code: %s\n", da.UserCode)
	fmt.Fprintln(out, "Waiting for authorization… (Ctrl-C to cancel)")
	return flow.PollDeviceToken(ctx, da)
}
