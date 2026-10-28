// Permission-event emitter helpers: thin wrappers that build the
// permission event payloads and append them to the active session store. The
// payload validators in payloads.go own the cross-field rules; these
// helpers only construct the typed payload and call Append.
package events

import (
	"fmt"

	"codemeld.dev/codemeld/internal/sessions"
)

// EmitPromptShown appends a permission_prompt_shown event. directTokens is the
// request's canonical direct-command token sequence
// (permissions.MatchRequest.SubjectTokens), recorded verbatim so a later audit
// replays direct matching from the tokens rather than re-tokenizing the
// flattened subject. It is nil for every non-direct subject kind and for a
// direct request that carries no canonical tokens; Append deep-copies it, so no
// caller alias survives in the record.
func EmitPromptShown(store *sessions.Store, subjectKind, subject, pathScope string, directTokens []string, directCommandSubject, directRequestSubject string) error {
	return EmitPromptShownAttributed(store, subjectKind, subject, pathScope, directTokens, directCommandSubject, directRequestSubject, "")
}

// EmitPromptShownAttributed is EmitPromptShown for a caller that knows which child agent's
// call this was; childInvocationID is empty for the run's own calls.
func EmitPromptShownAttributed(store *sessions.Store, subjectKind, subject, pathScope string, directTokens []string, directCommandSubject, directRequestSubject, childInvocationID string) error {
	p := PermissionPromptShown{
		SubjectKind:          subjectKind,
		Subject:              subject,
		PathScope:            pathScope,
		DirectCommandSubject: directCommandSubject,
		DirectRequestSubject: directRequestSubject,
		ChildInvocationID:    childInvocationID,
	}
	if directTokens != nil {
		p.DirectTokens = &directTokens
	}
	if subjectKind == subjectKindHost {
		p.PathScope, p.HostScope = "", pathScope
	}
	_, err := Append(store, p)
	return err
}

// EmitDecision appends a permission_decision event recording the user's response
// to a prompt. On a denied outcome the caller passes empty grantKind/
// grantPathScope so omitempty drops them. This event is emitted before any
// degradation rewrite, so grantKind/grantPathScope record the user's chosen values
// rather than the rewritten ones. It appends only.
func EmitDecision(store *sessions.Store, subjectKind, subject, pathScope, outcome, grantKind, grantPathScope, directCommandSubject, directRequestSubject string) error {
	return EmitDecisionAttributed(store, subjectKind, subject, pathScope, outcome, grantKind, grantPathScope, directCommandSubject, directRequestSubject, "")
}

// EmitDecisionAttributed is EmitDecision with the child-agent attribution.
func EmitDecisionAttributed(store *sessions.Store, subjectKind, subject, pathScope, outcome, grantKind, grantPathScope, directCommandSubject, directRequestSubject, childInvocationID string) error {
	p := PermissionDecision{
		SubjectKind:          subjectKind,
		Subject:              subject,
		PathScope:            pathScope,
		Outcome:              outcome,
		GrantKind:            grantKind,
		GrantPathScope:       grantPathScope,
		DirectCommandSubject: directCommandSubject,
		DirectRequestSubject: directRequestSubject,
		ChildInvocationID:    childInvocationID,
	}
	if subjectKind == subjectKindHost {
		p.PathScope, p.HostScope = "", pathScope
		p.GrantPathScope, p.GrantHostScope = "", grantPathScope
	}
	_, err := Append(store, p)
	return err
}

func EmitDecisionGrant(store *sessions.Store, subjectKind, subject, pathScope, grantKind, grantScope, grantSubject, directCommandSubject, directRequestSubject string) error {
	return EmitDecisionGrantAttributed(store, subjectKind, subject, pathScope, grantKind, grantScope, grantSubject, directCommandSubject, directRequestSubject, "")
}

// EmitDecisionGrantAttributed is EmitDecisionGrant with the child-agent attribution.
func EmitDecisionGrantAttributed(store *sessions.Store, subjectKind, subject, pathScope, grantKind, grantScope, grantSubject, directCommandSubject, directRequestSubject, childInvocationID string) error {
	if grantSubject == "" {
		return fmt.Errorf("%s: grant_subject is required for a stored grant", KindPermissionDecision)
	}
	p := PermissionDecision{
		SubjectKind:          subjectKind,
		Subject:              subject,
		PathScope:            pathScope,
		Outcome:              "granted",
		GrantKind:            grantKind,
		GrantPathScope:       grantScope,
		GrantSubject:         grantSubject,
		DirectCommandSubject: directCommandSubject,
		DirectRequestSubject: directRequestSubject,
		ChildInvocationID:    childInvocationID,
	}
	if subjectKind == subjectKindHost {
		p.PathScope, p.HostScope = "", pathScope
		p.GrantPathScope, p.GrantHostScope = "", grantScope
	}
	_, err := Append(store, p)
	return err
}

func EmitMatchedIdentity(store *sessions.Store, subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject string) error {
	return EmitMatchedIdentityAttributed(store, subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject, "")
}

// EmitMatchedIdentityAttributed is EmitMatchedIdentity with the child-agent attribution.
func EmitMatchedIdentityAttributed(store *sessions.Store, subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject, childInvocationID string) error {
	p := PermissionMatched{
		SubjectKind:          subjectKind,
		Subject:              subject,
		PathScope:            pathScope,
		GrantKind:            grantKind,
		GrantPathScope:       grantPathScope,
		Outcome:              outcome,
		OutcomeSource:        outcomeSource,
		ArgumentHash:         argumentHash,
		DirectRequestSubject: directRequestSubject,
		ChildInvocationID:    childInvocationID,
	}
	if subjectKind == subjectKindHost {
		p.PathScope, p.HostScope = "", pathScope
		p.GrantPathScope, p.GrantHostScope = "", grantPathScope
	}
	_, err := Append(store, p)
	return err
}

// EmitPersistFailed appends a permission_persist_failed event for a failed
// permission-grant persist. degradedToPathScope is the rewritten
// in-memory path scope, populated only when grantKind is "global" and empty for a
// folder grant. For a lock_timeout reason the caller must pass the canonical
// error_detail the validator pins ("lock acquisition timed out"); error_category
// is omitted (empty) for the reasons that do not originate in a file syscall. It
// appends only.
func EmitPersistFailed(store *sessions.Store, targetPath, grantKind, subjectKind, subject, reason, errorCategory, errorDetail, degradedToPathScope string) error {
	p := PermissionPersistFailed{
		TargetPath:          targetPath,
		GrantKind:           grantKind,
		SubjectKind:         subjectKind,
		Subject:             subject,
		Reason:              reason,
		ErrorCategory:       errorCategory,
		ErrorDetail:         errorDetail,
		DegradedToPathScope: degradedToPathScope,
	}
	if subjectKind == subjectKindHost {
		p.DegradedToPathScope, p.HostScope = "", degradedToPathScope
	}
	_, err := Append(store, p)
	return err
}

func EmitSystemOneCheckAttributed(store *sessions.Store, p PermissionSystemOneCheck, childInvocationID string) error {
	p.ChildInvocationID = childInvocationID
	_, err := Append(store, p)
	return err
}
