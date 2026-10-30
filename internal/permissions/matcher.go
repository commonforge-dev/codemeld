// Real-grant permission matching across direct, literal, and structured-tool subjects with path-scope rules.
package permissions

import "fmt"

// subjectKindDirect and subjectKindLiteral are the discriminators for
// direct-command and literal-command subjects, alongside the package-level
// subjectKindTool defined in scope.go.
const (
	subjectKindDirect  = "direct"
	subjectKindLiteral = "literal"
)

const subjectKindHost = "host"

// grant_kind values that a grant may carry. folder and global come from the
// on-disk parser (entry.go); session is in-memory only but is
// representable on PermissionEntry and matches with the same descendant rule as
// folder.
const (
	grantKindSession = "session"
	grantKindFolder  = "folder"
	grantKindGlobal  = "global"
)

// outcomeSourceGrant labels a MatchResult produced by a real grant, as opposed
// to a turn-cache hit (owned by the turn cache and prompt orchestration).
// Prompt orchestration maps this onto the permission_* event outcome source so
// a grant match and a cache hit stay distinguishable.
const outcomeSourceGrant = "grant"

// MatchRequest describes one permission check. Subject is the canonical subject
// string used by literal and tool matching, cache keys, and events; for a direct
// request it is the boundary-preserving request identity DirectStageRequestSubject
// builds, not the flattened command text. SubjectTokens is the canonical command
// token sequence and is required only when Kind == subjectKindDirect; literal and
// tool matching use Subject and ignore SubjectTokens. PathScope is the request's
// resolved, cleaned, absolute directory and is never the all-paths sentinel "*".
// Host is an already canonical hostname for host requests.
type MatchRequest struct {
	Kind          string
	Subject       string
	SubjectTokens []string
	// Assignments is part of what a grant authorizes, so an empty list is the
	// request "this command carries no assignment", never "unknown".
	Assignments []string
	// ClearEnvironment is likewise part of what a grant authorizes: false is the
	// request "this command inherits the environment", never "unknown".
	ClearEnvironment  bool
	PathScope         string
	Host              string
	FreshConfirmation bool
}

func checkFreshConfirmation(req MatchRequest) error {
	if req.FreshConfirmation && req.Kind != subjectKindHost {
		return fmt.Errorf("permissions: fresh confirmation is only valid for a host request, not %q", req.Kind)
	}
	return nil
}

// MatchResult is the outcome of Match. On a real-grant match, Matched is true,
// Grant points at a copy of the winning entry, and OutcomeSource is
// outcomeSourceGrant. On no match, Matched is false, Grant is nil, and
// OutcomeSource is empty; Match never consults the turn cache, so a no-match
// result carries no cache outcome source — reading the cache after a no-match is
// owned by the turn cache and prompt orchestration.
type MatchResult struct {
	Matched       bool
	Grant         *PermissionEntry
	OutcomeSource string
}

func Match(req MatchRequest, grants []PermissionEntry) MatchResult {
	for i := range grants {
		grant := grants[i]
		if !grantMatches(req, grant) {
			continue
		}
		return MatchResult{Matched: true, Grant: &grant, OutcomeSource: outcomeSourceGrant}
	}
	return MatchResult{}
}

func grantMatches(req MatchRequest, grant PermissionEntry) bool {
	if req.Kind == subjectKindHost {
		return hostGrantMatches(req, grant)
	}
	if grant.HostScope != "" {
		return false
	}
	return grant.Kind == req.Kind && subjectMatches(req, grant) && pathScopeMatches(req.PathScope, grant)
}

func hostGrantMatches(req MatchRequest, grant PermissionEntry) bool {
	if !hostSubjects[req.Subject] {
		return false
	}
	if grant.Kind != subjectKindTool || grant.PathScope != "" {
		return false
	}
	if grant.GrantKind != grantKindProject && grant.GrantKind != grantKindSession {
		return false
	}
	if req.Host == "" || req.Host == allPathsScope {
		return false
	}
	return grant.Subject == req.Subject && grant.HostScope == req.Host
}

// subjectMatches applies the kind-specific subject rule. Direct matching uses
// the canonical command tokens; literal matching is byte-equal on canonical
// subjects, except that a generalized compound grant is
// matched structurally by decomposing the request and pinning the grant's
// program set and operator structure while widening each stage's arguments to
// its stored scope; tool matching is exact registered-name equality or
// capability expansion (see toolSubjectMatches).
// An unrecognized kind never matches.
func subjectMatches(req MatchRequest, grant PermissionEntry) bool {
	switch req.Kind {
	case subjectKindDirect:
		if checkDirectRequestIdentity(req.Subject, req.SubjectTokens, req.Assignments, req.ClearEnvironment) != nil {
			return false
		}
		expands, _ := requestHomeExpansion(req.Subject, req.SubjectTokens, req.Assignments, req.ClearEnvironment)
		return matchesDirectSubject(req.SubjectTokens, req.Assignments, req.ClearEnvironment, expands, grant.Subject)
	case subjectKindLiteral:
		if isCompoundSubject(grant.Subject) {
			return matchesCompoundSubject(req.Subject, grant.Subject)
		}
		return MatchesLiteralSubject(req.Subject, grant.Subject)
	case subjectKindTool:
		return toolSubjectMatches(req.Subject, grant.Subject)
	default:
		return false
	}
}

// For direct requests, requestTokens must be the persisted canonical tokens;
// re-splitting requestSubject loses quoted-token boundaries. requestAssignments and
// requestClearEnv must likewise come from a recorded request identity — an audit that
// cannot prove that state must not call this at all, because an empty list and a false
// flag assert the request carried no assignment and inherited the environment.
func AuditSubjectMatches(kind, requestSubject string, requestTokens, requestAssignments []string, requestClearEnv bool, storedSubject string) bool {
	return subjectMatches(
		MatchRequest{
			Kind:             kind,
			Subject:          requestSubject,
			SubjectTokens:    requestTokens,
			Assignments:      requestAssignments,
			ClearEnvironment: requestClearEnv,
		},
		PermissionEntry{Kind: kind, Subject: storedSubject},
	)
}

// Legacy concrete grants are never retroactively widened: a stored "create"
// matches only request "create", never "edit". Path-scope containment is
// enforced separately by pathScopeMatches, so a capability match still respects
// descendant-or-equal scope.
func toolSubjectMatches(reqSubject, grantSubject string) bool {
	if reqSubject == grantSubject {
		return true
	}
	return capabilityContains(grantSubject, reqSubject)
}

// pathScopeMatches reports whether a grant's path scope authorizes requestPath.
// A global grant authorizes any path and is identified by its "*" scope; a
// session or folder grant authorizes its scope and every descendant.
// An unrecognized grant_kind, or a global grant whose stored scope is not "*",
// never matches.
func pathScopeMatches(requestPath string, grant PermissionEntry) bool {
	switch grant.GrantKind {
	case grantKindGlobal:
		return grant.PathScope == allPathsScope
	case grantKindSession, grantKindFolder:
		return IsDescendantOrEqual(requestPath, grant.PathScope)
	default:
		return false
	}
}
