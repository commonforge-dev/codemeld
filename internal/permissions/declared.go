// Project-declared command list: the token prefixes a project's settings file approves for Auto
// posture to run without prompting.
package permissions

import (
	"fmt"
	"path/filepath"
)

type DeclaredCommand struct {
	Subject string
}

func ParseDeclaredCommands(raw any) (entries []DeclaredCommand, notices []string, err error) {
	if raw == nil {
		return nil, nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("declared_commands must be a list, got %T", raw)
	}
	for i, item := range list {
		text, ok := item.(string)
		if !ok {
			return nil, nil, fmt.Errorf("declared_commands.%d must be a string, got %T", i, item)
		}
		entry, reason, ok := parseDeclaredCommand(text)
		if !ok {
			notices = append(notices, fmt.Sprintf("declared_commands.%d %q: %s", i, text, reason))
			continue
		}
		entries = append(entries, entry)
	}
	return entries, notices, nil
}

// Every entry is already a prefix, so spelling the trailing `:*` is the confirm-gated
// program-scope grant wearing a config file as a disguise; a bare program name is the same
// grant for any program the destructive classifier flags.
func parseDeclaredCommand(text string) (entry DeclaredCommand, rejectReason string, ok bool) {
	tokens, err := tokenizeShell(text)
	if err != nil {
		return DeclaredCommand{}, "does not tokenize as a shell command", false
	}
	if len(tokens) == 0 {
		return DeclaredCommand{}, "is empty", false
	}
	if isBareWildcardToken(tokens[len(tokens)-1]) {
		return DeclaredCommand{}, `must not spell the trailing ":*" wildcard; every entry is already a prefix`, false
	}
	program := tokens[0].Value
	args := make([]string, len(tokens)-1)
	for i, t := range tokens[1:] {
		args[i] = t.Value
	}
	// IsDestructiveProgram matches a canonical bare program token and derives no base name, so a
	// path spelling reaches it only once this call site strips the path: a bare entry is
	// program-wide over whatever it names, and `/tmp/probe/bin/hg` is as program-wide as `hg`.
	if len(args) == 0 && IsDestructiveProgram(filepath.Base(program)) {
		return DeclaredCommand{}, fmt.Sprintf("bare program %q is destructive-classified; declare it with the flags that scope it", program), false
	}
	return DeclaredCommand{Subject: PrefixSubject(program, args)}, "", true
}

// A declaration is a prefix of the canonical direct token sequence and spells no environment, so it
// authorizes only the invocation that inherits codemeld's own environment: it is matched through the
// same rule a stored unversioned grant subject uses, under which an assignment-bearing or
// environment-clearing request is a distinct request that never matches. The environment is not
// cosmetic — dispatch applies it to the child process, an assigned or cleared PATH re-resolves the
// program name against that environment, and a program's own configuration variables load code the
// declared tokens never named. classifyReadOnlyShell refuses the read-only auto path on the same ground.
func MatchesDeclaredCommand(commandTokens, assignments []string, clearEnvironment bool, entries []DeclaredCommand) bool {
	for _, e := range entries {
		if MatchesDirectSubject(commandTokens, assignments, clearEnvironment, e.Subject) {
			return true
		}
	}
	return false
}
