package permissions

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/paths"
)

var shellReservedWords = map[string]bool{
	"!": true, "{": true, "}": true, "[[": true, "]]": true, "case": true, "coproc": true, "do": true,
	"done": true, "elif": true, "else": true, "esac": true, "fi": true, "for": true, "function": true,
	"if": true, "in": true, "select": true, "then": true, "time": true, "until": true, "while": true,
}

func SystemOneEligible(req MatchRequest, mc ModeContext, blocked *BlockedPaths, commandText string) string {
	if req.Kind != subjectKindDirect && req.Kind != subjectKindLiteral {
		return "text"
	}
	if (mc.Mode != modePlan && mc.Mode != modeAutoEdits) || mc.NetworkEgress || mc.ExternalRead {
		return "text"
	}
	if strings.TrimSpace(commandText) == "" || strings.Contains(commandText, "\\\n") || req.PathScope == "" || mc.ProjectRoot == "" {
		return "text"
	}
	snap := blocked.Current()
	if snap == nil || snap.Home() == "" || snap.Degraded() {
		return "blocked_paths_unavailable"
	}
	mentionsBlocked := blockedMentions(snap)
	if hasSubstitutionSpelling(commandText) {
		return "substitution"
	}
	if mentionsBlocked(commandText) {
		return "blocked_path"
	}
	if req.Kind == subjectKindDirect && len(req.SubjectTokens) == 0 {
		return "shell_shape"
	}
	if req.Kind == subjectKindDirect && strings.Contains(req.SubjectTokens[0], "/") {
		return "program_location"
	}
	for _, t := range req.SubjectTokens {
		if hasSubstitutionSpelling(t) {
			return "substitution"
		}
		if mentionsBlocked(t) {
			return "blocked_path"
		}
	}
	if _, hit := snap.Blocking(req.PathScope); hit || strings.Contains(req.PathScope, ".codemeld/global") {
		return "blocked_path"
	}

	sourceMask, err := bareMask(commandText)
	if err != nil {
		return "shell_shape"
	}
	for i, bare := range sourceMask {
		if bare && (commandText[i] == '\n' || commandText[i] == '\r') {
			return "text"
		}
	}
	stripped, ok := stripNullRedirects(commandText)
	if !ok {
		return "shell_shape"
	}
	mask, err := bareMask(stripped)
	if err != nil || compoundBodyHasDisallowed(stripped, mask) {
		return "shell_shape"
	}
	if mc.ShellPathAsk && pathUncertainSpelling(stripped) {
		return "shell_shape"
	}
	stages, _ := splitCompound(stripped, mask)
	stageCtx := StageInCompound
	if len(stages) == 1 {
		stageCtx = StageSolo
	}
	for _, stage := range stages {
		if reason := systemOneStageEligible(stage, stageCtx, req.PathScope, mc, snap, mentionsBlocked); reason != "" {
			return reason
		}
	}
	return ""
}

func systemOneStageEligible(stage string, stageCtx StageContext, scope string, mc ModeContext, snap *BlockedPaths, mentionsBlocked func(string) bool) string {
	tokens, err := tokenizeShell(stage)
	if err != nil || len(tokens) == 0 {
		return "shell_shape"
	}
	lookup := systemOneLookupStage(tokens)
	norm, err := NormalizeDirectStage(stage, stageCtx)
	if err != nil {
		return "shell_shape"
	}
	if !lookup && norm.Route != RouteDirect {
		return "wrapper"
	}
	if !lookup && len(norm.Tokens) == 0 {
		return "shell_shape"
	}
	prog := sourceProgram(tokens)
	normProg := prog.Value
	if !lookup {
		normProg = norm.Tokens[0]
	}
	if shellReservedWords[normProg] {
		return "wrapper"
	}
	for _, t := range tokens {
		if hasSubstitutionSpelling(t.Value) || dollarOutsideSingleQuotes(t.Raw) {
			return "substitution"
		}
		if mentionsBlocked(t.Value) {
			return "blocked_path"
		}
		if strings.ContainsRune(t.unquoted, '{') {
			return "shell_shape"
		}
		if mc.ShellPathAsk && pathUncertainSpelling(t.Value) {
			return "shell_shape"
		}
		if reason := tokenPathsClear(snap, scope, t); reason != "" {
			return reason
		}
	}
	if strings.Contains(prog.Value, "/") || strings.Contains(prog.Raw, "/") || strings.Contains(normProg, "/") || strings.ContainsAny(prog.unquoted, "*?[~") {
		return "program_location"
	}
	if lookup {
		return ""
	}
	if !programOutsideWritableFolders(norm, mc, snap.FoldCase()) {
		return "program_location"
	}
	return ""
}

func systemOneLookupStage(tokens []ShellToken) bool {
	var names []ShellToken
	switch {
	case len(tokens) >= 2 && tokens[0].Value == "type":
		names = tokens[1:]
	case len(tokens) >= 3 && tokens[0].Value == "command" && tokens[1].Value == "-v":
		names = tokens[2:]
	default:
		return false
	}
	for _, t := range tokens {
		if t.Raw != t.Value {
			return false
		}
	}
	for _, t := range names {
		if !plainProgramName(t.Value) {
			return false
		}
	}
	return true
}

func hasSubstitutionSpelling(s string) bool {
	return strings.Contains(s, "$(") || strings.Contains(s, "`") || strings.Contains(s, "<(") || strings.Contains(s, ">(")
}

func blockedMentions(snap *BlockedPaths) func(string) bool {
	fold := func(s string) string {
		if snap.FoldCase() {
			return strings.ToLower(s)
		}
		return s
	}
	needles := []string{fold(".codemeld/global")}
	for _, form := range snap.Forms() {
		needles = append(needles, fold(form))
		if rest, ok := strings.CutPrefix(form, snap.Home()); ok && (rest == "" || rest[0] == '/') {
			needles = append(needles, fold("~"+rest))
		}
	}
	return func(s string) bool {
		s = fold(s)
		for _, n := range needles {
			if strings.Contains(s, n) {
				return true
			}
		}
		return false
	}
}

func dollarOutsideSingleQuotes(raw string) bool {
	inSingle, inDouble := false, false
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case inSingle:
			inSingle = c != '\''
		case c == '\\':
			i++
		case c == '\'' && !inDouble:
			inSingle = true
		case c == '"':
			inDouble = !inDouble
		case c == '$':
			return true
		}
	}
	return false
}

func pathUncertainSpelling(s string) bool {
	if strings.Contains(s, "~") || strings.Contains(s, "$HOME") || strings.Contains(s, "${HOME") {
		return true
	}
	for i := 0; i < len(s); i++ {
		boundary := i == 0 || !pathWordByte(s[i-1])
		if s[i] == '/' && boundary {
			return true
		}
		if strings.HasPrefix(s[i:], "..") && (boundary || s[i-1] == '/') && (i+2 == len(s) || !pathWordByte(s[i+2]) || s[i+2] == '/') {
			return true
		}
	}
	return false
}

func pathWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._-+@%*?[]/", c) >= 0
}

func tokenPathsClear(snap *BlockedPaths, scope string, t ShellToken) string {
	if strings.Contains(t.Value, "../") || strings.HasSuffix(t.Value, "..") || strings.ContainsRune(t.unquoted, '[') {
		return "shell_shape"
	}
	candidates := []string{t.Value}
	if _, after, ok := strings.Cut(t.Value, "="); ok {
		candidates = append(candidates, after)
	}
	if strings.HasPrefix(t.Value, "-") {
		for i := 1; i < len(t.Value); i++ {
			candidates = append(candidates, t.Value[i:])
		}
	}
	glob := strings.ContainsAny(t.unquoted, "*?[")
	if glob && globMetaCount(t.Value) > globMetaCount(t.unquoted) {
		return "shell_shape"
	}
	if glob {
		for _, seg := range strings.Split(t.Value, "/") {
			if strings.HasPrefix(seg, ".") && strings.ContainsAny(seg, "*?[") {
				return "shell_shape"
			}
		}
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if strings.HasPrefix(c, "~") {
			expanded, err := paths.Expand(snap.Home(), c)
			if err != nil {
				return "shell_shape"
			}
			c = expanded
		} else if !filepath.IsAbs(c) {
			c = filepath.Join(scope, c)
		}
		targets := []string{c}
		if glob {
			matches, err := filepath.Glob(filepath.Clean(c))
			if err != nil {
				return "shell_shape"
			}
			targets = append(targets, matches...)
		}
		for _, target := range targets {
			if _, hit := snap.Blocking(target); hit {
				return "blocked_path"
			}
			if _, hit := snap.BlockedWithin(target); hit {
				return "blocked_path"
			}
		}
	}
	return ""
}

func globMetaCount(s string) int {
	n := 0
	for _, c := range []string{"*", "?", "[", `\`} {
		n += strings.Count(s, c)
	}
	return n
}

func sourceProgram(tokens []ShellToken) ShellToken {
	first := 0
	for first < len(tokens)-1 && isEnvAssignment(tokens[first]) {
		first++
	}
	rest := tokens[first:]
	if inner, _, _, ok := envStage(rest); ok {
		rest = inner
	}
	return rest[0]
}

func programOutsideWritableFolders(norm StageNormalization, mc ModeContext, foldCase bool) bool {
	lookup := os.Getenv("PATH")
	if norm.ClearEnvironment {
		lookup = ""
	}
	for _, a := range norm.Assignments {
		if name, value, _ := strings.Cut(a, "="); name == "PATH" {
			lookup = value
		}
	}
	found, ok := lookupProgram(norm.Tokens[0], lookup)
	if !ok {
		return false
	}
	resolved, err := filepath.EvalSymlinks(found)
	if err != nil {
		return false
	}
	root, err := filepath.EvalSymlinks(mc.ProjectRoot)
	if err != nil {
		return false
	}
	folders := []string{root, filepath.Clean(mc.ProjectRoot)}
	for _, w := range mc.WritableFolders {
		folders = append(folders, filepath.Clean(w))
		if r, err := filepath.EvalSymlinks(w); err == nil {
			folders = append(folders, r)
		}
	}
	for _, folder := range folders {
		for _, p := range []string{found, resolved} {
			if _, inside := RelWithin(folder, p, foldCase); inside {
				return false
			}
		}
	}
	return true
}

func lookupProgram(name, pathList string) (string, bool) {
	if pathList == "" {
		return "", false
	}
	dirs := filepath.SplitList(pathList)
	for _, dir := range dirs {
		if !filepath.IsAbs(dir) {
			return "", false
		}
	}
	for _, dir := range dirs {
		if p, err := exec.LookPath(filepath.Join(dir, name)); err == nil {
			return p, true
		}
	}
	return "", false
}
