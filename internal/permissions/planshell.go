// Read-only raw-shell classification: the product-authored allowlist of
// side-effect-free executables and the per-invocation classifier that lets any active mode auto-allow
// a pure direct pipeline of allowlisted commands. Originally Plan-only, this classification now drives
// the read-only auto-allow in every mode; Plan additionally denies every other shape without
// prompting, while Build and Auto edits prompt for it.
package permissions

import (
	"runtime"
	"slices"
	"strings"
)

var shellPlatform = runtime.GOOS

var linuxOnly = map[string]struct{}{"linux": {}}

var freebsdOnly = map[string]struct{}{"freebsd": {}}

type commandPolicy struct {
	readOnlySubcommands map[string]struct{}
	// globalValueFlags matches by exact spelling only: an over-broad match here would move the
	// subcommand position and admit a mutation, so hg's deny-side abbreviation rule is never mirrored.
	globalValueFlags map[string]struct{}
	denyFlags        []string
	// subcommandDenyFlags scans the whole stage like denyFlags, but only once the resolved
	// subcommand is its key — for a flag spelling that runs a program under one subcommand and
	// reads under another (`-O` is git grep's pager, git diff/log/show's `--order-file`).
	subcommandDenyFlags map[string][]scopedDenyFlag
	// subcommandArgs runs alongside the deny scans, never instead of them: it judges the tokens
	// after a resolved subcommand, which is what a policy-level validator cannot do because
	// stageReadOnly returns that validator's verdict before any subcommand or deny-flag work.
	subcommandArgs map[string]func(tokens []string, start int) bool
	abbrevLong     bool
	// clusterShortFlags additionally scans a bundled short-flag cluster (`rg -nz`) for a denied
	// short flag. It is opt-in because a cluster letter is not always a flag: `date -Iseconds`
	// would otherwise match date's denied `-s`.
	clusterShortFlags bool
	argSensitive      bool
	platforms         map[string]struct{}
	validator         func([]string) bool
}

// safeSpellings are the audited shorter real flags of the same subcommand that the deny flag's prefix
// rule would otherwise reject (`git grep --text` inside `--textconv`). They are listed per subcommand
// because a spelling is not safe everywhere: `git cat-file --text` resolves to `--textconv`.
type scopedDenyFlag struct {
	flag          string
	safeSpellings []string
}

var commandPolicies = map[string]commandPolicy{
	"ls":       {}, // lists directory entries; no flag writes
	"cat":      {}, // streams file contents to stdout; reads only (a `>` redirect is the shell's, routed to literal matching)
	"head":     {}, // prints leading lines/bytes; reads only
	"grep":     {}, // searches input; has no in-place rewrite mode
	"wc":       {}, // counts lines/words/bytes; reads only
	"stat":     {}, // reports file metadata; reads only
	"pwd":      {}, // prints the working directory; touches nothing external
	"du":       {}, // summarizes disk usage of paths; reads only
	"which":    {}, // reports a command's resolved PATH location; reads only
	"realpath": {}, // canonicalizes a path to stdout; reads only
	"readlink": {}, // prints a symlink's target; reads only
	"basename": {}, // strips a path to its last component; pure string transform
	"dirname":  {}, // strips a path's last component; pure string transform
	"printenv": {}, // prints environment variables; reads only
	"whoami":   {}, // prints the effective user name; reads only
	"id":       {}, // prints user/group identity; reads only
	"uname":    {}, // prints system/kernel info; reads only
	"nl":       {}, // numbers input lines to stdout; reads only
	"column":   {}, // formats input into columns on stdout; reads only
	"echo":     {}, // writes its arguments to stdout; no flag mutates state (a `>` redirect is the shell's, routed to literal matching)
	"jq":       {}, // filters/transforms JSON to stdout; no flag writes files or executes a program
	"printf":   {}, // formats its arguments to stdout; no flag writes files or executes a program
	"true":     {},
	"cut":      {},
	"tr":       {},
	"col":      {},
	"cmp":      {},
	"od":       {},
	"rg": {
		// ripgrep rejects a long-option prefix (`rg --colo=never` is an unrecognized flag), so no
		// deny flag here has to cover its own abbreviations.
		denyFlags: []string{
			"--pre",          // `rg --pre=COMMAND` runs COMMAND on every searched file
			"--hostname-bin", // runs the named executable to resolve the hostname
			"-z",             // searching compressed files spawns a decompression binary
			"--search-zip",   // long form of -z
		},
		clusterShortFlags: true,
	},
	"file": {
		denyFlags: []string{
			"-C",        // `file -C` compiles the -m magic file and writes the .mgc — `-m` alone only reads it
			"--compile", // long form of -C
			// libmagic shells out to gzip/bzip2/lzip/lrzip/zstd for a format it is not linked against.
			"-z",
			"--uncompress",
			"-Z",
			"--uncompress-noreport",
		},
		clusterShortFlags: true,
		abbrevLong:        true,
	},
	"df": {
		denyFlags:  []string{"--sync"}, // `df --sync` runs sync(2) and flushes dirty buffers
		abbrevLong: true,
	},
	"diff": {
		denyFlags:         []string{"-l", "--paginate"}, // pipes the output through `pr` found on PATH
		clusterShortFlags: true,
		abbrevLong:        true,
		platforms:         linuxOnly,
	},
	"tail": {
		denyFlags: []string{
			"-f", // follow mode reads without bound, so it is never a safe read-only diagnostic
			"-F",
			"--follow",
		},
		clusterShortFlags: true,
		abbrevLong:        true,
	},
	"sort": {
		denyFlags: []string{
			"-o",
			"--output",
			"--compress-program",
		},
		clusterShortFlags: true,
		abbrevLong:        true,
	},
	"date": {
		denyFlags: []string{
			"-s", // `date -s <time>` sets the system clock
			"--set",
		},
		abbrevLong: true, // GNU date accepts unambiguous long-option prefixes (`--se`, `--s`)
	},
	"hg": {
		// hg resolves documented aliases (`status|st`, `summary|sum`, `log|history`, `identify|id`)
		// but also unambiguous command prefixes, whose ambiguity set depends on the installed
		// extensions — so the aliases are listed and `hg sta` stays prompt-gated.
		readOnlySubcommands: map[string]struct{}{
			"status":        {}, // read-only VCS action; reports working-copy state
			"st":            {},
			"diff":          {}, // read-only VCS action; prints a diff to stdout
			"log":           {}, // read-only VCS action; prints history
			"history":       {},
			"cat":           {}, // reads a file's content at a revision to stdout (`-o`/`--output` writes — denied below)
			"summary":       {}, // rebase-status parity; prints a read-only working-directory summary
			"sum":           {},
			"files":         {},
			"help":          {},
			"grep":          {},
			"root":          {},
			"id":            {},
			"identify":      {},
			"manifest":      {},
			"parents":       {},
			"heads":         {},
			"annotate":      {},
			"blame":         {},
			"tags":          {},
			"branches":      {},
			"tip":           {},
			"paths":         {},
			"version":       {},
			"locate":        {},
			"export":        {},
			"verify":        {},
			"admin::verify": {},
			"resolve":       {}, // read-only only as the exact list forms — see subcommandArgs
			"bookmark":      {},
			"bookmarks":     {},
			"branch":        {},
			"phase":         {},
		},
		globalValueFlags: map[string]struct{}{"--cwd": {}},
		denyFlags: []string{
			"--config",     // `hg log --config=alias.x=!<shell>` / `extensions.*` executes arbitrary code
			"-R",           // retargets another repository — scope escape
			"--repository", // long form of -R
			"--pager",      // `hg --pager <cmd>` runs an arbitrary program
			"-o",           // `hg cat -o FILE` writes a file
			"--output",     // `hg cat --output=FILE` writes a file
			"--ssh",        // hg runs this value as the transport program, before any network contact
			"--remotecmd",  // hg runs this value as the program on the far end
			"--insecure",   // skips certificate verification on a remote reach
			"--debugger",   // enters pdb, which reads Python from stdin
			"-T",           // a template renders a configured auth.*.password verbatim (`hg paths -Tjson`)
			"--template",
			"--style",
		},
		subcommandDenyFlags: map[string][]scopedDenyFlag{
			// `-e` is identify's hidden --ssh short form. Program-wide it would deny `hg help -e`,
			// the documented extension-help form, because short flags match by prefix.
			"id":       {{flag: "-e"}},
			"identify": {{flag: "-e"}},
			// `--option` is neither equal to nor a prefix of the denied `--output`, so it needs its own entry.
			"admin::verify": {{flag: "--option"}},
		},
		subcommandArgs: map[string]func([]string, int) bool{
			"id":        hgIdentifyArgsReadOnly,
			"identify":  hgIdentifyArgsReadOnly,
			"resolve":   hgResolveArgsReadOnly,
			"bookmark":  hgBookmarksArgsReadOnly,
			"bookmarks": hgBookmarksArgsReadOnly,
			"branch":    hgBranchArgsReadOnly,
			"phase":     hgPhaseArgsReadOnly,
		},
		clusterShortFlags: true, // hg accepts a cluster whose last letter takes the value (`hg id -ne CMD`)
		abbrevLong:        true, // hg accepts prefix abbreviations (`--repo`, `--pag`, `--out`, `--conf`)
	},
	"git": {
		readOnlySubcommands: map[string]struct{}{
			"status":       {},
			"diff":         {},
			"log":          {},
			"show":         {},
			"ls-files":     {},
			"help":         {},
			"cat-file":     {},
			"grep":         {},
			"blame":        {},
			"ls-tree":      {},
			"describe":     {},
			"shortlog":     {},
			"show-ref":     {},
			"for-each-ref": {},
			"merge-base":   {},
			"name-rev":     {},
			"rev-list":     {},
			"check-ignore": {},
		},
		globalValueFlags: map[string]struct{}{"-C": {}},
		denyFlags: []string{
			"-c",           // `git -c core.pager=<cmd>` / `core.sshCommand` / `alias.*` / `diff.external` executes arbitrary code
			"--config-env", // same code-exec surface via an env-provided config value
			"--git-dir",    // retargets the repository — scope escape
			"--work-tree",  // retargets the work tree — scope escape
			"--exec-path",  // redirects git's own subprograms — code execution
			"--output",     // `git diff/log/show --output=FILE` writes a file
		},
		subcommandDenyFlags: map[string][]scopedDenyFlag{
			"grep": {
				{flag: "-O"}, // `git grep -O[<pager>]` runs an arbitrary program on the matches
				{flag: "--open-files-in-pager"},
				{flag: "--textconv", safeSpellings: []string{"--text"}}, // runs the config-defined textconv program
				{flag: "--ext-grep"}, // hidden compat flag that permits calling the external grep(1)
			},
			"diff": {{flag: "--textconv", safeSpellings: []string{"--text"}}},
			"log":  {{flag: "--textconv", safeSpellings: []string{"--text"}}},
			"show": {{flag: "--textconv", safeSpellings: []string{"--text"}}},
			// cat-file has no `--text` of its own, so every prefix of either flag runs a program.
			"cat-file": {{flag: "--filters"}, {flag: "--textconv"}},
			"help":     {{flag: "-w"}, {flag: "--web"}}, // `git help -w <cmd>` opens the manual in a browser — network egress
		},
		subcommandArgs: map[string]func([]string, int) bool{
			"check-ignore": gitCheckIgnoreArgsReadOnly,
		},
	},
	"jj": {
		// jj 0.44 accepts no subcommand or long-option abbreviation (`jj stat`, `jj --ignore-work`
		// are both rejected), so every admitted spelling and every denied spelling is exact.
		readOnlySubcommands: map[string]struct{}{
			"status":    {},
			"st":        {},
			"log":       {},
			"diff":      {},
			"show":      {},
			"evolog":    {},
			"interdiff": {},
			"root":      {},
			"version":   {},
			"help":      {},
		},
		globalValueFlags: map[string]struct{}{"--color": {}},
		denyFlags: []string{
			"--config",       // `jj --config ui.diff-formatter=<cmd>` names a program jj then runs
			"--config-file",  // the same code-exec surface, supplied as a file
			"-R",             // retargets another repository — scope escape
			"--repository",   // long form of -R
			"--at-operation", // loads the repo at another operation — scope escape
			"--at-op",        // documented alias of --at-operation
			"--tool",         // names an external diff program on diff/show/log -p/evolog/interdiff
			"-T",             // a template reads configuration back out (`-T 'config("ui.pager")'`)
			"--template",
		},
		clusterShortFlags: true, // clap clusters a value-taking last letter (`jj log -pT'{id}'`)
	},
	"find": {
		argSensitive: true,
		validator:    findStageReadOnly,
	},
	"uniq":       {argSensitive: true, validator: uniqStageReadOnly},
	"sed":        {argSensitive: true, validator: sedStageReadOnly},
	"awk":        {argSensitive: true, validator: awkStageReadOnly},
	"bash":       {argSensitive: true, validator: noExecShellTokens},
	"sh":         {argSensitive: true, validator: noExecShellTokens},
	"env":        {argSensitive: true, validator: bareEnvTokens},
	"command":    {argSensitive: true, validator: commandLookupTokens},
	"type":       {argSensitive: true, validator: typeLookupTokens},
	"test":       {argSensitive: true, validator: testStageReadOnly},
	"[":          {argSensitive: true, validator: testStageReadOnly},
	"ps":         {argSensitive: true, platforms: linuxOnly, validator: psStageReadOnly},
	"pgrep":      {argSensitive: true, platforms: linuxOnly, validator: pgrepStageReadOnly},
	"pidof":      {argSensitive: true, platforms: linuxOnly, validator: pidofStageReadOnly},
	"pstree":     {argSensitive: true, platforms: linuxOnly, validator: pstreeStageReadOnly},
	"lsof":       {argSensitive: true, platforms: linuxOnly, validator: lsofStageReadOnly},
	"ss":         {argSensitive: true, platforms: linuxOnly, validator: ssStageReadOnly},
	"free":       {argSensitive: true, platforms: linuxOnly, validator: freeStageReadOnly},
	"vmstat":     {argSensitive: true, platforms: linuxOnly, validator: vmstatStageReadOnly},
	"uptime":     {argSensitive: true, platforms: linuxOnly, validator: uptimeStageReadOnly},
	"journalctl": {argSensitive: true, platforms: linuxOnly, validator: journalctlStageReadOnly},
	"dmesg":      {argSensitive: true, platforms: linuxOnly, validator: dmesgStageReadOnly},
	"top":        {argSensitive: true, platforms: linuxOnly, validator: topStageReadOnly},
}

var freebsdCommandPolicies = map[string]commandPolicy{
	"ps":       {argSensitive: true, platforms: freebsdOnly, validator: psStageReadOnly},
	"pgrep":    {argSensitive: true, platforms: freebsdOnly, validator: freebsdPgrepStageReadOnly},
	"pidof":    {argSensitive: true, platforms: freebsdOnly, validator: freebsdPidofStageReadOnly},
	"pstree":   {argSensitive: true, platforms: freebsdOnly, validator: freebsdPstreeStageReadOnly},
	"fstat":    {argSensitive: true, platforms: freebsdOnly, validator: freebsdFstatStageReadOnly},
	"procstat": {argSensitive: true, platforms: freebsdOnly, validator: freebsdProcstatStageReadOnly},
	"sockstat": {argSensitive: true, platforms: freebsdOnly, validator: freebsdSockstatStageReadOnly},
	"vmstat":   {argSensitive: true, platforms: freebsdOnly, validator: freebsdVMStatStageReadOnly},
	"uptime":   {argSensitive: true, platforms: freebsdOnly, validator: freebsdUptimeStageReadOnly},
}

// Short flags (`-c`, `-o`, `-R`) match the exact token and the glued-value form (`-oFILE`). The match
// is conservative — over-matching only forces a prompt, never an auto-allow — so a benign token
// sharing a short-flag prefix simply falls through to a prompt; the abbreviation match is likewise
// deliberately broader than hg's own uniqueness rule rather than replicating it.
func stageMatchesDenyFlag(token string, denyFlags []string, abbrevLong bool) bool {
	for _, f := range denyFlags {
		if strings.HasPrefix(f, "--") {
			name := token
			if i := strings.IndexByte(token, '='); i >= 0 { // `--flag=value` → `--flag`
				name = token[:i]
			}
			if name == f {
				return true
			}
			if abbrevLong && len(name) > 2 && strings.HasPrefix(f, name) {
				return true
			}
			continue
		}
		if strings.HasPrefix(token, f) { // short flag: exact or glued value
			return true
		}
	}
	return false
}

// clusterHidesDenyFlag reports whether a bundled short-flag cluster carries a denied short flag
// anywhere but its first position, which stageMatchesDenyFlag's prefix test cannot see (`rg -nz` is
// a working spelling of `rg -z`, while `rg -zn` already matches). Over-denial inside a cluster only
// costs a prompt; under-denial admits the flag the list exists to reject.
func clusterHidesDenyFlag(token string, denyFlags []string) bool {
	if len(token) < 3 || token[0] != '-' || token[1] == '-' {
		return false
	}
	for _, f := range denyFlags {
		if len(f) != 2 || f[0] != '-' {
			continue
		}
		if strings.IndexByte(token[1:], f[1]) >= 0 {
			return true
		}
	}
	return false
}

// Git resolves any unambiguous abbreviation of a subcommand long option, and which abbreviations are
// unambiguous changes with the flag set of the installed version, so a scoped long flag denies every
// prefix of itself rather than the spellings one binary happens to accept. The audited safe spellings
// are the only exemption; anything longer is an abbreviation of the denied flag.
func stageMatchesScopedDenyFlag(token string, denyFlags []scopedDenyFlag) bool {
	for _, f := range denyFlags {
		if !strings.HasPrefix(f.flag, "--") {
			if strings.HasPrefix(token, f.flag) { // short flag: exact or glued value
				return true
			}
			continue
		}
		name := token
		if i := strings.IndexByte(token, '='); i >= 0 {
			name = token[:i]
		}
		if name == f.flag {
			return true
		}
		if len(name) > 2 && strings.HasPrefix(f.flag, name) && !slices.Contains(f.safeSpellings, name) {
			return true
		}
	}
	return false
}

// The separate value of a globalValueFlags token is skipped so that a directory named like an
// admitted subcommand (`hg --cwd status commit`) cannot stand in for one.
func (p commandPolicy) stageSubcommand(tokens []string) (sub string, at int, ok bool) {
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if !strings.HasPrefix(tok, "-") {
			return tok, i, true
		}
		name := tok
		joined := false
		if eq := strings.IndexByte(tok, '='); eq >= 0 {
			name, joined = tok[:eq], true
		}
		if _, ok := p.globalValueFlags[name]; !ok {
			return "", 0, false
		}
		if !joined {
			i++
		}
	}
	return "", 0, false
}

// hgIdentifyValueFlags are the identify flags whose value is a separate token, so that value is not
// read as a positional. Every other value-taking identify flag is already denied outright.
var hgIdentifyValueFlags = map[string]struct{}{"-r": {}, "--rev": {}, "--cwd": {}}

// hg resolves a positional SOURCE through the `[paths]` configuration, so `hg id default` reaches a
// remote with no URL text in the stage, over a transport program a clustered `-ne CMD` can still
// supply. Rejecting every positional is the control; the transport deny flags are defense in depth.
func hgIdentifyArgsReadOnly(tokens []string, start int) bool {
	for i := start; i < len(tokens); i++ {
		tok := tokens[i]
		if len(tok) < 2 || tok[0] != '-' {
			return false
		}
		if _, ok := hgIdentifyValueFlags[tok]; ok {
			i++
		}
	}
	return true
}

// Only the two exact list spellings read: `hg resolve --tool CMD` runs an arbitrary merge program,
// and `-m`/`-u`/`--all` rewrite merge state.
func hgResolveArgsReadOnly(tokens []string, start int) bool {
	return len(tokens) == start+1 && (tokens[start] == "-l" || tokens[start] == "--list")
}

// Only the bare and exact list spellings read: a positional NAME creates a bookmark, and
// `-d`/`-m`/`-r`/`-i`/`-f` delete, rename, or move one. `-T` is denied program-wide.
func hgBookmarksArgsReadOnly(tokens []string, start int) bool {
	switch len(tokens) - start {
	case 0:
		return true
	case 1:
		return tokens[start] == "-l" || tokens[start] == "--list"
	default:
		return false
	}
}

// Bare `hg branch` prints the working-directory branch; every argument it takes sets one, including
// the `-r`/`--rev` spelling that reads under phase.
func hgBranchArgsReadOnly(tokens []string, start int) bool {
	return len(tokens) == start
}

// `-p`/`-d`/`-s` move the phase boundary, which is not locally reversible once published, so only
// the repeatable `-r`/`--rev` selector is admitted; a value-less spelling of it fails closed.
func hgPhaseArgsReadOnly(tokens []string, start int) bool {
	for i := start; i < len(tokens); i++ {
		name, joined := tokens[i], false
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name, joined = name[:eq], true
		}
		if name != "-r" && name != "--rev" {
			return false
		}
		if !joined {
			if i+1 >= len(tokens) {
				return false
			}
			i++
		}
	}
	return true
}

var gitCheckIgnoreFlags = map[string]struct{}{
	"-q": {}, "--quiet": {}, "-v": {}, "--verbose": {}, "--stdin": {}, "-z": {}, "-n": {}, "--non-matching": {},
}

// Reading the index runs a repository-configured `core.fsmonitor` program, so only the exact
// `--no-index` spelling is admitted; git would also read `--index` or an abbreviation as turning it off.
func gitCheckIgnoreArgsReadOnly(tokens []string, start int) bool {
	noIndex := false
	for _, tok := range tokens[start:] {
		if tok == "--" {
			break
		}
		if !strings.HasPrefix(tok, "-") {
			continue
		}
		if tok == "--no-index" {
			noIndex = true
			continue
		}
		if _, ok := gitCheckIgnoreFlags[tok]; !ok {
			return false
		}
	}
	return noIndex
}

func (p commandPolicy) stageReadOnly(tokens []string) bool {
	if !p.appliesToPlatform() {
		return false
	}
	if p.validator != nil {
		return p.validator(tokens)
	}
	var subDenyFlags []scopedDenyFlag
	if p.readOnlySubcommands != nil {
		sub, at, ok := p.stageSubcommand(tokens)
		if !ok {
			return false
		}
		if _, ok := p.readOnlySubcommands[sub]; !ok {
			return false
		}
		if check, ok := p.subcommandArgs[sub]; ok && !check(tokens, at+1) {
			return false
		}
		subDenyFlags = p.subcommandDenyFlags[sub]
	}
	for _, tok := range tokens {
		if stageMatchesDenyFlag(tok, p.denyFlags, p.abbrevLong) {
			return false
		}
		if p.clusterShortFlags && clusterHidesDenyFlag(tok, p.denyFlags) {
			return false
		}
		if stageMatchesScopedDenyFlag(tok, subDenyFlags) {
			return false
		}
	}
	return true
}

func (p commandPolicy) appliesToPlatform() bool {
	if len(p.platforms) == 0 {
		return true
	}
	_, ok := p.platforms[shellPlatform]
	return ok
}

// findNoValuePredicates are the only no-value read-only find predicates, actions, and boolean
// operators the safe subset accepts. Every other primary/action (`-delete`, `-exec`, `-prune`,
// `-printf`, `-fls`, …) is unlisted and so classifies mutating.
var findNoValuePredicates = map[string]struct{}{
	"-empty":  {}, // matches empty files/dirs; reads only
	"-print":  {}, // prints matched paths to stdout; reads only
	"-print0": {}, // prints matched paths NUL-separated; reads only
	"-o":      {}, // boolean or
	"-a":      {}, // boolean and
	"-not":    {},
	"!":       {},
}

// findBooleanOperators maps each operator admitted by findNoValuePredicates to whether it requires a
// complete expression on its left. All four require one on their right.
var findBooleanOperators = map[string]bool{
	"-o":   true,
	"-a":   true,
	"-not": false,
	"!":    false,
}

// findValuePredicates are the only value-taking read-only find predicates the safe subset accepts,
// each mapped to the validator its single following value token must pass. A predicate with a missing
// or invalid value classifies mutating.
var findValuePredicates = map[string]func(string) bool{
	"-type":     findValidType,      // one standard single-letter file-type code
	"-name":     findValidPattern,   // one glob pattern token
	"-iname":    findValidPattern,   // case-insensitive glob
	"-path":     findValidPattern,   // glob against the whole path
	"-ipath":    findValidPattern,   // case-insensitive path glob
	"-maxdepth": findValidNonNegInt, // non-negative depth limit
	"-mindepth": findValidNonNegInt, // non-negative depth floor
	"-mtime":    findValidTimeInt,   // find-style signed integer (days)
	"-ctime":    findValidTimeInt,
	"-atime":    findValidTimeInt,
	"-mmin":     findValidTimeInt, // find-style signed integer (minutes)
	"-cmin":     findValidTimeInt,
	"-amin":     findValidTimeInt,
	"-size":     findValidSize, // find-style size expression, e.g. 0, +1M, -100k
	"-newer":    findValidStartPath,
}

func findStageReadOnly(tokens []string) bool {
	i := 1
	paths := 0
	for i < len(tokens) && findValidStartPath(tokens[i]) {
		paths++
		i++
	}
	if paths == 0 { // a safe subset always names at least one relative start path
		return false
	}
	exprStart := i
	complete := false // whether a complete expression ends at the current position
	for i < len(tokens) {
		tok := tokens[i]
		if valid, ok := findValuePredicates[tok]; ok {
			if i+1 >= len(tokens) || !valid(tokens[i+1]) {
				return false // missing or invalid value
			}
			if _, isOperator := findBooleanOperators[tokens[i+1]]; isOperator {
				return false
			}
			complete = true
			i += 2
			continue
		}
		if _, ok := findNoValuePredicates[tok]; ok {
			if needsLeft, isOperator := findBooleanOperators[tok]; isOperator {
				if needsLeft && !complete {
					return false
				}
				complete = false
			} else {
				complete = true
			}
			i++
			continue
		}
		return false // unknown option/action/operator, or a late plain path token
	}
	return complete || i == exprStart
}

// Narrowing the start-path posture below the broader raw-shell path scope is deliberate;
// broadening it needs explicit review.
func findValidStartPath(tok string) bool {
	switch tok {
	case "", "!", "(", ")", ",":
		return false
	}
	if tok[0] == '-' || tok[0] == '/' { // option/operator/`--`/dash-leading, or absolute
		return false
	}
	if tok[0] == '~' || tok[0] == '$' { // expanded to a home path at exec, after classification
		return false
	}
	for _, seg := range strings.Split(tok, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// findValidType reports whether v is one standard single-letter find file-type code. The set is the
// portable intersection across GNU, BSD/macOS, and BusyBox find; platform-specific codes fail closed.
func findValidType(v string) bool {
	return len(v) == 1 && strings.IndexByte("bcdpfls", v[0]) >= 0
}

// findValidPattern reports whether v is a usable glob pattern token — any non-empty token, since find
// consumes the token after `-name`/`-path` literally as the pattern and never executes it.
func findValidPattern(v string) bool {
	return v != ""
}

// findValidNonNegInt reports whether v is a non-negative decimal integer (for -maxdepth/-mindepth).
func findValidNonNegInt(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// findValidTimeInt reports whether v is a find-style signed integer (`0`, `1`, `-1`, `+7`) for the
// -mtime/-ctime/-atime/-mmin/-cmin/-amin predicates.
func findValidTimeInt(v string) bool {
	if v != "" && (v[0] == '+' || v[0] == '-') {
		v = v[1:]
	}
	return findValidNonNegInt(v)
}

// findValidSize reports whether v is a find-style size expression: an optional `+`/`-` prefix, a
// decimal magnitude, and an optional single unit suffix from the portable set (`b`,`c`,`w`,`k`,`M`,`G`),
// e.g. `0`, `+1M`, `-100k`.
func findValidSize(v string) bool {
	if v != "" && (v[0] == '+' || v[0] == '-') {
		v = v[1:]
	}
	if v != "" && strings.IndexByte("bcwkMG", v[len(v)-1]) >= 0 {
		v = v[:len(v)-1]
	}
	return findValidNonNegInt(v)
}

func sedStageReadOnly(tokens []string) bool {
	args := tokens[1:]
	i := 0
	for i < len(args) && sedReadOnlyOption(args[i]) {
		i++
	}
	if i >= len(args) || !sedPrintOnlyScript(args[i]) {
		return false
	}
	files := args[i+1:]
	for _, f := range files {
		if f == "" || strings.HasPrefix(f, "-") {
			return false
		}
	}
	return true
}

func sedReadOnlyOption(tok string) bool {
	switch tok {
	case "-n", "--quiet", "--silent":
		return true
	}
	return false
}

func sedPrintOnlyScript(s string) bool {
	for _, command := range strings.Split(s, ";") {
		if !sedReadOnlyCommand(command) {
			return false
		}
	}
	return true
}

func sedReadOnlyCommand(s string) bool {
	body, addresses, ok := sedTrimAddress(s)
	if !ok || body == "" {
		return false
	}
	if body[0] == 'q' {
		return body == "q" && addresses < 2
	}
	if body[0] != 'p' && body[0] != '=' {
		return false
	}
	rest := body[1:]
	return rest == "" || rest == "q"
}

func sedTrimAddress(s string) (string, int, bool) {
	if rest, ok := strings.CutPrefix(s, "$"); ok {
		if strings.HasPrefix(rest, ",") {
			return "", 0, false
		}
		return rest, 1, true
	}
	rest, n := sedTrimAddressPart(s)
	if n == 0 {
		return rest, 0, true
	}
	if !strings.HasPrefix(rest, ",") {
		return rest, 1, true
	}
	rest, n = sedTrimAddressPart(rest[1:])
	if n == 0 {
		return "", 0, false
	}
	return rest, 2, true
}

func sedTrimAddressPart(s string) (string, int) {
	if strings.HasPrefix(s, "$") {
		return s[1:], 1
	}
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return s[n:], n
}

func awkStageReadOnly(tokens []string) bool {
	args := tokens[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch {
		case args[0] == "-F" && len(args) > 1 && args[1] != "":
			args = args[2:]
		case len(args[0]) > 2 && strings.HasPrefix(args[0], "-F"):
			args = args[1:]
		default:
			return false
		}
	}
	if len(args) == 0 || !awkRangePrintProgram(args[0]) && !awkReadOnlyProgram(args[0]) {
		return false
	}
	// AWK reads a `name=value` operand as an assignment, and GNU AWK opens `/dev/tcp`, `/dev/udp`,
	// and `/inet` paths as network connections.
	for _, f := range args[1:] {
		if f == "" || strings.HasPrefix(f, "-") || strings.Contains(f, "=") {
			return false
		}
		if strings.HasPrefix(f, "/dev/") || strings.HasPrefix(f, "/inet") {
			return false
		}
	}
	return true
}

func awkRangePrintProgram(s string) bool {
	rest, counter, ok := awkCounter(awkSpace(s))
	if !ok {
		return false
	}
	if rest, ok = awkBound(rest, ">="); !ok {
		return false
	}
	if rest, ok = strings.CutPrefix(awkSpace(rest), "&&"); !ok {
		return false
	}
	rest, upper, ok := awkCounter(awkSpace(rest))
	if !ok || upper != counter {
		return false
	}
	if rest, ok = awkBound(rest, "<="); !ok {
		return false
	}
	if rest, ok = strings.CutPrefix(awkSpace(rest), "{"); !ok {
		return false
	}
	if rest, ok = awkWord(awkSpace(rest), "print"); !ok {
		return false
	}
	for {
		rest = awkSpace(rest)
		if after, closed := strings.CutPrefix(rest, "}"); closed {
			return awkSpace(after) == ""
		}
		if rest, ok = awkTerm(rest); !ok {
			return false
		}
	}
}

func awkBound(s, op string) (string, bool) {
	rest, ok := strings.CutPrefix(awkSpace(s), op)
	if !ok {
		return "", false
	}
	return awkDigits(awkSpace(rest))
}

func awkTerm(s string) (string, bool) {
	switch {
	case s == "":
		return "", false
	case s[0] == '"':
		return awkString(s)
	case s[0] == '$':
		return awkWord(s[1:], "0")
	case s[0] >= '0' && s[0] <= '9':
		return awkDigits(s)
	}
	rest, _, ok := awkCounter(s)
	return rest, ok
}

func awkCounter(s string) (string, string, bool) {
	for _, name := range []string{"FNR", "NR"} {
		if rest, ok := awkWord(s, name); ok {
			return rest, name, true
		}
	}
	return "", "", false
}

func awkString(s string) (string, bool) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return s[i+1:], true
		case '\\', '\n':
			return "", false
		}
	}
	return "", false
}

func awkDigits(s string) (string, bool) {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	if n == 0 {
		return "", false
	}
	return awkWord(s, s[:n])
}

func awkWord(s, lit string) (string, bool) {
	rest, ok := strings.CutPrefix(s, lit)
	if !ok || !awkBoundary(rest) {
		return "", false
	}
	return rest, true
}

// A trailing `.` or word character means the token continues into something the grammar never
// admits: `printf`, a `NR`-prefixed variable, or a float/exponent bound.
func awkBoundary(s string) bool {
	if s == "" {
		return true
	}
	switch c := s[0]; {
	case c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_', c == '.':
		return false
	}
	return true
}

func awkSpace(s string) string {
	return strings.TrimLeft(s, " \t")
}

func uniqStageReadOnly(tokens []string) bool {
	args := tokens[1:]
	if len(args) == 1 && (args[0] == "--help" || args[0] == "--version") {
		return true
	}
	bareOptionalMethod := false
	for len(args) > 0 {
		if uniqReadOnlyOption(args[0]) {
			bareOptionalMethod = args[0] == "--all-repeated" || args[0] == "--group"
			args = args[1:]
			continue
		}
		n := uniqValueOptionTokens(args)
		if n < 0 {
			return false
		}
		if n == 0 {
			break
		}
		bareOptionalMethod = false
		args = args[n:]
	}
	if len(args) == 0 {
		return true
	}
	if bareOptionalMethod {
		return false
	}
	return len(args) == 1 && !strings.HasPrefix(args[0], "-")
}

func uniqReadOnlyOption(tok string) bool {
	switch tok {
	case "-c", "--count", "-d", "--repeated", "-D", "--all-repeated":
		return true
	case "-i", "--ignore-case", "-u", "--unique", "-z", "--zero-terminated":
		return true
	case "--all-repeated=none", "--all-repeated=prepend", "--all-repeated=separate":
		return true
	case "--group", "--group=separate", "--group=prepend", "--group=append", "--group=both":
		return true
	}
	return false
}

func uniqValueOptionTokens(args []string) int {
	tok := args[0]
	for _, opt := range []struct{ short, long string }{
		{"-f", "--skip-fields"},
		{"-s", "--skip-chars"},
		{"-w", "--check-chars"},
	} {
		switch {
		case tok == opt.short, tok == opt.long:
			if len(args) > 1 && findValidNonNegInt(args[1]) {
				return 2
			}
			return -1
		case strings.HasPrefix(tok, opt.short):
			if findValidNonNegInt(tok[len(opt.short):]) {
				return 1
			}
			return -1
		case strings.HasPrefix(tok, opt.long+"="):
			if findValidNonNegInt(tok[len(opt.long)+1:]) {
				return 1
			}
			return -1
		}
	}
	return 0
}

const (
	maxDiagInterval = 3600
	maxDiagCount    = 1000
)

func validBoundedInt(v string, max int) bool {
	if !findValidNonNegInt(v) {
		return false
	}
	n := 0
	for i := 0; i < len(v); i++ {
		digit := int(v[i] - '0')
		if n > max/10 || (n == max/10 && digit > max%10) {
			return false
		}
		n = n*10 + digit
	}
	return true
}

func validPositiveBoundedInt(v string, max int) bool {
	if !validBoundedInt(v, max) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] != '0' {
			return true
		}
	}
	return false
}

func validPidList(v string) bool {
	if v == "" {
		return false
	}
	for _, p := range strings.Split(v, ",") {
		if !findValidNonNegInt(p) {
			return false
		}
	}
	return true
}

// No documented Linux or FreeBSD ps(1) option writes a file, executes another program, opens a
// network connection, or escapes scope, and its operands are PIDs, so the option set is not
// restricted. Command-substitution syntax — "$(" or a backtick — is refused because it names
// another program to run; SplitCommand already keeps every substitution the shell would perform off
// direct execution, so this refusal only costs a prompt for inert quoted text. Every other argument
// spelling, including a quoted variable or glob, only changes argument text and is inert under
// direct execution, which runs the literal argv.
func psStageReadOnly(tokens []string) bool {
	for _, tok := range tokens[1:] {
		if strings.Contains(tok, "$(") || strings.Contains(tok, "`") {
			return false
		}
	}
	return true
}

// Any argv is inert only when test(1) runs directly: `sh -c` selects the shell builtin, whose bash
// `-v` primary runs a command substitution inside an array subscript, so the policy stays argSensitive.
func testStageReadOnly([]string) bool {
	return true
}

const pgrepFlags = "flaicvwxno"

func pgrepStageReadOnly(tokens []string) bool {
	operands := 0
	selectors := 0
	i := 1
	for i < len(tokens) {
		tok := tokens[i]
		switch tok {
		case "-u", "-U", "-P":
			if i+1 >= len(tokens) {
				return false
			}
			val := tokens[i+1]
			if tok == "-P" {
				if !validPidList(val) {
					return false
				}
			} else if val == "" {
				return false
			}
			selectors++
			i += 2
			continue
		}
		if strings.HasPrefix(tok, "-") {
			if len(tok) < 2 {
				return false
			}
			for k := 1; k < len(tok); k++ {
				if strings.IndexByte(pgrepFlags, tok[k]) < 0 {
					return false
				}
			}
			i++
			continue
		}
		operands++
		if operands > 1 {
			return false
		}
		i++
	}
	return operands+selectors >= 1
}

const pidofFlags = "sxqcz"

func pidofStageReadOnly(tokens []string) bool {
	names := 0
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			if len(tok) < 2 {
				return false
			}
			for k := 1; k < len(tok); k++ {
				if strings.IndexByte(pidofFlags, tok[k]) < 0 {
					return false
				}
			}
			continue
		}
		if tok == "" {
			return false
		}
		names++
	}
	return names >= 1
}

const pstreeFlags = "panhugscl"

func pstreeStageReadOnly(tokens []string) bool {
	operands := 0
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			if len(tok) < 2 {
				return false
			}
			for k := 1; k < len(tok); k++ {
				if strings.IndexByte(pstreeFlags, tok[k]) < 0 {
					return false
				}
			}
			continue
		}
		if tok == "" {
			return false
		}
		operands++
		if operands > 1 {
			return false
		}
	}
	return true
}

func lsofStageReadOnly(tokens []string) bool {
	return len(tokens) == 3 && tokens[1] == "-p" && findValidNonNegInt(tokens[2])
}

const ssReadFlags = "tulnpaemis46xwH"

func ssStageReadOnly(tokens []string) bool {
	for _, tok := range tokens[1:] {
		if len(tok) < 2 || tok[0] != '-' {
			return false
		}
		for k := 1; k < len(tok); k++ {
			if strings.IndexByte(ssReadFlags, tok[k]) < 0 {
				return false
			}
		}
	}
	return true
}

const freeFlags = "bkmghtwlo"

func freeStageReadOnly(tokens []string) bool {
	hasS, hasC := false, false
	i := 1
	for i < len(tokens) {
		tok := tokens[i]
		if len(tok) < 2 || tok[0] != '-' {
			return false
		}
		if tok == "-s" || tok == "-c" {
			if i+1 >= len(tokens) {
				return false
			}
			if tok == "-s" {
				if !validBoundedInt(tokens[i+1], maxDiagInterval) {
					return false
				}
				hasS = true
			} else {
				if !validBoundedInt(tokens[i+1], maxDiagCount) {
					return false
				}
				hasC = true
			}
			i += 2
			continue
		}
		if strings.HasPrefix(tok, "-s") {
			if !validBoundedInt(tok[2:], maxDiagInterval) {
				return false
			}
			hasS = true
			i++
			continue
		}
		if strings.HasPrefix(tok, "-c") {
			if !validBoundedInt(tok[2:], maxDiagCount) {
				return false
			}
			hasC = true
			i++
			continue
		}
		for k := 1; k < len(tok); k++ {
			if strings.IndexByte(freeFlags, tok[k]) < 0 {
				return false
			}
		}
		i++
	}
	return hasS == hasC
}

const vmstatFlags = "asdDwtnfm"

func vmstatStageReadOnly(tokens []string) bool {
	operands := make([]string, 0, 2)
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			if len(tok) < 2 {
				return false
			}
			for k := 1; k < len(tok); k++ {
				if strings.IndexByte(vmstatFlags, tok[k]) < 0 {
					return false
				}
			}
			continue
		}
		operands = append(operands, tok)
	}
	switch len(operands) {
	case 0:
		return true
	case 2:
		return validBoundedInt(operands[0], maxDiagInterval) && validBoundedInt(operands[1], maxDiagCount)
	default:
		return false
	}
}

func uptimeStageReadOnly(tokens []string) bool {
	for _, tok := range tokens[1:] {
		if tok != "-p" && tok != "-s" {
			return false
		}
	}
	return true
}

func freebsdPgrepStageReadOnly(tokens []string) bool {
	patterns := 0
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "" {
			return false
		}
		if tok[0] != '-' {
			patterns++
			continue
		}
		if len(tok) < 2 || strings.HasPrefix(tok, "--") || patterns > 0 {
			return false
		}
		for j := 1; j < len(tok); j++ {
			if strings.IndexByte("Safilnoqvx", tok[j]) >= 0 {
				continue
			}
			if strings.IndexByte("GPUgsu", tok[j]) < 0 {
				return false
			}
			value := tok[j+1:]
			if value == "" {
				if i+1 >= len(tokens) {
					return false
				}
				value = tokens[i+1]
				i++
			}
			if !validPidList(value) {
				return false
			}
			j = len(tok)
		}
	}
	return patterns > 0
}

func freebsdPidofStageReadOnly(tokens []string) bool {
	names := 0
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			if len(tok) < 2 {
				return false
			}
			for i := 1; i < len(tok); i++ {
				if strings.IndexByte("sxqz", tok[i]) < 0 {
					return false
				}
			}
			continue
		}
		if tok == "" {
			return false
		}
		names++
	}
	return names > 0
}

func freebsdPstreeStageReadOnly(tokens []string) bool {
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "-U" || tok == "-w" {
			continue
		}
		if tok == "-g" || tok == "-l" || tok == "-p" {
			if i+1 >= len(tokens) {
				return false
			}
			value := tokens[i+1]
			if tok == "-g" {
				if value != "1" && value != "2" && value != "3" {
					return false
				}
			} else if tok == "-l" && !validPositiveBoundedInt(value, maxDiagCount) {
				return false
			} else if tok == "-p" && !findValidNonNegInt(value) {
				return false
			}
			i++
			continue
		}
		if !findValidNonNegInt(tok) {
			return false
		}
	}
	return true
}

func freebsdFstatStageReadOnly(tokens []string) bool {
	return len(tokens) == 3 && tokens[1] == "-p" && findValidNonNegInt(tokens[2])
}

func freebsdProcstatStageReadOnly(tokens []string) bool {
	return len(tokens) == 3 && (tokens[1] == "-f" || tokens[1] == "-k" || tokens[1] == "-r") && findValidNonNegInt(tokens[2])
}

const freebsdSockstatFlags = "46AbCcfIiLlnqSsUuv"

func freebsdSockstatStageReadOnly(tokens []string) bool {
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "-j" || tok == "-p" {
			if i+1 >= len(tokens) {
				return false
			}
			value := tokens[i+1]
			if tok == "-j" {
				if !findValidNonNegInt(value) {
					return false
				}
			} else if !freebsdValidPortList(value) {
				return false
			}
			i++
			continue
		}
		if len(tok) < 2 || tok[0] != '-' || strings.HasPrefix(tok, "--") {
			return false
		}
		for j := 1; j < len(tok); j++ {
			if strings.IndexByte(freebsdSockstatFlags, tok[j]) < 0 {
				return false
			}
		}
	}
	return true
}

func freebsdValidPortList(value string) bool {
	if value == "" {
		return false
	}
	for _, item := range strings.Split(value, ",") {
		parts := strings.Split(item, "-")
		if len(parts) > 2 {
			return false
		}
		for _, part := range parts {
			if !validPositiveBoundedInt(part, 65535) {
				return false
			}
		}
	}
	return true
}

const freebsdVMStatFlags = "afHhimoPsz"

func freebsdVMStatStageReadOnly(tokens []string) bool {
	hasWait := false
	hasCount := false
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "-c" || tok == "-n" || tok == "-w" {
			if i+1 >= len(tokens) {
				return false
			}
			max := maxDiagCount
			switch tok {
			case "-w":
				max = maxDiagInterval
				hasWait = true
			case "-c":
				hasCount = true
			}
			if !validPositiveBoundedInt(tokens[i+1], max) {
				return false
			}
			i++
			continue
		}
		if len(tok) < 2 || tok[0] != '-' || strings.HasPrefix(tok, "--") {
			return false
		}
		for j := 1; j < len(tok); j++ {
			if strings.IndexByte(freebsdVMStatFlags, tok[j]) < 0 {
				return false
			}
		}
	}
	return !hasWait || hasCount
}

func freebsdUptimeStageReadOnly(tokens []string) bool {
	return len(tokens) == 1
}

const maxJournalLines = 1000

// systemd does not accept flag abbreviations.
var journalctlDenyFlags = []string{
	"-f", "--follow",
	"--vacuum-size", "--vacuum-time", "--vacuum-files",
	"--rotate", "--flush", "--sync", "--relinquish-var",
	"--setup-keys", "--verify",
	"--root", "-D", "--directory", "--file",
	"-M", "--machine", "--namespace",
	"--output-fields", "-o", "--output",
	"-e", "--pager-end",
}

func journalctlStageReadOnly(tokens []string) bool {
	for _, tok := range tokens[1:] {
		if stageMatchesDenyFlag(tok, journalctlDenyFlags, false) {
			return false
		}
	}
	hasNoPager := false
	hasBoundedLines := false
	i := 1
	for i < len(tokens) {
		tok := tokens[i]
		switch {
		case tok == "--no-pager":
			hasNoPager = true
			i++
		case tok == "-n" || tok == "--lines":
			if i+1 >= len(tokens) || !validPositiveBoundedInt(tokens[i+1], maxJournalLines) {
				return false
			}
			hasBoundedLines = true
			i += 2
		case strings.HasPrefix(tok, "--lines="):
			if !validPositiveBoundedInt(tok[len("--lines="):], maxJournalLines) {
				return false
			}
			hasBoundedLines = true
			i++
		case strings.HasPrefix(tok, "-n") && len(tok) > 2:
			if !validPositiveBoundedInt(tok[2:], maxJournalLines) {
				return false
			}
			hasBoundedLines = true
			i++
		case tok == "-u" || tok == "--unit" || tok == "-p" || tok == "--priority" || tok == "--since" || tok == "--until":
			if i+1 >= len(tokens) || tokens[i+1] == "" {
				return false
			}
			i += 2
		case strings.HasPrefix(tok, "--unit=") || strings.HasPrefix(tok, "--priority=") || strings.HasPrefix(tok, "--since=") || strings.HasPrefix(tok, "--until="):
			if eq := strings.IndexByte(tok, '='); eq+1 >= len(tok) {
				return false
			}
			i++
		case strings.HasPrefix(tok, "-u") && len(tok) > 2, strings.HasPrefix(tok, "-p") && len(tok) > 2:
			i++
		default:
			return false
		}
	}
	return hasNoPager && hasBoundedLines
}

const dmesgReadFlags = "HxTtkuredS"

const maxDmesgBufferBytes = 1 << 20

func dmesgStageReadOnly(tokens []string) bool {
	hasNoPager := false
	hasBoundedBuffer := false
	i := 1
	for i < len(tokens) {
		tok := tokens[i]
		if len(tok) < 2 || tok[0] != '-' {
			return false
		}
		if strings.HasPrefix(tok, "--") {
			name := tok
			val := ""
			hasVal := false
			if eq := strings.IndexByte(tok, '='); eq >= 0 {
				name = tok[:eq]
				val = tok[eq+1:]
				hasVal = true
			}
			switch name {
			case "--nopager":
				if hasVal {
					return false
				}
				hasNoPager = true
				i++
			case "--buffer-size":
				if hasVal {
					if !validPositiveBoundedInt(val, maxDmesgBufferBytes) {
						return false
					}
					i++
				} else {
					if i+1 >= len(tokens) || !validPositiveBoundedInt(tokens[i+1], maxDmesgBufferBytes) {
						return false
					}
					i += 2
				}
				hasBoundedBuffer = true
			case "--human", "--decode", "--ctime", "--notime", "--kernel", "--userspace", "--raw", "--reltime", "--show-delta", "--syslog":
				if hasVal {
					return false
				}
				i++
			case "--level", "--facility":
				if hasVal {
					if val == "" {
						return false
					}
					i++
				} else {
					if i+1 >= len(tokens) || tokens[i+1] == "" {
						return false
					}
					i += 2
				}
			default:
				return false
			}
			continue
		}
		consumedValue := false
		for j := 1; j < len(tok); j++ {
			c := tok[j]
			if c == 'P' {
				hasNoPager = true
				continue
			}
			if c == 's' {
				if tok[j+1:] != "" {
					if !validPositiveBoundedInt(tok[j+1:], maxDmesgBufferBytes) {
						return false
					}
				} else {
					if i+1 >= len(tokens) || !validPositiveBoundedInt(tokens[i+1], maxDmesgBufferBytes) {
						return false
					}
					consumedValue = true
				}
				hasBoundedBuffer = true
				break
			}
			if c == 'l' || c == 'f' {
				if tok[j+1:] != "" {
					break
				}
				if i+1 >= len(tokens) || tokens[i+1] == "" {
					return false
				}
				consumedValue = true
				break
			}
			if strings.IndexByte(dmesgReadFlags, c) < 0 {
				return false
			}
		}
		if consumedValue {
			i++
		}
		i++
	}
	return hasNoPager && hasBoundedBuffer
}

func topStageReadOnly(tokens []string) bool {
	hasBatch := false
	hasBoundedIterations := false
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if len(tok) < 2 || tok[0] != '-' || strings.HasPrefix(tok, "--") {
			return false
		}
		flag := tok[:2]
		switch flag {
		case "-b", "-H", "-h", "-V", "-O":
			if len(tok) > 2 {
				return false
			}
			hasBatch = hasBatch || flag == "-b"
		case "-n", "-e", "-E", "-o", "-p":
			value := tok[2:]
			if value == "" {
				if i+1 >= len(tokens) {
					return false
				}
				value = tokens[i+1]
				i++
			}
			if !topValidValue(flag, value) {
				return false
			}
			hasBoundedIterations = hasBoundedIterations || flag == "-n"
		default:
			return false
		}
	}
	return hasBatch && hasBoundedIterations
}

func topValidValue(flag, value string) bool {
	switch flag {
	case "-n":
		return validPositiveBoundedInt(value, maxDiagCount)
	case "-p":
		return validPidList(value)
	case "-e":
		return len(value) == 1 && strings.IndexByte("kmgtp", value[0]) >= 0
	case "-E":
		return len(value) == 1 && strings.IndexByte("kmgtpe", value[0]) >= 0
	case "-o":
		return topValidSortField(value)
	default:
		return false
	}
}

func topValidSortField(value string) bool {
	if value != "" && (value[0] == '+' || value[0] == '-') {
		value = value[1:]
	}
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '%':
		default:
			return false
		}
	}
	return true
}

// noExecShellTokens accepts the closed set of Bash/POSIX-shell syntax checks that parse a script
// without running any of it: `bash -n`, `bash -o noexec`, `bash -O extglob -n` in either option
// order, and `sh -n`, each followed only by plain script operands. Anything else fails closed —
// `bash --noexec` is not a Bash option at all, and one unrecognized option could restore execution.
// A plus-leading token is an invocation option, not an operand: `+n`, `+o noexec`, and grouped forms
// such as `+xn` all cancel no-exec mode, so `bash -n +n f.sh` would parse and then run f.sh.
func noExecShellTokens(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	args := tokens[1:]
	switch tokens[0] {
	case "sh":
		if len(args) == 0 || args[0] != "-n" {
			return false
		}
		args = args[1:]
	case "bash":
		n := bashNoExecOptions(args)
		if n == 0 {
			return false
		}
		args = args[n:]
	default:
		return false
	}
	for _, operand := range args {
		if operand == "" || strings.HasPrefix(operand, "-") || strings.HasPrefix(operand, "+") {
			return false
		}
	}
	return true
}

// bashNoExecOptions returns how many leading tokens form an accepted bash no-exec option sequence, or
// 0 when args does not begin with one. `-O extglob` — needed to parse extended glob patterns — is
// admitted only next to `-n`, so enabling a parser setting is never the whole option list.
func bashNoExecOptions(args []string) int {
	switch {
	case len(args) >= 3 && args[0] == "-O" && args[1] == "extglob" && args[2] == "-n":
		return 3
	case len(args) >= 3 && args[0] == "-n" && args[1] == "-O" && args[2] == "extglob":
		return 3
	case len(args) >= 1 && args[0] == "-n":
		return 1
	case len(args) >= 2 && args[0] == "-o" && args[1] == "noexec":
		return 2
	}
	return 0
}

// commandLookupTokens accepts the one `command` grammar that classifies read-only: `command -v`
// followed by exactly one operand spelled as a plain program name. `command -V`, a bare or
// multi-operand `-v`, any other option, and `command <program> …` all fail closed, so no `command`
// form outside the lookup can borrow the wrapper's route out of literal matching.
func commandLookupTokens(tokens []string) bool {
	return len(tokens) == 3 && tokens[0] == "command" && tokens[1] == "-v" && plainProgramName(tokens[2])
}

func bareEnvTokens(tokens []string) bool {
	return len(tokens) == 1 && tokens[0] == "env"
}

func typeLookupTokens(tokens []string) bool {
	return len(tokens) == 2 && tokens[0] == "type" && plainProgramName(tokens[1])
}

// plainProgramName reports whether name is a bare program name safe to hand to exec.LookPath: a
// non-empty run of letters, digits, `_`, `-`, `.`, and `+` that does not start with `-`. The closed
// byte set rejects a path (`/`), an assignment (`=`), whitespace, and every shell metacharacter,
// leaving nothing whose meaning depends on a shell the lookup never runs.
func plainProgramName(name string) bool {
	if name == "" || name[0] == '-' {
		return false
	}
	for i := range len(name) {
		switch c := name[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '_', c == '-', c == '.', c == '+':
		default:
			return false
		}
	}
	return true
}

// stageIsShellProgram reports whether a stage's canonical program is a wrapper. The no-exec and
// `command -v` exceptions hold only on the direct and staged routes, which perform the exact
// validated invocation; the literal route hands its text back to `sh -c`, so a wrapper stage there
// stays mutating. Bare `env` runs no other program, so it is not a wrapper on any route.
func stageIsShellProgram(tokens []string) bool {
	return len(tokens) > 0 && wrapperPrograms[tokens[0]] && !bareEnvTokens(tokens)
}

// stageNeedsOwnedArgv reports whether a stage may auto-allow only where dispatch can rewrite its
// argv. jj's isolation lives in a command-line `--config` prefix, because no environment variable
// disables its repository and workspace configuration; the literal route re-runs its text through
// `sh -c` and cannot carry that prefix, so a jj-bearing literal stays mutating.
func stageNeedsOwnedArgv(tokens []string) bool {
	return len(tokens) > 0 && tokens[0] == "jj"
}

var probeFlagPrograms = map[string]struct{}{
	"go": {}, "hg": {}, "git": {}, "python3": {}, "node": {}, "mise": {}, "rg": {}, "jq": {}, "awk": {}, "sed": {}, "find": {},
	"systemctl": {}, "codemeld": {},
}

// python3 and node read a bare `version` or `help` word as a script file to run, so they are absent.
var probeSubcommandPrograms = map[string]struct{}{
	"go": {}, "hg": {}, "git": {}, "mise": {},
}

func ProbeStageReadOnly(tokens []string) bool {
	if len(tokens) != 2 {
		return false
	}
	if _, ok := probeFlagPrograms[tokens[0]]; ok {
		switch tokens[1] {
		case "--version", "-V", "--help", "-h":
			return true
		}
	}
	if _, ok := probeSubcommandPrograms[tokens[0]]; ok {
		return tokens[1] == "version" || tokens[1] == "help"
	}
	return false
}

func stageTokensReadOnly(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	if policy, ok := commandPolicies[tokens[0]]; ok && policy.stageReadOnly(tokens) {
		return true
	}
	policy, ok := freebsdCommandPolicies[tokens[0]]
	return ok && policy.stageReadOnly(tokens)
}

func classifyReadOnlyShell(req MatchRequest, mc ModeContext) OperationClass {
	if mc.LiteralRoute {
		// The literal/wrapper/redirection route is mutating by default, but a bare simple compound whose
		// every stage is read-only is safe to auto-allow. Only a literal-subject
		// request carries the canonical compound text RecognizeSimpleCompound needs to decompose.
		if req.Kind == subjectKindLiteral {
			return classifyLiteralCompound(req.Subject)
		}
		return ClassMutating
	}
	if len(mc.Stages) == 0 {
		return ClassMutating
	}
	for _, stage := range mc.Stages {
		if stage.Route != RouteDirect || len(stage.Assignments) > 0 || stage.ClearEnvironment {
			return ClassMutating
		}
		if !ProbeStageReadOnly(stage.Tokens) && !stageTokensReadOnly(stage.Tokens) {
			return ClassMutating
		}
	}
	return ClassReadOnly
}

func stageArgSensitive(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	if policy, ok := commandPolicies[tokens[0]]; ok && policy.appliesToPlatform() {
		return policy.argSensitive
	}
	policy, ok := freebsdCommandPolicies[tokens[0]]
	return ok && policy.argSensitive && policy.appliesToPlatform()
}

// argDependent reports whether the verdict rests on argument text rather than the program name, so a
// token the shell has yet to expand is not the token the policy judged. A subcommand set or a deny
// flag list makes a policy argument-dependent exactly as a validator does.
func (p commandPolicy) argDependent() bool {
	return p.argSensitive || len(p.readOnlySubcommands) > 0 || len(p.denyFlags) > 0 || len(p.subcommandDenyFlags) > 0
}

func stageArgDependent(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	if policy, ok := commandPolicies[tokens[0]]; ok && policy.appliesToPlatform() {
		return policy.argDependent()
	}
	policy, ok := freebsdCommandPolicies[tokens[0]]
	return ok && policy.argDependent() && policy.appliesToPlatform()
}

const devNullTarget = "/dev/null"

func stripNullRedirects(canonical string) (string, bool) {
	mask, err := bareMask(canonical)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	kept := 0
	for i := 0; i < len(canonical); i++ {
		if !mask[i] || (canonical[i] != '>' && canonical[i] != '<') {
			continue
		}
		start, end, ok := nullRedirectSpan(canonical, mask, i)
		if !ok || start < kept {
			return "", false
		}
		b.WriteString(canonical[kept:start])
		kept = end
		i = end - 1
	}
	b.WriteString(canonical[kept:])
	return b.String(), true
}

// A here-string only feeds an inert word to stdin, so removing it leaves the programs that run
// unchanged; any span whose word or boundaries could mean more is rejected, never guessed at.
func stripClassifierHereStrings(subject string) (string, bool) {
	mask, err := bareMask(subject)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	kept := 0
	for i := 0; i < len(subject); i++ {
		if !mask[i] || subject[i] != '<' {
			continue
		}
		opEnd := i
		for opEnd < len(subject) && mask[opEnd] && subject[opEnd] == '<' {
			opEnd++
		}
		if opEnd-i < 3 {
			i = opEnd - 1
			continue
		}
		start, end, ok := hereStringSpan(subject, mask, i, opEnd)
		if !ok {
			return "", false
		}
		b.WriteString(subject[kept:start])
		kept = end
		i = end - 1
	}
	b.WriteString(subject[kept:])
	return b.String(), true
}

func hereStringSpan(s string, mask []bool, op, opEnd int) (start, end int, ok bool) {
	if opEnd-op != 3 || strings.ContainsAny(s, "\n\r") || op == 0 || !mask[op-1] || !isShellSpace(s[op-1]) {
		return 0, 0, false
	}
	prev := op - 1
	for prev >= 0 && mask[prev] && isShellSpace(s[prev]) {
		prev--
	}
	if prev < 0 || (mask[prev] && strings.IndexByte(";|&(){}<>!", s[prev]) >= 0) {
		return 0, 0, false
	}
	word := opEnd
	for word < len(s) && mask[word] && isShellSpace(s[word]) {
		word++
	}
	if word == len(s) {
		return 0, 0, false
	}
	end = word
	if s[word] == '\'' {
		end = word + 1 + strings.IndexByte(s[word+1:], '\'') + 1
	} else {
		for end < len(s) && mask[end] && !runeNeedsQuote(rune(s[end])) {
			end++
		}
		if end == word {
			return 0, 0, false
		}
	}
	if end < len(s) && (!mask[end] || (!isShellSpace(s[end]) && strings.IndexByte(";|&", s[end]) < 0)) {
		return 0, 0, false
	}
	return op - 1, end, true
}

func stripLiteralForClassification(canonical string) (string, bool) {
	remainder, ok := stripClassifierHereStrings(canonical)
	if !ok {
		return "", false
	}
	return stripNullRedirects(remainder)
}

func nullRedirectSpan(s string, mask []bool, i int) (start, end int, ok bool) {
	if s[i] != '>' {
		return 0, 0, false
	}
	start = i
	for start > 0 && mask[start-1] && s[start-1] >= '0' && s[start-1] <= '9' {
		start--
	}
	descriptor := s[start:i]
	switch descriptor {
	case "", "1", "2":
	default:
		return 0, 0, false
	}
	if start > 0 {
		switch {
		case !mask[start-1]:
			return 0, 0, false
		case isShellSpace(s[start-1]):
			start--
		case descriptor == "" && strings.IndexByte("&|;<>", s[start-1]) < 0:
		default:
			return 0, 0, false
		}
	}
	j := i + 1
	if j < len(s) && mask[j] && s[j] == '&' {
		return dupRedirectSpan(s, mask, start, j, descriptor)
	}
	if j < len(s) && mask[j] && s[j] == '>' {
		return 0, 0, false
	}
	for j < len(s) && mask[j] && isShellSpace(s[j]) {
		j++
	}
	end = j + len(devNullTarget)
	if end > len(s) || s[j:end] != devNullTarget {
		return 0, 0, false
	}
	for k := j; k < end; k++ {
		if !mask[k] {
			return 0, 0, false
		}
	}
	if !redirectSpanTerminated(s, mask, end) {
		return 0, 0, false
	}
	return start, end, true
}

// A descriptor duplication creates no file and truncates none, which is why these two spellings are
// admitted into a read-only classification.
func dupRedirectSpan(s string, mask []bool, start, amp int, descriptor string) (int, int, bool) {
	var target byte
	switch descriptor {
	case "1":
		target = '2'
	case "2":
		target = '1'
	default:
		return 0, 0, false
	}
	end := amp + 2
	if end > len(s) || !mask[amp+1] || s[amp+1] != target {
		return 0, 0, false
	}
	if !redirectSpanTerminated(s, mask, end) {
		return 0, 0, false
	}
	return start, end, true
}

func redirectSpanTerminated(s string, mask []bool, end int) bool {
	if end >= len(s) {
		return true
	}
	return isShellSpace(s[end]) || (mask[end] && strings.IndexByte(";|&", s[end]) >= 0)
}

func tokenExpansionFree(raw string) bool {
	if containsLineContinuation(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; c {
		case '\\':
			if i+1 >= len(raw) {
				return false
			}
			i++
		case '\'':
			j := strings.IndexByte(raw[i+1:], '\'')
			if j < 0 {
				return false
			}
			i += j + 1
		case '"':
			i++
			for i < len(raw) && raw[i] != '"' {
				if raw[i] == '\\' && i+1 < len(raw) && isDoubleQuoteEscape(raw[i+1]) {
					i += 2
					continue
				}
				if raw[i] == '$' || raw[i] == '`' {
					return false
				}
				i++
			}
			if i >= len(raw) {
				return false
			}
		default:
			if runeNeedsQuote(rune(c)) {
				return false
			}
		}
	}
	return true
}

func stagesExpansionFree(stages []StageNormalization) bool {
	for _, stage := range stages {
		tokens, err := tokenizeShell(stage.Source)
		if err != nil {
			return false
		}
		for _, t := range tokens {
			if !tokenExpansionFree(t.Raw) {
				return false
			}
		}
	}
	return true
}

// LiteralRunsHg and LiteralRunsPS report whether a literal-route command runs a named program in any
// stage, after the `/dev/null` redirects classification strips. They fail closed on text they cannot
// decompose, which only costs a route that never reached the program.
func LiteralRunsHg(canonical string) bool {
	return literalRunsProgram(canonical, "hg")
}

func LiteralRunsPS(canonical string) bool {
	return literalRunsProgram(canonical, "ps")
}

func literalRunsProgram(canonical, program string) bool {
	stripped, ok := stripLiteralForClassification(canonical)
	if !ok {
		return false
	}
	if _, stages, _, ok := SimpleCompoundStages(stripped); ok {
		return stagesRunProgram(stages, program)
	}
	split, err := SplitCommand(stripped)
	if err != nil {
		return false
	}
	return stagesRunProgram(split.Stages, program)
}

func stagesRunProgram(stages []StageNormalization, program string) bool {
	for _, stage := range stages {
		if len(stage.Tokens) > 0 && stage.Tokens[0] == program {
			return true
		}
	}
	return false
}

func classifyStrippedSingleStage(stages []StageNormalization) OperationClass {
	stage := stages[0]
	if stage.Route != RouteDirect || len(stage.Assignments) > 0 {
		return ClassMutating
	}
	if stageIsShellProgram(stage.Tokens) || stageNeedsOwnedArgv(stage.Tokens) || !stageTokensReadOnly(stage.Tokens) {
		return ClassMutating
	}
	if stageArgDependent(stage.Tokens) && !stagesExpansionFree(stages) {
		return ClassMutating
	}
	return ClassReadOnly
}

type literalBreakdown struct {
	stripped  string
	wrapped   bool
	compound  bool
	stages    []StageNormalization
	operators []string
}

func breakDownLiteral(canonical string) (literalBreakdown, bool) {
	stripped, ok := stripLiteralForClassification(canonical)
	if !ok {
		return literalBreakdown{}, false
	}
	literal := literalBreakdown{stripped: stripped}
	literal.wrapped, literal.stages, literal.operators, literal.compound = SimpleCompoundStages(stripped)
	if literal.compound {
		return literal, true
	}
	split, err := SplitCommand(stripped)
	if err != nil || !split.AllowedShell || split.LiteralRoute || split.CdHint != "" || len(split.Stages) != 1 {
		return literalBreakdown{}, false
	}
	literal.stages = split.Stages
	return literal, true
}

func classifyLiteralCompound(canonical string) OperationClass {
	// Even quoted substitutions execute under `sh -c`.
	if strings.Contains(canonical, "$(") || strings.Contains(canonical, "`") {
		return ClassMutating
	}
	literal, ok := breakDownLiteral(canonical)
	if !ok {
		return ClassMutating
	}
	stripped, wrapped, stages, operators := literal.stripped, literal.wrapped, literal.stages, literal.operators
	reparsedByShell := stripped != canonical
	if !literal.compound {
		if !reparsedByShell && !bareEnvTokens(stages[0].Tokens) {
			return ClassMutating
		}
		return classifyStrippedSingleStage(stages)
	}
	// A redirect-free all-`|` compound never reaches here — SplitCommand keeps it on the direct
	// route for per-stage authorization — so an unstripped one arrived by a cause still in force.
	if !wrapped && !reparsedByShell {
		hasNonPipeOperator := false
		for _, op := range operators {
			if op != "|" {
				hasNonPipeOperator = true
			}
		}
		if !hasNonPipeOperator {
			return ClassMutating
		}
	}
	argSensitive := false
	argDependent := false
	for _, stage := range stages {
		if stageIsShellProgram(stage.Tokens) || stageNeedsOwnedArgv(stage.Tokens) || !stageTokensReadOnly(stage.Tokens) {
			return ClassMutating
		}
		argSensitive = argSensitive || (stageArgSensitive(stage.Tokens) && !bareEnvTokens(stage.Tokens))
		argDependent = argDependent || stageArgDependent(stage.Tokens)
	}
	if wrapped {
		toks, err := tokenizeShell(stripped)
		if err != nil || len(toks) != 3 || !tokenExpansionFree(toks[2].Raw) {
			return ClassMutating
		}
		if !argSensitive || !stagesExpansionFree(stages) {
			return ClassMutating
		}
		return ClassReadOnly
	}
	if argDependent && !stagesExpansionFree(stages) {
		return ClassMutating
	}
	if argSensitive && !reparsedByShell {
		return ClassMutating
	}
	return ClassReadOnly
}
