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

// commandLookupTokens accepts the one `command` grammar that classifies read-only: `command -v`,
// an optional `--`, then exactly one operand spelled as a plain program name. `command -V`, a bare
// or multi-operand `-v`, any other option, and `command <program> …` all fail closed, so no
// `command` form outside the lookup can borrow the wrapper's route out of literal matching.
func commandLookupTokens(tokens []string) bool {
	if len(tokens) < 3 || tokens[0] != "command" || tokens[1] != "-v" {
		return false
	}
	names := tokens[2:]
	if names[0] == "--" {
		names = names[1:]
	}
	return len(names) == 1 && plainProgramName(names[0])
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
