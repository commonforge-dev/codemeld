package permissions

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func literalSummary(command string) PromptSummaryResult {
	return PromptSummary(
		MatchRequest{Kind: subjectKindLiteral, Subject: command},
		PromptSummaryInput{Action: "Run command", Command: command},
	)
}

func directSummary(command string) PromptSummaryResult {
	return PromptSummary(
		MatchRequest{Kind: subjectKindDirect, Subject: command},
		PromptSummaryInput{Action: "Run command", Command: command},
	)
}

func TestPromptSummary_AcceptedShellWriteForms(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{"> out", []string{"out"}},
		{">> out.log", []string{"out.log"}},
		{"1>out", []string{"out"}},
		{"2>>err.log", []string{"err.log"}},
		{"> a >> b", []string{"a", "b"}},
		{"rm x > /dev/null", []string{"x"}},
		{"tee a b", []string{"a", "b"}},
		{"tee -a out", []string{"out"}},
		{"tee --append --ignore-interrupts o", []string{"o"}},
		{"tee -i -- -dashed", []string{"-dashed"}},
		{"cp a b", []string{"b"}},
		{"mv a b", []string{"b"}},
		{"install a b", []string{"b"}},
		{"ln a b", []string{"b"}},
		{"cp -- -a b", []string{"b"}},
		{"mkdir a b", []string{"a", "b"}},
		{"rm x y", []string{"x", "y"}},
		{"touch f", []string{"f"}},
		{"touch a a", []string{"a", "a"}},
		{"truncate -s 0 f", []string{"f"}},
		{"truncate --size 10 -- f g", []string{"f", "g"}},
		{"dd if=/dev/zero of=out bs=1", []string{"out"}},
		{"cp a b > log", []string{"b", "log"}},
		{"mv a b > log", []string{"b", "log"}},
		{"install a b >> log", []string{"b", "log"}},
		{"ln a b > log", []string{"b", "log"}},
		{"mkdir d e > log", []string{"d", "e", "log"}},
		{"rm x >> log", []string{"x", "log"}},
		{"truncate -s 0 f 2> log", []string{"f", "log"}},
		{"dd if=/dev/zero of=out bs=1 > log", []string{"out", "log"}},
		{"> log mv a b", []string{"log", "b"}},
		{"> log dd if=/dev/zero of=out", []string{"log", "out"}},
		{"tee x >> y", []string{"x", "y"}},
		{"touch 'my file.txt'", []string{"my file.txt"}},
		{"mkdir 2>>err a", []string{"err", "a"}},
		{"> log touch x", []string{"log", "x"}},
		{"tee a > log b", []string{"a", "log", "b"}},
		{"touch a > one b >> two c", []string{"a", "one", "b", "two", "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			got := literalSummary(tc.command)
			if got.Unknown {
				t.Fatalf("%q reached the unknown fallback; want the closed write grammar", tc.command)
			}
			if got.Effect != "runs a command, writes" {
				t.Fatalf("effect = %q, want the run+write union", got.Effect)
			}
			if !reflect.DeepEqual(got.Targets, tc.want) {
				t.Fatalf("targets = %#v, want %#v in source order", got.Targets, tc.want)
			}
		})
	}
}

func TestPromptSummary_RejectedShellForms(t *testing.T) {
	commands := []string{
		"git commit > log",
		"curl https://example.test > out",
		"1 > out",
		"2 >> out",
		"touch 1 > out",
		"touch 2 >> out",
		"touch 3>out",
		"touch 12>out",
		"touch 0>out",
		"tee 1 > out",
		"> log touch 2 > out",
		"sed -i 's/a/b/' f",
		"perl -i -pe 's/a/b/' f",
		"cp --help",
		"cp --version",
		"cp a",
		"cp a b c",
		"cp -r a b",
		"tee",
		"tee --help",
		"tee -x out",
		"tee -a",
		"mkdir --",
		"mkdir",
		"rm -rf x",
		"rm",
		"truncate f",
		"truncate -s f",
		"truncate --help f",
		"truncate -s '' f",
		"dd",
		"dd of=out of=other",
		"dd if=/dev/zero",
		"dd --help",
		"dd of=",
		"python3 -c 'open(\"x\",\"w\").write(\"1\")'",
		"sh -c 'rm x'",
		"node -e 'require(\"fs\").writeFileSync(\"x\",\"1\")'",
		"echo aGk= | base64 -d > out",
		"echo hi | tee out",
		"rm x && rm y",
		"rm x ; rm y",
		"rm x || rm y",
		"rm x &",
		"cat < in > out",
		"echo x &> out",
		"echo x >& out",
		"echo x 2>&1 > out",
		"rm $HOME/x",
		"cp $FILES out > log",
		"touch ~/x",
		"touch *.txt",
		"touch {a,b}",
		"rm \"unterminated",
		"rm x >",
		">",
		">>",
		"rm `date`",
		"rm $(ls)",
		"",
		"FOO=1 touch x",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			got := literalSummary(command)
			if !got.Unknown {
				t.Fatalf("%q was summarized as %q -> %#v; want the unknown-effect fallback", command, got.Effect, got.Targets)
			}
			if got.Effect != "unknown" || len(got.Targets) != 0 {
				t.Fatalf("fallback still advertises effect %q and targets %#v", got.Effect, got.Targets)
			}
			if !strings.Contains(got.Sentence, "inspect the complete request") {
				t.Fatalf("fallback sentence does not direct the user to the full request: %q", got.Sentence)
			}
		})
	}
}

// A literal request is handed to `sh -c` verbatim, so expansion anywhere in the accepted form
// disqualifies it; a direct request's argv is already fixed, so only its reported targets must
// be expansion-free.
func TestPromptSummary_ExpansionCheckDependsOnRoute(t *testing.T) {
	const command = "cp \"$SRC\" out"
	if got := literalSummary(command); !got.Unknown {
		t.Fatalf("literal route summarized %q despite expansion in a participating word: %#v", command, got.Targets)
	}
	got := directSummary(command)
	if got.Unknown {
		t.Fatalf("direct route rejected %q whose reported target is expansion-free", command)
	}
	if !reflect.DeepEqual(got.Targets, []string{"out"}) {
		t.Fatalf("direct targets = %#v, want [out]", got.Targets)
	}
	if expansion := directSummary("cp a \"$DEST\""); !expansion.Unknown {
		t.Fatalf("direct route reported an expansion-bearing target: %#v", expansion.Targets)
	}

	// Words other than the reported target also participate in the accepted grammar: an option
	// argument, an operand the summary does not report, and a redirection target.
	for _, tc := range []struct {
		command      string
		directTarget []string
	}{
		{"truncate -s \"$SIZE\" f", []string{"f"}},
		{"tee \"$OPT\" out", nil},
		{"cp a b > \"$LOG\"", nil},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if got := literalSummary(tc.command); !got.Unknown {
				t.Fatalf("literal route summarized %q despite expansion in a participating word: %#v", tc.command, got.Targets)
			}
			got := directSummary(tc.command)
			if tc.directTarget == nil {
				if !got.Unknown {
					t.Fatalf("direct route summarized %q whose reported target bears expansion: %#v", tc.command, got.Targets)
				}
				return
			}
			if !reflect.DeepEqual(got.Targets, tc.directTarget) {
				t.Fatalf("direct targets for %q = %#v, want %#v", tc.command, got.Targets, tc.directTarget)
			}
		})
	}
}

// `sh -c` reads a word-initial bare `#` as a comment and never executes the words after it, so a
// literal request carrying one cannot be summarized; an escaped or quoted `#` stays an operand.
func TestPromptSummary_LiteralCommentTakesUnknownFallback(t *testing.T) {
	for _, command := range []string{
		"touch safe # > claimed",
		"touch safe #claimed",
		"> log touch safe # x",
		"tee out # more",
		// The comment sits in an accepted option argument the summary never reports, so only the
		// literal-route whole-form check can catch it.
		"truncate -s # f",
	} {
		t.Run(command, func(t *testing.T) {
			got := literalSummary(command)
			if !got.Unknown {
				t.Fatalf("%q was summarized as %q -> %#v; a shell comment must take the unknown-effect fallback", command, got.Effect, got.Targets)
			}
		})
	}
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{"touch safe \\# > claimed", []string{"safe", "#", "claimed"}},
		{"touch safe '#' > claimed", []string{"safe", "#", "claimed"}},
	} {
		t.Run(tc.command, func(t *testing.T) {
			got := literalSummary(tc.command)
			if got.Unknown {
				t.Fatalf("%q reached the unknown fallback; an escaped or quoted `#` is a real operand", tc.command)
			}
			if !reflect.DeepEqual(got.Targets, tc.want) {
				t.Fatalf("targets = %#v, want %#v", got.Targets, tc.want)
			}
		})
	}
}

// A redirect-only command whose every target is /dev/null matches the accepted grammar and
// requests no write, so it must read as known-neutral rather than as an unclassifiable request.
func TestPromptSummary_RedirectOnlyDevNullIsAcceptedNeutral(t *testing.T) {
	for _, command := range []string{"> /dev/null", "> /dev/null 2>> /dev/null"} {
		t.Run(command, func(t *testing.T) {
			got := literalSummary(command)
			if got.Unknown {
				t.Fatalf("%q reached the unknown fallback; the redirect-only grammar accepts it", command)
			}
			if got.Effect != "runs a command" {
				t.Fatalf("effect = %q, want a run-only effect with no write claim", got.Effect)
			}
			if len(got.Targets) != 0 {
				t.Fatalf("targets = %#v, want none: /dev/null is not a written target", got.Targets)
			}
		})
	}
}

func TestPromptSummary_ShapeCounting(t *testing.T) {
	cases := []struct {
		payload   string
		wantLines int
		wantChars int
	}{
		{"", 0, 0},
		{"a", 1, 1},
		{"a\n", 1, 2},
		{"a\nb", 2, 3},
		{"a\n\n", 2, 3},
		{"héllo", 1, 5},
		{"日本語\n", 1, 4},
	}
	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			lines, chars := promptShape(tc.payload)
			if lines != tc.wantLines || chars != tc.wantChars {
				t.Fatalf("promptShape(%q) = (%d, %d), want (%d, %d)", tc.payload, lines, chars, tc.wantLines, tc.wantChars)
			}
		})
	}
}

func TestPromptSummary_ShapeLineReportsKindEffectAndCounts(t *testing.T) {
	got := literalSummary("touch a\nb")
	rows := got.DisplayRows()
	if len(rows) < 2 {
		t.Fatalf("DisplayRows = %#v, want at least a summary and a shape row", rows)
	}
	// A newline is a rejected construct, so this stays unknown while still reporting its size.
	want := "Request: shell command, 2 lines, 9 characters, effect: unknown"
	if rows[1] != want {
		t.Fatalf("shape row = %q, want %q", rows[1], want)
	}
	for _, banned := range []string{subjectKindDirect, subjectKindLiteral, subjectKindTool, "structured-tool", "literal-command"} {
		if strings.Contains(rows[1], banned) {
			t.Fatalf("shape row leaks the matching discriminator %q: %q", banned, rows[1])
		}
	}
}

func TestBoundPromptFact_EscapesControlBytesAtomically(t *testing.T) {
	if got := BoundPromptFact("a\nb\tc"); got != `a\x0Ab\x09c` {
		t.Fatalf("BoundPromptFact = %q, want visible escapes", got)
	}
	if got := BoundPromptFact("\x7f"); got != `\x7F` {
		t.Fatalf("DEL not escaped: %q", got)
	}

	over := strings.Repeat("x", 130)
	got := BoundPromptFact(over)
	if utf8.RuneCountInString(got) != promptFactRuneCap+1 {
		t.Fatalf("over-cap rendering has %d code points, want %d plus the ellipsis", utf8.RuneCountInString(got), promptFactRuneCap)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("over-cap rendering lacks the ellipsis: %q", got)
	}

	multibyte := BoundPromptFact(strings.Repeat("é", 130))
	if utf8.RuneCountInString(multibyte) != promptFactRuneCap+1 || !utf8.ValidString(multibyte) {
		t.Fatalf("multi-byte truncation split a rune or missed the cap: %q", multibyte)
	}

	// The escape unit spans four code points, so a cap landing inside it must drop the whole
	// unit rather than emit a partial escape.
	atCap := BoundPromptFact(strings.Repeat("x", 118) + "\n" + "tail")
	if strings.Contains(atCap, `\x0`) && !strings.Contains(atCap, `\x0A`) {
		t.Fatalf("escape unit was split: %q", atCap)
	}
	if atCap != strings.Repeat("x", 118)+"…" {
		t.Fatalf("atomic escape truncation = %q", atCap)
	}
}

func TestPromptSummary_TargetRowsAreCappedWithOmittedCount(t *testing.T) {
	got := literalSummary("touch a b c d e f g h")
	if len(got.Targets) != 8 {
		t.Fatalf("targets = %#v, want all eight retained on the result", got.Targets)
	}
	rows := got.DisplayRows()
	targetRows := 0
	overflow := ""
	for _, row := range rows {
		if strings.HasPrefix(row, "Requested target: ") {
			targetRows++
		}
		if strings.HasPrefix(row, "… plus ") {
			overflow = row
		}
	}
	if targetRows != promptTargetRowCap {
		t.Fatalf("rendered %d target rows, want the cap of %d", targetRows, promptTargetRowCap)
	}
	if overflow != "… plus 2 more requested targets; inspect the complete request" {
		t.Fatalf("omitted-target row = %q", overflow)
	}
}

func TestPromptSummary_StructuredTools(t *testing.T) {
	cases := []struct {
		name       string
		req        MatchRequest
		in         PromptSummaryInput
		wantKind   string
		wantEffect string
		wantTarget string
	}{
		{"create", MatchRequest{Kind: subjectKindTool, Subject: "create"}, PromptSummaryInput{Action: "Create file", RequestedTarget: "a.md", Body: "x\n"}, "file create", "writes", "a.md"},
		{"edit", MatchRequest{Kind: subjectKindTool, Subject: "edit"}, PromptSummaryInput{Action: "Edit file", RequestedTarget: "a.md", Body: "--- a\n+++ b\n"}, "file edit", "writes", "a.md"},
		{"delete", MatchRequest{Kind: subjectKindTool, Subject: "delete"}, PromptSummaryInput{Action: "Delete file", RequestedTarget: "a.md"}, "file delete", "writes", "a.md"},
		{"mkdir", MatchRequest{Kind: subjectKindTool, Subject: "mkdir"}, PromptSummaryInput{Action: "Create directory", RequestedTarget: "build"}, "directory create", "writes", "build"},
		{"move", MatchRequest{Kind: subjectKindTool, Subject: "move"}, PromptSummaryInput{Action: "Move", RequestedTarget: "a -> b"}, "file move", "writes", "a -> b"},
		{"read", MatchRequest{Kind: subjectKindTool, Subject: "read"}, PromptSummaryInput{Action: "Run tool", RequestedTarget: "/outside/x", Body: `read({"path":"/outside/x"})`}, "file read", "reads", "/outside/x"},
		{"grep", MatchRequest{Kind: subjectKindTool, Subject: "grep"}, PromptSummaryInput{Action: "Run tool", RequestedTarget: "/outside", Body: "grep(...)"}, "file search", "reads", "/outside"},
		{"glob", MatchRequest{Kind: subjectKindTool, Subject: "glob"}, PromptSummaryInput{Action: "Run tool", RequestedTarget: "/outside", Body: "glob(...)"}, "file search", "reads", "/outside"},
		{"list", MatchRequest{Kind: subjectKindTool, Subject: "list"}, PromptSummaryInput{Action: "Run tool", RequestedTarget: "/outside", Body: "list(...)"}, "directory listing", "reads", "/outside"},
		{"tree", MatchRequest{Kind: subjectKindTool, Subject: "tree"}, PromptSummaryInput{Action: "Run tool", RequestedTarget: "/outside", Body: "tree(...)"}, "directory listing", "reads", "/outside"},
		{"file_count", MatchRequest{Kind: subjectKindTool, Subject: "file_count"}, PromptSummaryInput{Action: "Run tool", RequestedTarget: "/outside", Body: "file_count(...)"}, "file count", "reads", "/outside"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PromptSummary(tc.req, tc.in)
			if got.Unknown {
				t.Fatalf("%s reached the unknown fallback", tc.name)
			}
			if got.Kind != tc.wantKind || got.Effect != tc.wantEffect {
				t.Fatalf("kind/effect = %q/%q, want %q/%q", got.Kind, got.Effect, tc.wantKind, tc.wantEffect)
			}
			if !reflect.DeepEqual(got.Targets, []string{tc.wantTarget}) {
				t.Fatalf("targets = %#v, want [%s]", got.Targets, tc.wantTarget)
			}
		})
	}
}

func TestPromptSummary_UnknownForUnclassifiedTool(t *testing.T) {
	got := PromptSummary(
		MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit"},
		PromptSummaryInput{Action: "Run tool", Body: `vcs_commit({"message":"x"})`},
	)
	if !got.Unknown || got.Effect != "unknown" || len(got.Targets) != 0 {
		t.Fatalf("unclassified tool summarized as %#v, want the fallback", got)
	}
	if got.Chars != len(`vcs_commit({"message":"x"})`) {
		t.Fatalf("fallback dropped the shape counts: %#v", got)
	}
}

func TestPromptSummary_ReadToolWithoutPathReportsNoTarget(t *testing.T) {
	got := PromptSummary(
		MatchRequest{Kind: subjectKindTool, Subject: "glob"},
		PromptSummaryInput{Action: "Run tool", Body: `glob({"pattern":"*.go"})`},
	)
	if got.Effect != "reads" {
		t.Fatalf("effect = %q, want reads", got.Effect)
	}
	if len(got.Targets) != 0 {
		t.Fatalf("targets = %#v, want none when the call carries no path", got.Targets)
	}
}

func TestPromptSummary_Host(t *testing.T) {
	got := PromptSummary(
		MatchRequest{Kind: subjectKindHost, Subject: "web_fetch", Host: "docs.example.test"},
		PromptSummaryInput{HostRequest: "https://docs.example.test/a"},
	)
	if got.Effect != "contacts a host" || got.Kind != "host request" {
		t.Fatalf("host summary = %#v", got)
	}
	if !reflect.DeepEqual(got.Targets, []string{"docs.example.test"}) {
		t.Fatalf("host targets = %#v, want the canonical host", got.Targets)
	}
	if got.Lines != 1 || got.Chars != len("https://docs.example.test/a") {
		t.Fatalf("host shape counts the wrong payload: %#v", got)
	}
}

func TestPromptSummary_BatchUnionAndFallback(t *testing.T) {
	known := PromptSummary(
		MatchRequest{Kind: subjectKindDirect, Subject: "cp a b"},
		PromptSummaryInput{Action: "Run command", Command: "cp a b", Stages: []string{"cp a b", "touch c"}},
	)
	if known.Unknown {
		t.Fatalf("batch of classified stages fell back to unknown: %#v", known)
	}
	if known.StageCount != 2 {
		t.Fatalf("stage count = %d, want 2", known.StageCount)
	}
	if !reflect.DeepEqual(known.Targets, []string{"b", "c"}) {
		t.Fatalf("batch targets = %#v, want the union in stage order", known.Targets)
	}
	if known.Lines != 2 || known.Chars != len("cp a b\ntouch c") {
		t.Fatalf("batch shape counts the wrong payload: %#v", known)
	}
	if !strings.Contains(known.DisplayRows()[1], "(2 stages)") {
		t.Fatalf("shape row does not name the stage count: %q", known.DisplayRows()[1])
	}

	mixed := PromptSummary(
		MatchRequest{Kind: subjectKindDirect, Subject: "cp a b"},
		PromptSummaryInput{Action: "Run command", Command: "cp a b", Stages: []string{"cp a b", "ls -l"}},
	)
	if !mixed.Unknown || len(mixed.Targets) != 0 {
		t.Fatalf("one unclassifiable stage did not force the whole batch unknown: %#v", mixed)
	}
	if !strings.Contains(mixed.Sentence, "all 2 pipeline stages") {
		t.Fatalf("batch fallback sentence hides the stage count: %q", mixed.Sentence)
	}
}
