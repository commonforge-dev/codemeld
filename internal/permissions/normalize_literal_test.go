// Tests for literal-command canonicalization and byte-equal literal-subject matching.
package permissions

import "testing"

// TestCanonicalLiteralForm covers value-based quoting normalization (safe tokens
// collapse to one spelling), conservative raw preservation (expansion/glob/operator
// tokens keep their verbatim span), whitespace collapse, and — via the loop's
// re-canonicalization — idempotency. The redirection cases also cover the Done-when
// item that I/O redirection operators are accepted by the literal path and never
// rewritten into ordinary quoted arguments.
func TestCanonicalLiteralForm(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// safe tokens normalize to one canonical spelling derived from the value:
		// quoting style that does not change the value is dropped.
		{name: "single-quoted safe value unquotes", input: `sh -c 'echo hi'`, want: `sh -c 'echo hi'`},
		{name: "double-quoted safe value becomes single-quoted", input: `sh -c "echo hi"`, want: `sh -c 'echo hi'`},
		{name: "nested single quotes spliced", input: `sh -c "echo 'hi there'"`, want: `sh -c 'echo '\''hi there'\'''`},
		{name: "bare safe arg stays bare", input: `gofmt -w x`, want: `gofmt -w x`},
		{name: "single-quoted safe arg unquotes", input: `gofmt -w 'x'`, want: `gofmt -w x`},
		{name: "double-quoted safe arg unquotes", input: `gofmt -w "x"`, want: `gofmt -w x`},

		{name: "unquoted tokens stay unquoted", input: "git log --oneline", want: "git log --oneline"},
		{name: "runs of spaces collapse to one", input: "echo    hi", want: "echo hi"},
		{name: "leading and trailing whitespace stripped", input: "   echo hi   ", want: "echo hi"},
		{name: "tabs and newlines between tokens collapse", input: "echo\thi\nthere", want: "echo hi there"},
		{name: "concatenated quote styles fold to value", input: `foo"bar"baz 'q'`, want: `foobarbaz q`},
		{name: "backslash-escaped space becomes single-quoted", input: `echo a\ b`, want: `echo 'a b'`},
		{name: "empty quoted token kept as empty quotes", input: `echo ''`, want: `echo ''`},
		{name: "empty input yields empty form", input: "   ", want: ""},

		// expansion/glob tokens fail closed to their raw span so distinct shell
		// semantics never collapse to one subject.
		{name: "unquoted parameter expansion preserved", input: "echo $x", want: "echo $x"},
		{name: "double-quoted parameter expansion preserved", input: `echo "$x"`, want: `echo "$x"`},
		{name: "single-quoted dollar literal preserved", input: `echo '$x'`, want: `echo '$x'`},
		{name: "command substitution preserved", input: "echo $(date)", want: "echo $(date)"},
		{name: "glob preserved", input: "ls *.go", want: "ls *.go"},

		// I/O redirection and shell operators are preserved verbatim, never quoted.
		{name: "spaced stdout redirect", input: "echo hi > out.txt", want: "echo hi > out.txt"},
		{name: "glued stderr redirect", input: "cat 2>err.log", want: "cat 2>err.log"},
		{name: "here-string", input: "cat <<<input", want: "cat <<<input"},
		{name: "append and fd-dup operators", input: "run >> log 2>&1", want: "run >> log 2>&1"},
		{name: "redirect operator kept, quoted target normalized", input: `echo hi > "a b.txt"`, want: `echo hi > 'a b.txt'`},
		{name: "and-operator preserved", input: "a && b", want: "a && b"},

		// assignment-word grammar is preserved verbatim: a leading KEY=VALUE
		// environment assignment must not collapse onto a quoted command word of
		// the same value (they execute different programs), and a quoted value
		// must keep its unquoted NAME= prefix rather than become a command-word
		// shape. Redirection is what routes these through literal canonicalization.
		{name: "leading env assignment preserved bare", input: `FOO=bar echo hi > out`, want: `FOO=bar echo hi > out`},
		{name: "quoted command word resembling assignment preserved", input: `"FOO=bar" echo hi > out`, want: `"FOO=bar" echo hi > out`},
		{name: "assignment with quoted value keeps NAME= grammar", input: `FOO="bar baz" echo hi > out`, want: `FOO="bar baz" echo hi > out`},

		// backslash-newline is shell line continuation (removed by the shell), but
		// the tokenizer models it as a literal newline; the raw span is preserved
		// so it cannot collapse onto a quoted literal-newline command of different
		// shell text. The single-quoted literal-newline form re-quotes from value.
		// a shell reserved word's quoting is grammar-significant: unquoted `for`
		// opens a loop, while `"for"` is a command word naming a program. Both
		// spellings are preserved verbatim so they cannot collapse to one subject.
		{name: "reserved word command position preserved bare", input: "for > out", want: "for > out"},
		{name: "quoted reserved word command word preserved", input: `"for" > out`, want: `"for" > out`},

		{name: "unquoted line continuation preserved", input: "sh -c echo\\\nhi", want: "sh -c echo\\\nhi"},
		{name: "double-quoted line continuation preserved", input: "sh -c \"echo\\\nhi\"", want: "sh -c \"echo\\\nhi\""},
		{name: "single-quoted literal newline re-quoted", input: "sh -c 'echo\nhi'", want: "sh -c 'echo\nhi'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalLiteralForm(tt.input)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm(%q) error = %v, want nil", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("CanonicalLiteralForm(%q) = %q, want %q", tt.input, got, tt.want)
			}
			// the canonical form is idempotent. Re-canonicalizing the
			// output must yield byte-identical output.
			again, err := CanonicalLiteralForm(got)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm(canonical %q) error = %v, want nil", got, err)
			}
			if again != got {
				t.Fatalf("CanonicalLiteralForm not idempotent: %q -> %q -> %q", tt.input, got, again)
			}
		})
	}
}

// TestCanonicalLiteralForm_Idempotent asserts the guarantee directly:
// canonicalizing twice yields the same bytes, including for inputs that change
// shape on the first pass (whitespace collapse, mixed quoting, redirection).
func TestCanonicalLiteralForm_Idempotent(t *testing.T) {
	inputs := []string{
		`sh -c "echo hi"`,
		`sh -c 'echo hi'`,
		`sh -c "echo 'hi there'"`,
		"   git   status   ",
		`foo"bar"baz 'q'`,
		`echo a\ b`,
		"cat 2>err.log <<<payload",
	}
	for _, in := range inputs {
		once, err := CanonicalLiteralForm(in)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q) error = %v, want nil", in, err)
		}
		twice, err := CanonicalLiteralForm(once)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q) error = %v, want nil", once, err)
		}
		if once != twice {
			t.Fatalf("not idempotent for %q: %q != %q", in, once, twice)
		}
	}
}

// TestCanonicalLiteralForm_Errors confirms malformed input surfaces the
// tokenizer error instead of returning a partial form that could broaden a match.
func TestCanonicalLiteralForm_Errors(t *testing.T) {
	for _, in := range []string{`sh -c "echo hi`, `echo 'unterminated`, `echo abc\`} {
		if _, err := CanonicalLiteralForm(in); err == nil {
			t.Fatalf("CanonicalLiteralForm(%q) error = nil, want error", in)
		}
	}
}

func TestMatchesLiteralSubject(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		stored string
		want   bool
	}{
		{name: "identical canonical forms match", input: `sh -c 'echo hi'`, stored: `sh -c 'echo hi'`, want: true},
		// matching is pure byte equality on already-canonical subjects.
		// Forms differing only in whitespace must not match — MatchesLiteralSubject
		// performs no re-normalization that would collapse the extra space.
		{name: "differ only in whitespace rejected", input: "echo hi", stored: "echo  hi", want: false},
		// expansion variants stay distinct after canonicalization (their raw spans
		// are preserved), so their canonical subjects are not byte-equal here.
		{name: "literal-dollar vs expansion rejected", input: `echo '$x'`, stored: `echo "$x"`, want: false},
		{name: "different arguments rejected", input: "rm -rf /tmp", stored: "rm -rf /var", want: false},
		{name: "empty matches empty", input: "", stored: "", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesLiteralSubject(tt.input, tt.stored); got != tt.want {
				t.Fatalf("MatchesLiteralSubject(%q, %q) = %v, want %v", tt.input, tt.stored, got, tt.want)
			}
		})
	}
}

// TestCanonicalLiteralForm_QuoteEquivalence asserts that every spelling in a group
// collapses to one identical canonical form, so a grant stored for one spelling
// matches the rest. Each group's first element is the expected canonical form.
func TestCanonicalLiteralForm_QuoteEquivalence(t *testing.T) {
	groups := [][]string{
		{`gofmt -w x`, `gofmt -w 'x'`, `gofmt -w "x"`},
		{`echo 'a b'`, `echo "a b"`, `echo a\ b`},
		{`sh -c 'echo hi'`, `sh -c "echo hi"`},
		{`echo a b c`, `echo 'a' "b" c`, `echo "a" b 'c'`},
		{`gofmt -w x`, `   gofmt    -w   "x"  `},
	}
	for _, group := range groups {
		want, err := CanonicalLiteralForm(group[0])
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q) error = %v", group[0], err)
		}
		for _, in := range group {
			got, err := CanonicalLiteralForm(in)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm(%q) error = %v", in, err)
			}
			if got != want {
				t.Fatalf("CanonicalLiteralForm(%q) = %q, want %q (equivalent to %q)", in, got, want, group[0])
			}
			if !MatchesLiteralSubject(got, want) {
				t.Fatalf("MatchesLiteralSubject(%q, %q) = false, want true", got, want)
			}
		}
	}
}

// TestCanonicalLiteralForm_DistinctForms is the adversarial negative table: each
// group is a set of commands that execute differently and must therefore keep
// distinct canonical forms, so a grant for one never matches another.
func TestCanonicalLiteralForm_DistinctForms(t *testing.T) {
	groups := [][]string{
		{`echo '$x'`, `echo "$x"`, `echo $x`}, // literal dollar vs expansion vs unquoted expansion
		{`echo x`, `echo y`},                  // different value
		{`gofmt -w x`, `gofmt -W x`},          // different flag
		{`cp a b`, `cp b a`},                  // reordered operands
		{`ls`, `ls -l`},                       // added flag
		{`ls *.go`, `ls *.txt`},               // different glob
		{`echo '*'`, `echo *`},                // literal star vs glob
		{`a && b`, `a || b`},                  // different operator
		{`cat a`, `cat a > out`},              // added redirection stage
		// assignment word vs quoted command word vs quoted-value assignment: the
		// first runs echo with FOO in its environment, the second tries to run a
		// program named FOO=bar, the third sets FOO to "bar baz".
		{`FOO=bar echo hi > out`, `"FOO=bar" echo hi > out`, `FOO="bar baz" echo hi > out`},
		// backslash-newline line continuation (unquoted and double-quoted, both run
		// `sh -c echohi`) vs a single-quoted literal newline (runs a two-line body):
		// the first two preserve their raw span, the third re-quotes from value, so
		// none collapse despite the tokenizer modeling the continuation as a newline.
		{"sh -c echo\\\nhi", "sh -c \"echo\\\nhi\"", "sh -c 'echo\nhi'"},
		// reserved-word grammar boundary: unquoted `for` is parsed as a loop
		// keyword (shell grammar), while `"for"` is an ordinary command word
		// naming a program. With a redirection they are distinct command forms, so
		// their canonical subjects must not collapse — the safe argv pair
		// `gofmt -w x` / `gofmt -w "x"` (no reserved word) still collapses above.
		{`for > out`, `"for" > out`},
	}
	for _, group := range groups {
		seen := map[string]string{}
		for _, in := range group {
			got, err := CanonicalLiteralForm(in)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm(%q) error = %v", in, err)
			}
			if prev, dup := seen[got]; dup {
				t.Fatalf("CanonicalLiteralForm collapsed distinct commands %q and %q to %q", prev, in, got)
			}
			seen[got] = in
		}
	}
}

// TestArgumentHashFollowsCanonicalForm pins the audit-trail contract: the
// argument hash is computed over the new canonical form, so equivalent spellings
// hash identically while any value change yields a different hash.
func TestArgumentHashFollowsCanonicalForm(t *testing.T) {
	hashOf := func(in string) string {
		c, err := CanonicalLiteralForm(in)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q) error = %v", in, err)
		}
		return ComputeArgumentHash(c)
	}
	want := ComputeArgumentHash(`gofmt -w x`)
	for _, in := range []string{`gofmt -w x`, `gofmt -w 'x'`, `gofmt -w "x"`} {
		if got := hashOf(in); got != want {
			t.Fatalf("argument hash for %q = %q, want %q", in, got, want)
		}
	}
	if hashOf(`gofmt -w y`) == want {
		t.Fatalf("argument hash collided across distinct values")
	}
}
