// Tests for the shared shell-word tokenizer: quoted/escaped spans, whitespace handling, and syntax errors.
package permissions

import "testing"

func TestTokenizeShell_Values(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []ShellToken
	}{
		{
			name:  "plain words",
			input: "git log --oneline",
			want: []ShellToken{
				{Value: "git", Raw: "git", Quoted: false},
				{Value: "log", Raw: "log", Quoted: false},
				{Value: "--oneline", Raw: "--oneline", Quoted: false},
			},
		},
		{
			name:  "single quoted span preserved verbatim",
			input: "echo 'hello world'",
			want: []ShellToken{
				{Value: "echo", Raw: "echo", Quoted: false},
				{Value: "hello world", Raw: "'hello world'", Quoted: true},
			},
		},
		{
			name:  "double quoted span",
			input: `echo "a b"`,
			want: []ShellToken{
				{Value: "echo", Raw: "echo", Quoted: false},
				{Value: "a b", Raw: `"a b"`, Quoted: true},
			},
		},
		{
			name:  "mixed quoting in one token",
			input: `foo"bar"baz`,
			want: []ShellToken{
				{Value: "foobarbaz", Raw: `foo"bar"baz`, Quoted: true},
			},
		},
		{
			name:  "single and double quotes mixed in one token",
			input: `'a b'"c d"`,
			want: []ShellToken{
				{Value: "a bc d", Raw: `'a b'"c d"`, Quoted: true},
			},
		},
		{
			name:  "backslash-escaped space joins token",
			input: `a\ b`,
			want: []ShellToken{
				{Value: "a b", Raw: `a\ b`, Quoted: false},
			},
		},
		{
			name:  "escaped quote outside quotes is literal and unquoted",
			input: `echo \"`,
			want: []ShellToken{
				{Value: "echo", Raw: "echo", Quoted: false},
				{Value: `"`, Raw: `\"`, Quoted: false},
			},
		},
		{
			name:  "escaped double quote inside double quotes",
			input: `"a\"b"`,
			want: []ShellToken{
				{Value: `a"b`, Raw: `"a\"b"`, Quoted: true},
			},
		},
		{
			name:  "literal backslash inside double quotes",
			input: `"a\nb"`,
			want: []ShellToken{
				{Value: `a\nb`, Raw: `"a\nb"`, Quoted: true},
			},
		},
		{
			name:  "surrounding and interior whitespace trimmed",
			input: "  git   log  ",
			want: []ShellToken{
				{Value: "git", Raw: "git", Quoted: false},
				{Value: "log", Raw: "log", Quoted: false},
			},
		},
		{
			name:  "tabs separate tokens",
			input: "a\tb",
			want: []ShellToken{
				{Value: "a", Raw: "a", Quoted: false},
				{Value: "b", Raw: "b", Quoted: false},
			},
		},
		{
			name:  "empty string yields no tokens",
			input: "   ",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenizeShell(tt.input)
			if err != nil {
				t.Fatalf("tokenizeShell(%q) error = %v, want nil", tt.input, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("tokenizeShell(%q) = %d tokens %+v, want %d", tt.input, len(got), got, len(tt.want))
			}
			for i := range got {
				if got[i].Value != tt.want[i].Value || got[i].Raw != tt.want[i].Raw || got[i].Quoted != tt.want[i].Quoted {
					t.Fatalf("token %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestTokenizeShell_Errors(t *testing.T) {
	assertErrorInputs(t, "tokenizeShell", func(s string) error {
		_, err := tokenizeShell(s)
		return err
	}, []errorCase{
		{name: "unterminated single quote", input: "echo 'abc"},
		{name: "unterminated double quote", input: `echo "abc`},
		{name: "dangling backslash", input: `echo abc\`},
		{name: "dangling backslash inside double quote", input: `"abc\`},
	})
}
