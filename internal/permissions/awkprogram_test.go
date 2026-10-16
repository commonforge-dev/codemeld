package permissions

import (
	"strings"
	"testing"
)

func TestAwkStageRejectsAdversarialPrograms(t *testing.T) {
	for _, prog := range []string{
		`/"/ { print > "/tmp/x" } /"/`,
		`{ print > "f" }`,
		`{ print >> "f" }`,
		`{ print | "sh" }`,
		`{ print |& "sh" }`,
		`{ "date" | getline d }`,
		`{ getline l < "/etc/passwd" }`,
		`BEGIN { system("id") }`,
		`BEGIN { print ENVIRON["HOME"] }`,
		`BEGIN { print PROCINFO["pid"] }`,
		`@load "x"`,
		`BEGIN { f = "system"; @f("id") }`,
		`{ a = 4 / 2; print a > "f" }`,
		"{ print a,\n b > \"f\" }",
		"{ print a ?\n b : c > \"f\" }",
		"{ print a &&\n b > \"f\" }",
		"{ print a ||\n b > \"f\" }",
		"{ print a \\\n> \"f\" }",
		"{ print a, # c\n b > \"f\" }",
		`{ print (a > "f") }`,
		`{ print a >= 1 }`,
		`{ printf("%s", a) > "f" }`,
		`$1 || $2 { print a | "sh" }`,
		`{ x = a ||| "sh" }`,
		`$1 >> 2`,
		`{ if ($1) /x/ }`,
		`{ n = length / 2 }`,
		`{ a++ / 2 }`,
		`{ $/x/ }`,
		`/a/ / 2`,
		`{ x = a) / 2 }`,
		`/[/ { print }`,
		`/[]/] " / { print > "x" } # "`,
		`/[\]/] " / { print > "x" } # "`,
		"a \\\n/ 1; print > \"/tmp/x\"; y = 1 / 2",
		``,
		`# only a comment`,
		`{ next /x/ }`,
		`{ print "unterminated }`,
		`/unterminated { print }`,
		`{ printf "%s", $0 > "/dev/stderr" }`,
		`BEGIN { ARGV[1] = "/etc/shadow" } { print }`,
		`{ close("f") }`,
		`{ fflush() }`,
		"{ print `id` }",
		`BEGIN { print ARGC }`,
		`BEGIN { print SYMTAB["NR"] }`,
		`BEGIN { print FUNCTAB["f"] }`,
		`BEGIN { print 0x1system("id") }`,
		`BEGIN { print 0X1system("id") }`,
	} {
		t.Run(prog, func(t *testing.T) {
			if tokens := []string{"awk", prog, "f"}; awkStageReadOnly(tokens) {
				t.Fatalf("awkStageReadOnly(%q) = true, want false", tokens)
			}
		})
	}
}

func TestAwkStageRejectsUnsafeOptions(t *testing.T) {
	for _, tokens := range [][]string{
		{"awk", "-f", "prog.awk", "f"},
		{"awk", "-v", "x=1", "{print}", "f"},
		{"awk", "--", "{print}", "f"},
		{"awk", "-F:", "-f", "x", "f"},
		{"awk", "--field-separator=:", "{print}", "f"},
		{"awk", "-o", "{print}", "f"},
		{"awk", "-i", "lib.awk", "{print}", "f"},
		{"awk", "--include=lib.awk", "{print}", "f"},
		{"awk", "-l", "ext", "{print}", "f"},
		{"awk", "--load=ext", "{print}", "f"},
		{"awk", "-E", "prog.awk", "f"},
		{"awk", "--exec=prog.awk", "f"},
		{"awk", "-d", "{print}", "f"},
		{"awk", "--dump-variables", "{print}", "f"},
		{"awk", "-p", "{print}", "f"},
		{"awk", "--profile", "{print}", "f"},
		{"awk", "--pretty-print", "{print}", "f"},
		{"awk", "{print}", "f", "-F"},
		{"awk", "-F"},
		{"awk", "-F", "", "{print}", "f"},
		{"awk", "-F", ":"},
	} {
		t.Run(strings.Join(tokens, " "), func(t *testing.T) {
			if awkStageReadOnly(tokens) {
				t.Fatalf("awkStageReadOnly(%q) = true, want false", tokens)
			}
		})
	}
}

func TestAwkReadOnlyProgramAccepts(t *testing.T) {
	for _, prog := range []string{
		`{print NF}`,
		`{print $1, $3}`,
		`function flush() { if (section != "") printf "%5d  %s\n", words, section } /^## / { flush(); section = $0; words = 0; next } { words += NF } END { flush() }`,
		`{print $1}`,
		`NR==FNR{a[$1];next} ($1 in a)`,
		`$3 > 100 { print $1 }`,
		`$1 >= 2 || $2 == "x"`,
		`{ s += $2 } END { print s/NR }`,
		`{ print ($1 + $2) / 2 }`,
		`{ if (/x/) print }`,
		`a[/x/]`,
		`{ delete a[/x/] }`,
		`{ exit /x/ }`,
		`{ x = $1 /2/ 1 }`,
		`{ a /= 2; print a }`,
		`{ print "a" / 2 }`,
		`{ print b[1] / 2 }`,
		"{ print a,\n b }",
		"{ print a }\n$1 > 0 { print }",
		`/[[:alpha:]]x[]a]\// { print }`,
		`BEGIN{print "x"} NR>=1 && NR<=2 {print}`,
		`NR>=1 && NR<=2 {print} END{print}`,
		`NR>=1 && NR<=2 {print}{print}`,
		`NR>=1 && NR<=2 {print;}`,
		`NR>=1 && NR<=2 {print NR, $0}`,
		`NR>=1 && NR<=2 {print $1}`,
		`NR>=1 && NR<=2 {print $0 $2}`,
		`NR>=1 && NR<=2 {printf "%s" $0}`,
		`NR>=1 && NR<=2 {print x}`,
		`NR>=1 && NR<=2 {x=1 print}`,
		`NR>=1 && NR<=2 {print length($0)}`,
		`NR>=1 && NR<=2 {print "a\nb"}`,
		`NR>=1 && NR<=2`,
		`NR>=1 {print}`,
		`NR<=2 {print}`,
		`NR>=1 && FNR<=2 {print}`,
		`NR>1 && NR<2 {print}`,
		`NR>=1 || NR<=2 {print}`,
		`NR>=+1 && NR<=2 {print}`,
		`NR>=1.0 && NR<=2 {print}`,
		`NR>=1e2 && NR<=2 {print}`,
		`NR>= && NR<=2 {print}`,
		`NRX>=1 && NRX<=2 {print}`,
		`/needle/ {print}`,
		`NR>=1 && NR<=2 {print NR ":" $0}`,
	} {
		t.Run(prog, func(t *testing.T) {
			if !awkReadOnlyProgram(prog) {
				t.Fatalf("awkReadOnlyProgram(%q) = false, want true", prog)
			}
		})
	}
}

func TestAwkStageAcceptsSeparateFieldSeparator(t *testing.T) {
	if tokens := []string{"awk", "-F", ":", "{print $1}", "f"}; !awkStageReadOnly(tokens) {
		t.Fatalf("awkStageReadOnly(%q) = false, want true", tokens)
	}
}
