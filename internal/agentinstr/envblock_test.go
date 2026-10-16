// Exact-format tests for the environment context block: date day-granularity,
// absolute cwd, runtime.GOOS, project/VCS slice incl. the no-VCS case, and the
// absence of per-turn-volatile fields.
package agentinstr

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixedInputs() EnvironmentInputs {
	return EnvironmentInputs{
		Now:         time.Date(2026, time.June, 10, 14, 37, 5, 0, time.UTC),
		WorkingDir:  "/data/srht/codemeld/main",
		ProjectRoot: "/data/srht/codemeld/main",
		VCSName:     "hg",
	}
}

func TestEnvironmentBlock_ExactFormat(t *testing.T) {
	got := EnvironmentBlock(fixedInputs())
	want := "Environment:\n" +
		"- Date: 2026-06-10\n" +
		"- Working directory: /data/srht/codemeld/main\n" +
		"- Operating system: " + runtime.GOOS + "\n" +
		"- Project: main\n" +
		"- Version control: Mercurial"
	if got != want {
		t.Fatalf("EnvironmentBlock() =\n%q\nwant\n%q", got, want)
	}
}

func TestEnvironmentBlock_RepoRootExactFormatAndPlacement(t *testing.T) {
	in := fixedInputs()
	in.WorkingDir = "/data/srht/codemeld/main/internal"
	in.ProjectRoot = "/data/srht/codemeld/main"
	in.RepoRoot = "/data/srht/codemeld"
	got := EnvironmentBlock(in)
	want := "Environment:\n" +
		"- Date: 2026-06-10\n" +
		"- Working directory: /data/srht/codemeld/main/internal\n" +
		"- Operating system: " + runtime.GOOS + "\n" +
		"- Project: main\n" +
		"- Repository root: /data/srht/codemeld\n" +
		"- Version control: Mercurial"
	if got != want {
		t.Fatalf("EnvironmentBlock() with a repo root =\n%q\nwant\n%q", got, want)
	}
}

func TestEnvironmentBlock_RepoRootRendersWhenEqualToProjectAndWorkingDir(t *testing.T) {
	in := fixedInputs()
	in.RepoRoot = in.ProjectRoot
	if got := EnvironmentBlock(in); !strings.Contains(got, "- Repository root: /data/srht/codemeld/main\n") {
		t.Fatalf("repository-root line suppressed when equal to project root and working directory: %q", got)
	}
}

func TestEnvironmentBlock_EmptyRepoRootEmitsNoLine(t *testing.T) {
	in := fixedInputs()
	in.RepoRoot = ""
	got := EnvironmentBlock(in)
	if strings.Contains(got, "Repository root") {
		t.Fatalf("empty RepoRoot must emit no repository-root line or placeholder: %q", got)
	}
	if got != EnvironmentBlock(fixedInputs()) {
		t.Fatalf("empty RepoRoot changed the rest of the block: %q", got)
	}
}

func TestEnvironmentBlock_DateIsDayGranularityNoClockTime(t *testing.T) {
	got := EnvironmentBlock(fixedInputs())
	if !strings.Contains(got, "- Date: 2026-06-10\n") {
		t.Fatalf("date line missing day-granularity date: %q", got)
	}
	// The supplied clock value has hour/minute/second set; none may leak into the block.
	for _, clock := range []string{"14", "37", "05", ":"} {
		if strings.Contains(got, "Date: 2026-06-10 "+clock) || strings.Contains(got, "14:37") {
			t.Fatalf("clock time leaked into date line: %q", got)
		}
	}
}

// TestEnvironmentBlock_DateRendersLocalTimezoneDayAcrossBoundary pins the day-boundary edge
// the date is rendered at day granularity in the day of Now's *own* location, not in
// UTC. Each case is an instant whose local-zone calendar day differs from its UTC calendar day;
// the block must show the local day and never the UTC day, otherwise a user just east or west of
// UTC would see yesterday's or tomorrow's date near midnight. The existing day-granularity test
// uses a UTC value and only proves no clock time leaks, so it cannot catch a UTC-vs-local mix-up.
func TestEnvironmentBlock_DateRendersLocalTimezoneDayAcrossBoundary(t *testing.T) {
	cases := []struct {
		name     string
		now      time.Time
		wantDay  string
		otherDay string // the UTC day that must NOT appear
	}{
		{
			// 2026-06-11 09:30 in UTC+10 is 2026-06-10 23:30 UTC: the local day is one ahead.
			name:     "east of UTC renders the later local day",
			now:      time.Date(2026, time.June, 11, 9, 30, 0, 0, time.FixedZone("UTC+10", 10*3600)),
			wantDay:  "2026-06-11",
			otherDay: "2026-06-10",
		},
		{
			// 2026-06-09 20:00 in UTC-10 is 2026-06-10 06:00 UTC: the local day is one behind.
			name:     "west of UTC renders the earlier local day",
			now:      time.Date(2026, time.June, 9, 20, 0, 0, 0, time.FixedZone("UTC-10", -10*3600)),
			wantDay:  "2026-06-09",
			otherDay: "2026-06-10",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := fixedInputs()
			in.Now = tc.now
			// Sanity-check the fixture: the instant really does straddle the date boundary, so the
			// assertion below is meaningful rather than vacuous.
			if tc.now.UTC().Format("2006-01-02") != tc.otherDay {
				t.Fatalf("fixture UTC day = %q, want %q (instant must straddle the date boundary)", tc.now.UTC().Format("2006-01-02"), tc.otherDay)
			}
			got := EnvironmentBlock(in)
			if !strings.Contains(got, "- Date: "+tc.wantDay+"\n") {
				t.Fatalf("date line did not render the local-timezone day %q: %q", tc.wantDay, got)
			}
			if strings.Contains(got, tc.otherDay) {
				t.Fatalf("block rendered the UTC day %q instead of the local day %q: %q", tc.otherDay, tc.wantDay, got)
			}
		})
	}
}

func TestEnvironmentBlock_UsesRuntimeGOOS(t *testing.T) {
	got := EnvironmentBlock(fixedInputs())
	if !strings.Contains(got, "- Operating system: "+runtime.GOOS+"\n") {
		t.Fatalf("operating system line does not use runtime.GOOS (%q): %q", runtime.GOOS, got)
	}
}

func TestEnvironmentBlock_ProjectNameIsBasename(t *testing.T) {
	in := fixedInputs()
	in.ProjectRoot = "/home/user/projects/codemeld"
	got := EnvironmentBlock(in)
	if !strings.Contains(got, "- Project: codemeld\n") {
		t.Fatalf("project name is not the basename of the project root: %q", got)
	}
}

func TestEnvironmentBlock_VCSDisplayNames(t *testing.T) {
	cases := map[string]string{
		"git":           "Git",
		"hg":            "Mercurial",
		"jj":            "Jujutsu",
		"fossil":        "fossil", // custom template name rendered verbatim
		"My Custom VCS": "My Custom VCS",
	}
	for name, want := range cases {
		in := fixedInputs()
		in.VCSName = name
		got := EnvironmentBlock(in)
		if !strings.HasSuffix(got, "- Version control: "+want) {
			t.Fatalf("VCSName %q rendered wrong; want suffix %q, got %q", name, want, got)
		}
	}
}

func TestEnvironmentBlock_NoVCSDetected(t *testing.T) {
	in := fixedInputs()
	in.VCSName = ""
	got := EnvironmentBlock(in)
	want := "Environment:\n" +
		"- Date: 2026-06-10\n" +
		"- Working directory: /data/srht/codemeld/main\n" +
		"- Operating system: " + runtime.GOOS + "\n" +
		"- Project: main\n" +
		"- Version control: no version control detected"
	if got != want {
		t.Fatalf("EnvironmentBlock() with no VCS =\n%q\nwant\n%q", got, want)
	}
	if strings.Contains(want, "Repository root") {
		t.Fatalf("expected no-VCS block must contain no repository-root line: %q", want)
	}
}

func TestEnvironmentBlock_ExcludesVolatileState(t *testing.T) {
	got := strings.ToLower(EnvironmentBlock(fixedInputs()))
	// No branch/head, dirty status, or directory listing in the always-on block.
	for _, forbidden := range []string{"branch", "head", "dirty", "uncommitted", "modified", "untracked", "listing"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("block must not contain volatile field %q: %q", forbidden, got)
		}
	}
}
