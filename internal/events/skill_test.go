package events

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

func testDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func validSlashLoad() SkillLoaded {
	return SkillLoaded{Name: "my-skill", Layer: "project", Via: "slash", Bytes: 4, SHA256: testDigest("body")}
}

func TestSkillLoaded_AcceptsBuiltRecords(t *testing.T) {
	child := ids.NewV7()
	cases := map[string]SkillLoaded{
		"slash body":         validSlashLoad(),
		"empty body":         {Name: "my-skill", Layer: "global", Via: "slash", Bytes: 0, SHA256: testDigest("")},
		"digit-leading name": {Name: "7zip", Layer: "global", Via: "tool", Bytes: 4, SHA256: testDigest("body")},
		"64-char name":       {Name: strings.Repeat("a", 64), Layer: "project", Via: "tool", Bytes: 4, SHA256: testDigest("body")},
		"tool file":          {Name: "my-skill", Layer: "project", Via: "tool", File: "refs/guide.md", Bytes: 3, SHA256: testDigest("abc")},
		"child tool call":    {Name: "my-skill", Layer: "project", Via: "tool", Bytes: 4, SHA256: testDigest("body"), ChildInvocationID: child},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			ev, err := Build(p)
			if err != nil {
				t.Fatalf("Build(%+v) error = %v", p, err)
			}
			got := ev.(sessions.Event)
			if got.Kind != "skill_loaded" {
				t.Fatalf("kind = %q, want skill_loaded", got.Kind)
			}
			if err := ValidatePayload("skill_loaded", got.Payload); err != nil {
				t.Fatalf("ValidatePayload(%s) error = %v", got.Payload, err)
			}
		})
	}
}

func TestSkillLoaded_RejectsInvalidRecords(t *testing.T) {
	cases := map[string]func(*SkillLoaded){
		"empty name":          func(p *SkillLoaded) { p.Name = "" },
		"uppercase name":      func(p *SkillLoaded) { p.Name = "My-skill" },
		"leading hyphen name": func(p *SkillLoaded) { p.Name = "-skill" },
		"double hyphen name":  func(p *SkillLoaded) { p.Name = "my--skill" },
		"65-char name":        func(p *SkillLoaded) { p.Name = strings.Repeat("a", 65) },
		"unknown layer":       func(p *SkillLoaded) { p.Layer = "user" },
		"unknown via":         func(p *SkillLoaded) { p.Via = "auto" },
		"absolute file":       func(p *SkillLoaded) { p.Via, p.File = "tool", "/etc/passwd" },
		"dot file":            func(p *SkillLoaded) { p.Via, p.File = "tool", "." },
		"parent file":         func(p *SkillLoaded) { p.Via, p.File = "tool", "../other/SKILL.md" },
		"inner parent file":   func(p *SkillLoaded) { p.Via, p.File = "tool", "refs/../../x" },
		"unclean file":        func(p *SkillLoaded) { p.Via, p.File = "tool", "refs//guide.md" },
		"trailing slash file": func(p *SkillLoaded) { p.Via, p.File = "tool", "refs/" },
		"negative bytes":      func(p *SkillLoaded) { p.Bytes = -1 },
		"empty digest":        func(p *SkillLoaded) { p.SHA256 = "" },
		"uppercase digest":    func(p *SkillLoaded) { p.SHA256 = strings.ToUpper(testDigest("body")) },
		"short digest":        func(p *SkillLoaded) { p.SHA256 = testDigest("body")[:63] },
		"bad child id":        func(p *SkillLoaded) { p.Via, p.ChildInvocationID = "tool", "not-a-uuid" },
		"slash with file":     func(p *SkillLoaded) { p.File = "refs/guide.md" },
		"slash with child id": func(p *SkillLoaded) { p.ChildInvocationID = ids.NewV7() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := validSlashLoad()
			mutate(&p)
			if _, err := Build(p); err == nil {
				t.Fatalf("Build accepted %+v", p)
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidatePayload("skill_loaded", raw); err == nil {
				t.Fatalf("ValidatePayload accepted %s", raw)
			}
		})
	}
}

func TestSkillLoaded_DecodeRejectsMissingRequiredFields(t *testing.T) {
	base := `{"name":"my-skill","layer":"project","via":"slash","file":"","bytes":0,"sha256":"` + testDigest("") + `"}`
	if err := ValidatePayload("skill_loaded", json.RawMessage(base)); err != nil {
		t.Fatalf("ValidatePayload(%s) error = %v, want empty file and zero bytes accepted", base, err)
	}
	for _, field := range []string{"name", "layer", "via", "file", "bytes", "sha256"} {
		t.Run(field, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal([]byte(base), &m); err != nil {
				t.Fatal(err)
			}
			delete(m, field)
			raw, _ := json.Marshal(m)
			if err := ValidatePayload("skill_loaded", raw); err == nil {
				t.Fatalf("ValidatePayload accepted %s without %s", raw, field)
			}
		})
	}
}

func TestAppendSkillLoaded_AppendsOnlyValidRecords(t *testing.T) {
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	if err := AppendSkillLoaded(store, validSlashLoad()); err != nil {
		t.Fatalf("AppendSkillLoaded error = %v", err)
	}
	bad := validSlashLoad()
	bad.Bytes = -1
	if err := AppendSkillLoaded(store, bad); err == nil {
		t.Fatal("AppendSkillLoaded accepted a negative byte count")
	}
	records := store.Records()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	ev, ok := records[0].(sessions.Event)
	if !ok || ev.Kind != "skill_loaded" {
		t.Fatalf("record = %+v, want a skill_loaded event", records[0])
	}
	var got SkillLoaded
	if err := json.Unmarshal(ev.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if got != validSlashLoad() {
		t.Fatalf("payload = %+v, want %+v", got, validSlashLoad())
	}
}
