package enforce

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"reflect"
	"testing"
)

func validAutoEdits() Policy {
	return Policy{
		Mode:         ModeAutoEdits,
		BlockedPaths: []string{"/home/u/.codemeld", "/home/u/link", "/home/u/real"},
		WriteRoots:   []string{"/p/a", "/p/b.go"},
		NoWritePaths: []string{"/p/.codemeld"},
		TmpDir:       "/tmp/codemeld-1",
	}
}

func frameBytes(payload string) []byte {
	b := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(b, uint32(len(payload)))
	return append(b, payload...)
}

func roundTrip(t *testing.T, p Policy) Policy {
	t.Helper()
	var buf bytes.Buffer
	if err := WritePolicyFrame(&buf, p); err != nil {
		t.Fatalf("WritePolicyFrame: %v", err)
	}
	got, err := ReadPolicyFrame(&buf)
	if err != nil {
		t.Fatalf("ReadPolicyFrame: %v", err)
	}
	return got
}

func TestPolicyFrameRoundTrips(t *testing.T) {
	plan := Policy{Mode: ModePlan, BlockedPaths: []string{"/home/u/.codemeld"}}
	network := validAutoEdits()
	network.ExceptionalAuthority = NetworkAccessAuthority
	for name, p := range map[string]Policy{"auto_edits": validAutoEdits(), "plan": plan, "network": network} {
		if got := roundTrip(t, p); !reflect.DeepEqual(got, p) {
			t.Errorf("%s: round trip = %+v, want %+v", name, got, p)
		}
	}
	if reflect.DeepEqual(roundTrip(t, network), roundTrip(t, validAutoEdits())) {
		t.Error("network policy decoded equal to the ordinary policy")
	}
}

func TestReadPolicyFrameLeavesTrailingBytes(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePolicyFrame(&buf, validAutoEdits()); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("payload")
	if _, err := ReadPolicyFrame(&buf); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(&buf)
	if string(rest) != "payload" {
		t.Errorf("remaining = %q, want %q", rest, "payload")
	}
}

func TestWritePolicyFrameRejectsOversizedPolicy(t *testing.T) {
	p := validAutoEdits()
	for range 5000 {
		p.BlockedPaths = append(p.BlockedPaths, "/blocked/entry/number/padding")
	}
	var buf bytes.Buffer
	err := WritePolicyFrame(&buf, p)
	if err == nil || err.Error() != "policy frame exceeds 65536 bytes" {
		t.Fatalf("err = %v, want the size error", err)
	}
	if buf.Len() != 0 {
		t.Errorf("wrote %d bytes, want 0", buf.Len())
	}
}

func TestReadPolicyFrameRejectsBadFrames(t *testing.T) {
	good := `{"mode":"plan","exceptional_authority":"","blocked_paths":["/b"],"write_roots":null,"no_write_paths":null,"tmp_dir":""}`
	huge := make([]byte, 4)
	binary.BigEndian.PutUint32(huge, 70000)
	cases := map[string][]byte{
		"declared length 70000": huge,
		"truncated":             frameBytes(good)[:20],
		"short header":          {0, 0},
		"unknown field extra":   frameBytes(`{"mode":"plan","blocked_paths":["/b"],"extra":1}`),
		"unknown read_roots":    frameBytes(`{"mode":"plan","blocked_paths":["/b"],"read_roots":["/"]}`),
		"second value":          frameBytes(good + ` {}`),
		"trailing garbage":      frameBytes(good + ` x`),
	}
	for name, b := range cases {
		if _, err := ReadPolicyFrame(bytes.NewReader(b)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := ReadPolicyFrame(bytes.NewReader(frameBytes(good + " \n\t"))); err != nil {
		t.Errorf("trailing whitespace: %v", err)
	}
}

func TestPolicyValidationRejects(t *testing.T) {
	cases := map[string]func(*Policy){
		"empty blocked_paths":          func(p *Policy) { p.BlockedPaths = nil },
		"relative blocked":             func(p *Policy) { p.BlockedPaths = []string{"docs"} },
		"relative write root":          func(p *Policy) { p.WriteRoots = []string{"docs"} },
		"relative no-write":            func(p *Policy) { p.NoWritePaths = []string{"docs"} },
		"relative tmp_dir":             func(p *Policy) { p.TmpDir = "docs" },
		"unclean blocked":              func(p *Policy) { p.BlockedPaths = []string{"/a/../b"} },
		"unclean write root":           func(p *Policy) { p.WriteRoots = []string{"/a/../b"} },
		"unclean no-write":             func(p *Policy) { p.NoWritePaths = []string{"/a/../b"} },
		"unclean tmp_dir":              func(p *Policy) { p.TmpDir = "/a/../b" },
		"mode build":                   func(p *Policy) { p.Mode = "build" },
		"auto_edits empty tmp_dir":     func(p *Policy) { p.TmpDir = "" },
		"auto_edits unknown authority": func(p *Policy) { p.ExceptionalAuthority = "delete" },
		"plan with tmp_dir":            func(p *Policy) { *p = Policy{Mode: ModePlan, BlockedPaths: []string{"/b"}, TmpDir: "/t"} },
		"plan with write_roots":        func(p *Policy) { *p = Policy{Mode: ModePlan, BlockedPaths: []string{"/b"}, WriteRoots: []string{"/w"}} },
		"plan with no_write_paths": func(p *Policy) {
			*p = Policy{Mode: ModePlan, BlockedPaths: []string{"/b"}, NoWritePaths: []string{"/w"}}
		},
		"plan with exceptional_authority": func(p *Policy) {
			*p = Policy{Mode: ModePlan, BlockedPaths: []string{"/b"}, ExceptionalAuthority: NetworkAccessAuthority}
		},
	}
	for name, mutate := range cases {
		p := validAutoEdits()
		mutate(&p)
		if err := WritePolicyFrame(io.Discard, p); err == nil {
			t.Errorf("%s: WritePolicyFrame accepted", name)
		}
		payload, err := jsonOf(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPolicyFrame(bytes.NewReader(frameBytes(payload))); err == nil {
			t.Errorf("%s: ReadPolicyFrame accepted", name)
		}
	}
}

func TestWritePolicyFrameRejectsInvalidUTF8Paths(t *testing.T) {
	const bad = "/private/\xff"
	cases := map[string]func(*Policy){
		"blocked":    func(p *Policy) { p.BlockedPaths = append(p.BlockedPaths, bad) },
		"write root": func(p *Policy) { p.WriteRoots = []string{bad} },
		"no-write":   func(p *Policy) { p.NoWritePaths = []string{bad} },
		"tmp_dir":    func(p *Policy) { p.TmpDir = bad },
	}
	for name, mutate := range cases {
		p := validAutoEdits()
		mutate(&p)
		var buf bytes.Buffer
		if err := WritePolicyFrame(&buf, p); err == nil {
			t.Errorf("%s: WritePolicyFrame accepted", name)
		}
		if buf.Len() != 0 {
			t.Errorf("%s: wrote %d bytes, want 0", name, buf.Len())
		}
	}
}

func TestPolicyFrameRoundTripsUnicodePath(t *testing.T) {
	p := validAutoEdits()
	p.BlockedPaths = append(p.BlockedPaths, "/tmp/é日本")
	p.WriteRoots = []string{"/tmp/é日本/w"}
	p.NoWritePaths = []string{"/tmp/é日本/w/.codemeld"}
	p.TmpDir = "/tmp/é日本/t"
	if got := roundTrip(t, p); !reflect.DeepEqual(got, p) {
		t.Errorf("round trip = %+v, want %+v", got, p)
	}
}

func jsonOf(p Policy) (string, error) {
	b, err := json.Marshal(p)
	return string(b), err
}

func TestControlArg(t *testing.T) {
	if ControlArg != "--control" {
		t.Errorf("ControlArg = %q", ControlArg)
	}
}
