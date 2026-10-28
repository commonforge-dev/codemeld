package systemone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/provider"
)

const (
	testKey     = "sk-systemone-secret-sentinel"
	testCommand = `ls -la 'a b' | grep "x<y>&z" 2>/dev/null; echo	$HOME`
	bodyMarker  = "BODY-MARKER-7f3e"
)

func validJSON(effect string, readOnly, secrets, code float64) string {
	return fmt.Sprintf(`{"model":"typesafe/jev-1.13-20260917","answers":{"effect":{"type":"choice","choice":%q,"probabilities":{"read_only":%v,"writes_files":0.01,"network":0}},"secrets":{"type":"noul","noul":%v},"code":{"type":"noul","noul":%v}},"usage":{"cost":0.00001}}`, effect, readOnly, secrets, code)
}

func entryFor(srv *httptest.Server) provider.ProviderEntry {
	return provider.ProviderEntry{BaseURL: srv.URL + "/api/v1", APIKey: testKey}
}

func TestModels_MatchValidatedList(t *testing.T) {
	want := []Model{
		{"openrouter:typesafe/jev-1.13", "openrouter", "typesafe/jev-1.13", 0.9, 0.3, 0.2},
		{"venice:jev-latest", "venice", "jev-latest", 0.9, 0.3, 0.2},
		{"openrouter:liquid/d1", "openrouter", "liquid/d1", 0.8, 0.3, 0.2},
	}
	if len(Models) != len(want) {
		t.Fatalf("Models = %v, want %v", Models, want)
	}
	for i, w := range want {
		if Models[i] != w {
			t.Errorf("Models[%d] = %+v, want %+v", i, Models[i], w)
		}
		if got, ok := Lookup(w.Name); !ok || got != w {
			t.Errorf("Lookup(%q) = (%+v, %v)", w.Name, got, ok)
		}
	}
	for _, name := range []string{"off", "openrouter", "typesafe/jev-1.13", "openrouter:typesafe/jev-1.12", "OPENROUTER:liquid/d1"} {
		if _, ok := Lookup(name); ok {
			t.Errorf("Lookup(%q) found an entry", name)
		}
	}
}

func TestClassify_SendsOneRequestPerModel(t *testing.T) {
	custom := &provider.AuthHeader{Name: "X-Api-Key", Value: "key={api_key}"}
	for _, m := range Models {
		for _, auth := range []*provider.AuthHeader{nil, custom} {
			t.Run(fmt.Sprintf("%s custom=%v", m.Name, auth != nil), func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost || r.URL.Path != "/api/v1/systemone" {
						t.Errorf("request = %s %s, want POST /api/v1/systemone", r.Method, r.URL.Path)
					}
					if auth == nil {
						if got := r.Header.Get("Authorization"); got != "Bearer "+testKey {
							t.Errorf("Authorization = %q", got)
						}
					} else {
						if got := r.Header.Get("X-Api-Key"); got != "key="+testKey {
							t.Errorf("X-Api-Key = %q", got)
						}
						if got := r.Header.Get("Authorization"); got != "" {
							t.Errorf("Authorization = %q, want none with a custom header", got)
						}
					}
					var body struct {
						Model     string `json:"model"`
						State     string `json:"state"`
						Questions map[string]struct {
							Type         string            `json:"type"`
							Instructions string            `json:"instructions"`
							Criteria     map[string]string `json:"criteria"`
						} `json:"questions"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Errorf("decode request: %v", err)
					}
					if body.Model != m.ModelID || body.State != testCommand {
						t.Errorf("model, state = %q, %q", body.Model, body.State)
					}
					wantTypes := map[string]string{"effect": "choice", "secrets": "noul", "code": "noul"}
					if len(body.Questions) != len(wantTypes) {
						t.Errorf("questions = %v", body.Questions)
					}
					for id, typ := range wantTypes {
						q := body.Questions[id]
						if q.Type != typ || q.Instructions != questions[id].Instructions {
							t.Errorf("question %s = %+v", id, q)
						}
						if (id == "effect") != (q.Criteria != nil) {
							t.Errorf("question %s criteria = %v", id, q.Criteria)
						}
					}
					if len(body.Questions["effect"].Criteria) != 6 {
						t.Errorf("effect criteria = %v", body.Questions["effect"].Criteria)
					}
					_, _ = io.WriteString(w, validJSON("read_only", 0.97, 0.02, 0.01))
				}))
				defer srv.Close()

				entry := entryFor(srv)
				entry.AuthHeader = auth
				got, err := Classify(context.Background(), srv.Client(), m, entry, testCommand)
				if err != nil {
					t.Fatalf("Classify: %v", err)
				}
				want := Answer{Model: "typesafe/jev-1.13-20260917", Effect: "read_only", ReadOnly: 0.97, Secrets: 0.02, Code: 0.01}
				if got != want {
					t.Errorf("Answer = %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestClassify_EmptyKeyIsAuthWithoutRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	entry := entryFor(srv)
	entry.APIKey = ""
	_, err := Classify(context.Background(), srv.Client(), Models[0], entry, testCommand)
	var se *Error
	if !errors.As(err, &se) || se.Kind != KindAuth {
		t.Fatalf("err = %v, want auth", err)
	}
	if hits.Load() != 0 {
		t.Errorf("an uncredentialed request was sent")
	}
}

func replace(body, old, repl string) string {
	if !strings.Contains(body, old) {
		panic("fixture does not contain " + old)
	}
	return strings.Replace(body, old, repl, 1)
}

func TestClassify_FailureKinds(t *testing.T) {
	leaky := bodyMarker + " " + testKey + " " + testCommand
	valid := validJSON("read_only", 0.97, 0.02, 0.01)
	oversized := strings.Repeat("x", bodyLimit*2)
	status := func(code int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, body)
		}
	}
	ok := func(body string) http.HandlerFunc { return status(http.StatusOK, body) }

	var crossHits atomic.Int32
	cross := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		crossHits.Add(1)
		_, _ = io.WriteString(w, valid)
	}))
	defer cross.Close()
	var sameHits atomic.Int32

	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    ErrorKind
	}{
		{"402", status(http.StatusPaymentRequired, leaky), KindCredits},
		{"401", status(http.StatusUnauthorized, leaky), KindAuth},
		{"403", status(http.StatusForbidden, leaky), KindAuth},
		{"429", status(http.StatusTooManyRequests, leaky), KindRateLimited},
		{"500", status(http.StatusInternalServerError, leaky), KindServer},
		{"503", status(http.StatusServiceUnavailable, leaky), KindServer},
		{"oversized 402", status(http.StatusPaymentRequired, oversized), KindCredits},
		{"oversized 401", status(http.StatusUnauthorized, oversized), KindAuth},
		{"same-host redirect", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/elsewhere" {
				sameHits.Add(1)
				_, _ = io.WriteString(w, valid)
				return
			}
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, KindServer},
		{"cross-host redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, cross.URL+"/systemone", http.StatusTemporaryRedirect)
		}, KindServer},
		{"bad JSON", ok(`{"model":`), KindMalformed},
		{"leaky bad JSON", ok(leaky), KindMalformed},
		{"missing model", ok(replace(valid, `"model":"typesafe/jev-1.13-20260917",`, "")), KindMalformed},
		{"empty model", ok(replace(valid, `"typesafe/jev-1.13-20260917"`, `""`)), KindMalformed},
		{"missing answers", ok(`{"model":"m"}`), KindMalformed},
		{"missing code answer", ok(replace(valid, `,"code":{"type":"noul","noul":0.01}`, "")), KindMalformed},
		{"missing read_only", ok(replace(valid, `"read_only":0.97,`, "")), KindMalformed},
		{"null read_only", ok(replace(valid, `"read_only":0.97`, `"read_only":null`)), KindMalformed},
		{"missing secrets noul", ok(replace(valid, `"type":"noul","noul":0.02`, `"type":"noul"`)), KindMalformed},
		{"null secrets noul", ok(replace(valid, `"noul":0.02`, `"noul":null`)), KindMalformed},
		{"missing code noul", ok(replace(valid, `"type":"noul","noul":0.01`, `"type":"noul"`)), KindMalformed},
		{"null code noul", ok(replace(valid, `"noul":0.01`, `"noul":null`)), KindMalformed},
		{"read_only above 1", ok(replace(valid, `"read_only":0.97`, `"read_only":1.2`)), KindMalformed},
		{"secrets below 0", ok(replace(valid, `"noul":0.02`, `"noul":-0.1`)), KindMalformed},
		{"other effect probability above 1", ok(replace(valid, `"writes_files":0.01`, `"writes_files":1.5`)), KindMalformed},
		{"effect typed noul", ok(replace(valid, `"effect":{"type":"choice"`, `"effect":{"type":"noul"`)), KindMalformed},
		{"secrets typed choice", ok(replace(valid, `"secrets":{"type":"noul"`, `"secrets":{"type":"choice"`)), KindMalformed},
		{"code typed choice", ok(replace(valid, `"code":{"type":"noul"`, `"code":{"type":"choice"`)), KindMalformed},
		{"absent effect choice", ok(replace(valid, `"choice":"read_only",`, "")), KindMalformed},
		{"unknown effect choice", ok(replace(valid, `"choice":"read_only"`, `"choice":"harmless"`)), KindMalformed},
		{"oversized 2xx", ok(oversized), KindMalformed},
		{"over cap with a valid first 64 KiB", ok(valid + strings.Repeat(" ", bodyLimit+1-len(valid))), KindMalformed},
		{"trailing non-whitespace", ok(valid + " x"), KindMalformed},
		{"second JSON document", ok(valid + "\n{}"), KindMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			_, err := Classify(context.Background(), srv.Client(), Models[0], entryFor(srv), testCommand)
			assertKind(t, err, tt.want)
		})
	}
	if sameHits.Load() != 0 || crossHits.Load() != 0 {
		t.Errorf("a redirect was followed: same-host %d, cross-host %d", sameHits.Load(), crossHits.Load())
	}
}

func assertKind(t *testing.T, err error, want ErrorKind) {
	t.Helper()
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("err = %v (%T), want *Error", err, err)
	}
	if se.Kind != want {
		t.Errorf("Kind = %q, want %q", se.Kind, want)
	}
	for _, secret := range []string{testKey, "Bearer " + testKey, testCommand, bodyMarker} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q contains %q", err.Error(), secret)
		}
	}
}

func TestClassify_ValidEdgeAnswers(t *testing.T) {
	tests := []struct {
		name string
		body string
		want Answer
	}{
		{"non read_only top label", validJSON("network", 0.95, 0.1, 0.1), Answer{"typesafe/jev-1.13-20260917", "network", 0.95, 0.1, 0.1}},
		{"present zeros", validJSON("read_only", 0, 0, 0), Answer{"typesafe/jev-1.13-20260917", "read_only", 0, 0, 0}},
	}
	exact := validJSON("read_only", 0.97, 0.02, 0.01)
	exact += strings.Repeat(" ", bodyLimit-len(exact))
	tests = append(tests, struct {
		name string
		body string
		want Answer
	}{"exactly at cap", exact, Answer{"typesafe/jev-1.13-20260917", "read_only", 0.97, 0.02, 0.01}})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()
			got, err := Classify(context.Background(), srv.Client(), Models[0], entryFor(srv), testCommand)
			if err != nil {
				t.Fatalf("Classify: %v", err)
			}
			if got != tt.want {
				t.Errorf("Answer = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestClassify_InterruptedCalls(t *testing.T) {
	stall := func(partial bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			if partial {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"model":"m",`)
				w.(http.Flusher).Flush()
			}
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		}
	}

	t.Run("deadline before response", func(t *testing.T) {
		srv := httptest.NewServer(stall(false))
		defer srv.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := Classify(ctx, srv.Client(), Models[0], entryFor(srv), testCommand)
		assertKind(t, err, KindTimeout)
	})

	t.Run("deadline during a stalled body read", func(t *testing.T) {
		srv := httptest.NewServer(stall(true))
		defer srv.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := Classify(ctx, srv.Client(), Models[0], entryFor(srv), testCommand)
		assertKind(t, err, KindTimeout)
	})

	t.Run("caller cancellation", func(t *testing.T) {
		entered := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(entered)
			stall(true)(w, r)
		}))
		defer srv.Close()
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-entered
			cancel()
		}()
		_, err := Classify(ctx, srv.Client(), Models[0], entryFor(srv), testCommand)
		assertKind(t, err, KindNetwork)
	})

	t.Run("connection error", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		entry := entryFor(srv)
		srv.Close()
		_, err := Classify(context.Background(), nil, Models[0], entry, testCommand)
		assertKind(t, err, KindNetwork)
	})

	t.Run("mid-body I/O error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + `{"model":"m",`)
			_ = buf.Flush()
			_ = conn.Close()
		}))
		defer srv.Close()
		_, err := Classify(context.Background(), srv.Client(), Models[0], entryFor(srv), testCommand)
		assertKind(t, err, KindNetwork)
	})
}

func TestClassify_ConcurrentCallsShareClientWithoutChangingIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			State string `json:"state"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		var i int
		_, _ = fmt.Sscanf(body.State, "echo %d", &i)
		_, _ = io.WriteString(w, validJSON("read_only", float64(i)/100, 0, 0))
	}))
	defer srv.Close()

	client := srv.Client()
	transport, timeout := client.Transport, client.Timeout
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := Classify(context.Background(), client, Models[i%len(Models)], entryFor(srv), fmt.Sprintf("echo %d", i))
			if err != nil {
				t.Errorf("call %d: %v", i, err)
				return
			}
			if got.ReadOnly != float64(i)/100 {
				t.Errorf("call %d got another call's answer: %+v", i, got)
			}
		}()
	}
	wg.Wait()
	if client.CheckRedirect != nil || client.Transport != transport || client.Timeout != timeout {
		t.Errorf("Classify changed the supplied client")
	}
}

func TestModelAllows_Thresholds(t *testing.T) {
	const eps = 0.001
	for _, m := range []Model{Models[0], Models[2]} {
		pass := Answer{Effect: "read_only", ReadOnly: m.ReadOnly, Secrets: m.Secrets - eps, Code: m.Code - eps}
		tests := []struct {
			name string
			edit func(*Answer)
			want bool
		}{
			{"read_only at threshold", func(*Answer) {}, true},
			{"read_only just above", func(a *Answer) { a.ReadOnly += eps }, true},
			{"read_only just below", func(a *Answer) { a.ReadOnly -= eps }, false},
			{"secrets just below", func(*Answer) {}, true},
			{"secrets at threshold", func(a *Answer) { a.Secrets = m.Secrets }, false},
			{"secrets just above", func(a *Answer) { a.Secrets = m.Secrets + eps }, false},
			{"code just below", func(*Answer) {}, true},
			{"code at threshold", func(a *Answer) { a.Code = m.Code }, false},
			{"code just above", func(a *Answer) { a.Code = m.Code + eps }, false},
			{"read_only fails only on secrets", func(a *Answer) { a.ReadOnly, a.Secrets = 1, 0.9 }, false},
			{"read_only fails only on code", func(a *Answer) { a.ReadOnly, a.Code = 1, 0.9 }, false},
		}
		for _, tt := range tests {
			t.Run(m.Name+" "+tt.name, func(t *testing.T) {
				a := pass
				tt.edit(&a)
				if got := m.Allows(a); got != tt.want {
					t.Errorf("Allows(%+v) = %v, want %v", a, got, tt.want)
				}
			})
		}
	}
	jev, _ := Lookup("openrouter:typesafe/jev-1.13")
	liquid, _ := Lookup("openrouter:liquid/d1")
	between := Answer{ReadOnly: 0.85, Secrets: 0, Code: 0}
	if jev.Allows(between) || !liquid.Allows(between) {
		t.Errorf("read_only 0.85: jev %v, liquid %v; want false, true", jev.Allows(between), liquid.Allows(between))
	}
}
