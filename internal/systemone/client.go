// Package systemone asks a validated System One decision model whether one shell command is
// read-only.
package systemone

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/provider"
)

const (
	callTimeout = 5 * time.Second
	bodyLimit   = 64 << 10
)

type Model struct {
	Name     string
	Provider string
	ModelID  string
	ReadOnly float64
	Secrets  float64
	Code     float64
}

var Models = []Model{
	{Name: "openrouter:typesafe/jev-1.13", Provider: "openrouter", ModelID: "typesafe/jev-1.13", ReadOnly: 0.9, Secrets: 0.3, Code: 0.2},
	{Name: "venice:jev-latest", Provider: "venice", ModelID: "jev-latest", ReadOnly: 0.9, Secrets: 0.3, Code: 0.2},
	{Name: "openrouter:liquid/d1", Provider: "openrouter", ModelID: "liquid/d1", ReadOnly: 0.8, Secrets: 0.3, Code: 0.2},
}

func Lookup(name string) (Model, bool) {
	for _, m := range Models {
		if m.Name == name {
			return m, true
		}
	}
	return Model{}, false
}

const rereadGuidance = "Code inside quotes still runs when another shell or program reads it again: bash -c, sh -c, eval, find -exec, xargs sh. A $(...) or backtick anywhere, including inside array subscripts such as x[$(cmd)], (( )), test -v, printf -v or trap, runs a command. Options such as git -c core.pager=, hg --config hooks., tar --to-command, sort --compress-program, less +! and rsync -e run commands."

type question struct {
	Type         string            `json:"type"`
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria,omitempty"`
}

var effectCriteria = map[string]string{
	"read_only":        "Only reads files or prints information. Creates, changes and deletes nothing, sends nothing over the network, and runs no other command. " + rereadGuidance,
	"writes_files":     "Creates or changes files or directories.",
	"deletes":          "Deletes files, directories or version-control history.",
	"network":          "Contacts another machine or the internet, even only to read or look something up.",
	"runs_hidden_code": "Runs code whose content is not in the command text, such as a script file, build file, package script, hook, alias or downloaded code, or runs a command hidden inside another argument. " + rereadGuidance,
	"changes_system":   "Changes processes, services, packages, permissions, scheduled jobs or other system state.",
}

var questions = map[string]question{
	"effect": {
		Type:         "choice",
		Instructions: "What is the strongest effect running this shell command can have?",
		Criteria:     effectCriteria,
	},
	"secrets": {
		Type:         "noul",
		Instructions: "Could this command read, print or expose passwords, keys, tokens, credentials or environment variables?",
	},
	"code": {
		Type:         "noul",
		Instructions: "Does this command contain program code in another language or for another shell, for example bash -c or sh -c text, python -c, perl -e, node -e, an awk program, or a sed script?",
	},
}

type Answer struct {
	Model    string
	Effect   string
	ReadOnly float64
	Secrets  float64
	Code     float64
}

func (m Model) Allows(a Answer) bool {
	return a.ReadOnly >= m.ReadOnly && a.Secrets < m.Secrets && a.Code < m.Code
}

type ErrorKind string

const (
	KindCredits     ErrorKind = "credits"
	KindAuth        ErrorKind = "auth"
	KindRateLimited ErrorKind = "rate_limited"
	KindServer      ErrorKind = "server"
	KindTimeout     ErrorKind = "timeout"
	KindNetwork     ErrorKind = "network"
	KindMalformed   ErrorKind = "malformed"
)

type Error struct{ Kind ErrorKind }

func (e *Error) Error() string { return "system one check failed: " + string(e.Kind) }

func Classify(ctx context.Context, client *http.Client, m Model, entry provider.ProviderEntry, command string) (Answer, error) {
	if entry.APIKey == "" {
		return Answer{}, &Error{Kind: KindAuth}
	}
	body, err := json.Marshal(struct {
		Model     string              `json:"model"`
		State     string              `json:"state"`
		Questions map[string]question `json:"questions"`
	}{m.ModelID, command, questions})
	if err != nil {
		return Answer{}, &Error{Kind: KindMalformed}
	}

	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	failed := func(err error) (Answer, error) {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return Answer{}, &Error{Kind: KindTimeout}
		}
		return Answer{}, &Error{Kind: KindNetwork}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(entry.BaseURL, "/")+"/systemone", bytes.NewReader(body))
	if err != nil {
		return Answer{}, &Error{Kind: KindNetwork}
	}
	req.Header.Set("Content-Type", "application/json")
	name, value := entry.ResolveAuthHeader()
	req.Header.Set(name, value)

	c := http.Client{}
	if client != nil {
		c = *client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := c.Do(req)
	if err != nil {
		return failed(err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only response body
	switch {
	case resp.StatusCode == http.StatusPaymentRequired:
		return Answer{}, &Error{Kind: KindCredits}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Answer{}, &Error{Kind: KindAuth}
	case resp.StatusCode == http.StatusTooManyRequests:
		return Answer{}, &Error{Kind: KindRateLimited}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return Answer{}, &Error{Kind: KindServer}
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit+1))
	if err != nil {
		return failed(err)
	}
	if len(raw) > bodyLimit {
		return Answer{}, &Error{Kind: KindMalformed}
	}
	a, ok := parseAnswer(raw)
	if !ok {
		return Answer{}, &Error{Kind: KindMalformed}
	}
	return a, nil
}

func parseAnswer(raw []byte) (Answer, bool) {
	type answer struct {
		Type          string              `json:"type"`
		Choice        *string             `json:"choice"`
		Probabilities map[string]*float64 `json:"probabilities"`
		Noul          *float64            `json:"noul"`
	}
	var doc struct {
		Model   string            `json:"model"`
		Answers map[string]answer `json:"answers"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if dec.Decode(&doc) != nil || !errors.Is(dec.Decode(&struct{}{}), io.EOF) || doc.Model == "" {
		return Answer{}, false
	}
	inRange := func(p *float64) bool { return p != nil && *p >= 0 && *p <= 1 }

	effect, secrets, code := doc.Answers["effect"], doc.Answers["secrets"], doc.Answers["code"]
	if effect.Type != "choice" || effect.Choice == nil || secrets.Type != "noul" || code.Type != "noul" {
		return Answer{}, false
	}
	if _, known := effectCriteria[*effect.Choice]; !known {
		return Answer{}, false
	}
	for _, p := range effect.Probabilities {
		if !inRange(p) {
			return Answer{}, false
		}
	}
	readOnly := effect.Probabilities["read_only"]
	if !inRange(readOnly) || !inRange(secrets.Noul) || !inRange(code.Noul) {
		return Answer{}, false
	}
	return Answer{Model: doc.Model, Effect: *effect.Choice, ReadOnly: *readOnly, Secrets: *secrets.Noul, Code: *code.Noul}, true
}
