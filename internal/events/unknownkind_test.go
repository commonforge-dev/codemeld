package events

import (
	"encoding/json"
	"errors"
	"testing"

	"codemeld.dev/codemeld/internal/sessions"
)

func TestValidatePayload_UnknownKindWrapsSentinel(t *testing.T) {
	err := ValidatePayload("from_a_newer_build", json.RawMessage(`{"x":1}`))
	if !errors.Is(err, sessions.ErrUnknownEventKind) {
		t.Fatalf("err = %v, want it to wrap sessions.ErrUnknownEventKind", err)
	}
	if got, want := err.Error(), `unknown event kind "from_a_newer_build"`; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestValidatePayload_KnownKindBadPayloadIsNotUnknownKind(t *testing.T) {
	err := ValidatePayload(KindStreamInterrupted, json.RawMessage(`{"source":"esc"}`))
	if err == nil {
		t.Fatal("stream_interrupted without content_chars was accepted")
	}
	if errors.Is(err, sessions.ErrUnknownEventKind) {
		t.Fatalf("err = %v, a known kind with a bad payload must not wrap ErrUnknownEventKind", err)
	}
}
