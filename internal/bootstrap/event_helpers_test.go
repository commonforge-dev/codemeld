// Shared event-payload decoders for bootstrap tests: one generic filter-unmarshal-collect
// over the in-memory store record stream and one over a disk-read session, replacing the
// per-kind copies that dupl flagged.
package bootstrap

import (
	"encoding/json"
	"testing"

	"codemeld.dev/codemeld/internal/sessions"
)

// decodeStoreEvents returns every event of the given kind in the store's in-memory
// record stream, in stream order, with its JSON payload decoded into T. It fails the
// test on a decode error, naming the kind so a failure stays as easy to diagnose as the
// per-kind decoders it replaces.
func decodeStoreEvents[T any](t *testing.T, store *sessions.Store, kind string) []T {
	t.Helper()
	var out []T
	for _, ev := range kindEvents(t, store, kind) {
		var p T
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode %s: %v", kind, err)
		}
		out = append(out, p)
	}
	return out
}

// decodeDiskEvents returns every event of the given kind in a disk-read session's record
// stream, in stream order, with its JSON payload decoded into T. It fails the test on a
// decode error, naming the kind. Callers pass a *sessions.Session (e.g. from
// readSessionFile) so the assertion sees the flushed/durable stream rather than the
// in-memory store object.
func decodeDiskEvents[T any](t *testing.T, sess *sessions.Session, kind string) []T {
	t.Helper()
	var out []T
	for _, r := range sess.Records {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != kind {
			continue
		}
		var p T
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode %s from disk: %v", kind, err)
		}
		out = append(out, p)
	}
	return out
}
