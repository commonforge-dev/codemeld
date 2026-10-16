// Event append API: validates a payload, coerces invalid UTF-8 to U+FFFD, mints
// a UUIDv7 record id, stamps the canonical timestamp, and appends the event
// record to the active session store.
package events

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

// now is a test seam for the record timestamp so append ordering is observable
// without wall-clock coupling; production callers see time.Now().UTC().
var now = func() time.Time { return time.Now().UTC() }

// Append validates payload, mints a fresh UUIDv7 record id, stamps the canonical
// timestamp, and appends the event record to store. The payload's string fields
// are coerced to valid UTF-8 (invalid byte sequences replaced with U+FFFD)
// before marshalling, and always-present list fields render as “
// rather than null. It returns the appended record. Append does not flush;
// callers trigger durability at the points via the store. An invalid
// payload is rejected before anything is appended.
func Append(store *sessions.Store, payload EventPayload) (sessions.Record, error) {
	if store == nil {
		return nil, fmt.Errorf("events.Append: nil store")
	}
	ev, err := Build(payload)
	if err != nil {
		return nil, err
	}
	store.Append(ev)
	return ev, nil
}

func Build(payload EventPayload) (sessions.Record, error) {
	if payload == nil {
		return nil, fmt.Errorf("events.Build: nil payload")
	}
	// A typed nil (e.g. var p *LaunchBegan; Append(store, p)) satisfies the
	// interface and survives the == nil check, but a value-receiver validate()
	// on a nil pointer would panic. Reject it as an invalid payload instead.
	if rv := reflect.ValueOf(payload); isNilKind(rv.Kind()) && rv.IsNil() {
		return nil, fmt.Errorf("events.Build: nil payload")
	}
	// Validate the canonical (UTF-8-coerced) payload, not the caller's raw one,
	// so cross-field checks observe the same bytes that will be persisted.
	canonical, ok := canonicalize(reflect.ValueOf(payload)).Interface().(EventPayload)
	if !ok {
		return nil, fmt.Errorf("events.Build: canonical payload does not implement EventPayload")
	}
	if err := canonical.validate(); err != nil {
		return nil, err
	}
	data, err := marshalPayload(canonical)
	if err != nil {
		return nil, fmt.Errorf("%s: marshal payload: %w", canonical.Kind(), err)
	}
	ev := sessions.Event{
		ID:   ids.NewV7(),
		Kind: canonical.Kind(),
		// Truncate to the canonical millisecond UTC form the session codec
		// persists (sessions.Marshal), so the returned/in-memory record and the
		// on-disk record carry the same timestamp rather than diverging by the
		// sub-millisecond precision now() may retain.
		Timestamp: now().UTC().Truncate(time.Millisecond),
		Payload:   json.RawMessage(data),
	}
	return ev, nil
}

// isNilKind reports whether k is one of the reflect kinds whose values can be
// nil, so reflect.Value.IsNil is safe to call.
func isNilKind(k reflect.Kind) bool {
	switch k {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
		return true
	default:
		return false
	}
}

// marshalPayload renders a payload to its canonical JSON: every string field is
// UTF-8-sanitized and every nil slice becomes an empty slice, so the on-disk
// bytes are deterministic and forward (UTF-8 coercion, always-present
// lists like model_response.anomaly and slash_command.args).
func marshalPayload(payload EventPayload) ([]byte, error) {
	canonical := canonicalize(reflect.ValueOf(payload))
	return json.Marshal(canonical.Interface())
}

// canonicalize returns a deep copy of v with two normalizations applied: every
// string is coerced to valid UTF-8 (invalid byte runs -> U+FFFD via
// strings.ToValidUTF8, which collapses each run to a single replacement rather
// than encoding/json's per-byte replacement), and every nil slice is
// materialized as an empty slice so it marshals as `[]`. The copy leaves the
// caller's payload untouched.
func canonicalize(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.String:
		return reflect.ValueOf(strings.ToValidUTF8(v.String(), "�")).Convert(v.Type())
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(canonicalize(v.Elem()))
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		t := v.Type()
		for i := range v.NumField() {
			if t.Field(i).PkgPath != "" {
				continue // unexported field; none of the payload types have these
			}
			out.Field(i).Set(canonicalize(v.Field(i)))
		}
		return out
	case reflect.Slice:
		// Allocate a non-nil slice even when the source is nil so an empty
		// always-present list renders as `[]`, not null.
		n := v.Len()
		out := reflect.MakeSlice(v.Type(), n, n)
		for i := range n {
			out.Index(i).Set(canonicalize(v.Index(i)))
		}
		return out
	default:
		return v
	}
}
