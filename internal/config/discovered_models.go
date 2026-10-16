package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/locks"
)

const (
	// DiscoveredModelsVersion is the current models.yaml schema version. It is written
	// on every store and lets future readers migrate or reject incompatible shapes.
	DiscoveredModelsVersion = 1
	// discoveredModelsMode keeps the store owner-only. Discovered model availability is
	// account-linked, so the file must not be group/world-readable — matching the
	// ChatGPT model cache and settings-persistence discipline.
	discoveredModelsMode os.FileMode = 0o600
	// discoveredModelsLockTimeout bounds the wait for the write lock, matching the other
	// sidecar-cache lock timeouts.
	discoveredModelsLockTimeout = 2 * time.Second
)

// DiscoveredModelsStore is the codemeld-owned, persisted discovered-model store. It is
// keyed by provider id so several providers share one file, and it carries only
// selection/capability metadata — never API keys, auth headers, prompts, or raw
// provider responses. The shape is deliberately generic (plain strings, ints, and a
// free-form capabilities map) so provider and bootstrap packages can populate it
// without internal/config depending on them.
type DiscoveredModelsStore struct {
	Version   int                           `yaml:"version"`
	Providers map[string]DiscoveredProvider `yaml:"providers"`
}

// DiscoveredProvider is one provider's discovered model list plus optional,
// secret-free refresh metadata. RefreshedAt/Source are advisory only; consumers must
// still tolerate their absence.
type DiscoveredProvider struct {
	RefreshedAt string            `yaml:"refreshed_at,omitempty"`
	Source      string            `yaml:"source,omitempty"`
	Models      []DiscoveredModel `yaml:"models"`
}

// DiscoveredModel is one discovered model's whitelisted selection/capability metadata.
// Capabilities holds provider-specific fields (e.g. reasoning levels, verbosity) as a
// generic map so this package needs no provider-specific types. Producers should place
// only safe, non-secret values there; as a backstop the write path redacts secret-shaped
// keys and values (see sanitizeProvider) so auth material cannot reach the on-disk store.
type DiscoveredModel struct {
	ID              string         `yaml:"id"`
	DisplayName     string         `yaml:"display_name,omitempty"`
	ContextWindow   int64          `yaml:"context_window,omitempty"`
	InputModalities []string       `yaml:"input_modalities,omitempty"`
	Capabilities    map[string]any `yaml:"capabilities,omitempty"`
}

func ReadDiscoveredModels(path string) (DiscoveredModelsStore, error) {
	if path == "" {
		return DiscoveredModelsStore{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return DiscoveredModelsStore{}, nil
		}
		return DiscoveredModelsStore{}, err
	}
	var store DiscoveredModelsStore
	if err := yaml.Unmarshal(data, &store); err != nil {
		return DiscoveredModelsStore{}, nil
	}
	return store, nil
}

// UpdateDiscoveredModelsProvider sets providerID's entry to models in the store at
// path, preserving every other provider's entry, and republishes the whole store
// owner-only and atomically under a sidecar lock. The read-merge-write happens under
// the lock so concurrent updates to different providers cannot lose each other's rows.
// It stamps the current schema version. An empty path is a no-op (nil error) so a
// caller with no known settings location silently skips persistence.
func UpdateDiscoveredModelsProvider(path, providerID string, entry DiscoveredProvider) error {
	return updateDiscoveredModelsProviderThen(path, providerID, entry, nil)
}

// UpdateDiscoveredModelsProviderThen sets providerID's store entry, runs then while
// still holding the discovered-models lock, and restores the exact prior store bytes if
// then fails. This lets callers pair the store write with a later durable write without
// allowing concurrent store updates to be clobbered by rollback.
func UpdateDiscoveredModelsProviderThen(path, providerID string, entry DiscoveredProvider, then func() error) error {
	return updateDiscoveredModelsProviderThen(path, providerID, entry, then)
}

func updateDiscoveredModelsProviderThen(path, providerID string, entry DiscoveredProvider, then func() error) error {
	if path == "" {
		if then != nil {
			return then()
		}
		return nil
	}
	if _, _, err := fsutil.EnsureDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("config: ensure discovered-models dir: %w", err)
	}
	release, reason, lockErr := locks.Acquire(path+".lock", discoveredModelsLockTimeout)
	if reason != locks.ReasonNone {
		return fmt.Errorf("config: lock discovered-models store: %w", lockErr)
	}
	defer release()

	prior, readErr := os.ReadFile(path)
	hadPrior := readErr == nil
	if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
		return fmt.Errorf("config: read prior discovered-models store: %w", readErr)
	}

	store, err := ReadDiscoveredModels(path)
	if err != nil {
		return fmt.Errorf("config: read discovered-models store: %w", err)
	}
	store.Version = DiscoveredModelsVersion
	if store.Providers == nil {
		store.Providers = map[string]DiscoveredProvider{}
	}
	store.Providers[providerID] = sanitizeProvider(entry)
	if err := writeDiscoveredModelsStore(path, store); err != nil {
		return err
	}
	if then == nil {
		return nil
	}
	if err := then(); err != nil {
		if restoreErr := restoreDiscoveredModelsStore(path, prior, hadPrior); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("config: restore discovered-models store after callback failure: %w", restoreErr))
		}
		return err
	}
	return nil
}

func writeDiscoveredModelsStore(path string, store DiscoveredModelsStore) error {
	data, err := yaml.Marshal(store)
	if err != nil {
		return fmt.Errorf("config: encode discovered-models store: %w", err)
	}
	if step, _, werr := fsutil.WriteAtomic(path, data, discoveredModelsMode); werr != nil {
		return fmt.Errorf("config: write discovered-models store (%s): %w", step, werr)
	}
	return nil
}

func restoreDiscoveredModelsStore(path string, prior []byte, hadPrior bool) error {
	if hadPrior {
		if step, _, err := fsutil.WriteAtomic(path, prior, discoveredModelsMode); err != nil {
			return fmt.Errorf("write prior discovered-models store (%s): %w", step, err)
		}
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove newly-created discovered-models store: %w", err)
	}
	return nil
}

// secretShapedTokens are lowercased substrings that mark a capability key or a string
// value as secret-shaped. The store persists selection metadata only, so any field whose
// key or value contains one of these is redacted before the store is written — a
// defensive backstop so a producer that mistakenly places auth material in the free-form
// metadata cannot leak it into the on-disk cache.
var secretShapedTokens = []string{"api_key", "apikey", "authorization", "bearer", "sk-"}

var secretTextNormalizer = strings.NewReplacer("_", "", "-", "", " ", "")

func looksSecret(s string) bool {
	s = strings.ToLower(s)
	normalized := secretTextNormalizer.Replace(s)
	for _, tok := range secretShapedTokens {
		if strings.Contains(s, tok) || (tok != "sk-" && strings.Contains(normalized, secretTextNormalizer.Replace(tok))) {
			return true
		}
	}
	return false
}

// sanitizeProvider returns a copy of entry with every secret-shaped string field and
// capability key/value removed. It never mutates the caller's slices or maps.
func sanitizeProvider(entry DiscoveredProvider) DiscoveredProvider {
	entry.RefreshedAt = redactSecret(entry.RefreshedAt)
	entry.Source = redactSecret(entry.Source)
	if len(entry.Models) == 0 {
		return entry
	}
	models := make([]DiscoveredModel, len(entry.Models))
	for i, m := range entry.Models {
		m.ID = redactSecret(m.ID)
		m.DisplayName = redactSecret(m.DisplayName)
		m.InputModalities = redactSecretSlice(m.InputModalities)
		m.Capabilities = sanitizeCapabilities(m.Capabilities)
		models[i] = m
	}
	entry.Models = models
	return entry
}

func redactSecret(s string) string {
	if looksSecret(s) {
		return ""
	}
	return s
}

func redactSecretSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !looksSecret(s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sanitizeCapabilities drops every secret-shaped key or value, recursing into nested
// maps and slices, and returns nil when nothing survives so the omitempty field
// disappears from the persisted YAML.
func sanitizeCapabilities(caps map[string]any) map[string]any {
	if len(caps) == 0 {
		return nil
	}
	sv, ok := sanitizeValue(map[string]any(caps))
	if !ok {
		return nil
	}
	return sv.(map[string]any)
}

// sanitizeValue redacts secret-shaped data from an arbitrary capability value. Maps and
// slices are handled via reflection so concrete producer shapes (map[string]string,
// []string, and nested combinations) are recursed the same as map[string]any/[]any:
// secret-shaped string keys and values are dropped, empty containers collapse to absent,
// and every surviving container is normalized to map[string]any / []any for stable YAML.
func sanitizeValue(v any) (any, bool) {
	if s, ok := v.(string); ok {
		if looksSecret(s) {
			return nil, false
		}
		return s, true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		out := make(map[string]any, rv.Len())
		for _, key := range rv.MapKeys() {
			ks := fmt.Sprint(key.Interface())
			if looksSecret(ks) {
				continue
			}
			if sv, ok := sanitizeValue(rv.MapIndex(key).Interface()); ok {
				out[ks] = sv
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case reflect.Slice, reflect.Array:
		out := make([]any, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			if sv, ok := sanitizeValue(rv.Index(i).Interface()); ok {
				out = append(out, sv)
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case reflect.Pointer, reflect.Interface:
		// Unwrap to the underlying value; a nil pointer/interface or an unsupported
		// underlying kind drops out via the recursive call's own fail-closed default.
		if rv.IsNil() {
			return nil, false
		}
		return sanitizeValue(rv.Elem().Interface())
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return v, true
	default:
		// Fail closed: structs, pointers-to-struct, funcs, chans, complex, etc. can
		// carry secret-shaped fields (e.g. an Authorization struct field) that YAML would
		// marshal into models.yaml, so drop anything not on the safe-scalar whitelist.
		return nil, false
	}
}
