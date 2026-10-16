package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
)

func TestFavoriteTransition_ExactIdentity(t *testing.T) {
	anthropic := Favorite{Provider: "anthropic", ID: "shared-model"}
	openai := Favorite{Provider: "openai", ID: "shared-model"}

	added := applyFavorite([]Favorite{anthropic}, openai, true)
	if want := []Favorite{anthropic, openai}; !slices.Equal(added, want) {
		t.Fatalf("adding same ID under a different provider = %v, want %v", added, want)
	}

	removed := applyFavorite(added, openai, false)
	if want := []Favorite{anthropic}; !slices.Equal(removed, want) {
		t.Fatalf("removing one provider's pair = %v, want %v", removed, want)
	}

	casing := applyFavorite([]Favorite{anthropic}, Favorite{Provider: "Anthropic", ID: "shared-model"}, false)
	if want := []Favorite{anthropic}; !slices.Equal(casing, want) {
		t.Fatalf("removing a differently-cased provider = %v, want %v", casing, want)
	}
}

func TestFavoriteTransition_OrderedAddRemove(t *testing.T) {
	a := Favorite{Provider: "anthropic", ID: "a"}
	b := Favorite{Provider: "openai", ID: "b"}
	c := Favorite{Provider: "anthropic", ID: "c"}

	cases := []struct {
		name     string
		existing []Favorite
		target   Favorite
		want     bool
		expected []Favorite
	}{
		{"add to empty list", nil, a, true, []Favorite{a}},
		{"add absent pair appends last", []Favorite{a, b}, c, true, []Favorite{a, b, c}},
		{"add present pair keeps order", []Favorite{a, b, c}, a, true, []Favorite{a, b, c}},
		{"remove keeps sibling order", []Favorite{a, b, c}, b, false, []Favorite{a, c}},
		{"remove every exact duplicate", []Favorite{a, b, a, c, a}, a, false, []Favorite{b, c}},
		{"remove absent pair is a no-op", []Favorite{a, b}, c, false, []Favorite{a, b}},
		{"remove from empty list", nil, a, false, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyFavorite(tc.existing, tc.target, tc.want)
			if !slices.Equal(got, tc.expected) {
				t.Fatalf("applyFavorite(%v, %v, %t) = %v, want %v", tc.existing, tc.target, tc.want, got, tc.expected)
			}
		})
	}
}

func TestFavoriteTransition_DefensiveCopies(t *testing.T) {
	a := Favorite{Provider: "anthropic", ID: "a"}
	b := Favorite{Provider: "openai", ID: "b"}
	c := Favorite{Provider: "anthropic", ID: "c"}

	cases := []struct {
		name     string
		existing []Favorite
		target   Favorite
		want     bool
	}{
		{"append", []Favorite{a, b}, c, true},
		{"already present", []Favorite{a, b}, b, true},
		{"remove", []Favorite{a, b, c}, b, false},
		{"remove absent", []Favorite{a, b}, c, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			existing := slices.Clone(tc.existing)
			got := applyFavorite(existing, tc.target, tc.want)
			if len(got) == 0 {
				t.Fatalf("case needs a non-empty result to prove isolation")
			}
			gotBefore := slices.Clone(got)

			existing[0] = Favorite{Provider: "mutated", ID: "mutated"}
			if !slices.Equal(got, gotBefore) {
				t.Fatalf("mutating the caller list changed the result: %v, want %v", got, gotBefore)
			}

			got[0] = Favorite{Provider: "also-mutated", ID: "also-mutated"}
			if existing[0] != (Favorite{Provider: "mutated", ID: "mutated"}) {
				t.Fatalf("mutating the result changed the caller list: %v", existing[0])
			}
			for i := 1; i < len(existing); i++ {
				if existing[i] != tc.existing[i] {
					t.Fatalf("mutating the result changed caller entry %d: %v, want %v", i, existing[i], tc.existing[i])
				}
			}
		})
	}

	t.Run("append does not fill caller spare capacity", func(t *testing.T) {
		backing := []Favorite{a, b, {Provider: "reserved", ID: "reserved"}}
		existing := backing[:2]

		got := applyFavorite(existing, c, true)
		if want := []Favorite{a, b, c}; !slices.Equal(got, want) {
			t.Fatalf("applyFavorite = %v, want %v", got, want)
		}
		if backing[2] != (Favorite{Provider: "reserved", ID: "reserved"}) {
			t.Fatalf("append wrote into the caller's spare capacity: %v", backing[2])
		}
	})
}

func favoritesComposed(favs ...Favorite) map[string]any {
	list := make([]any, 0, len(favs))
	for _, f := range favs {
		list = append(list, map[string]any{"provider": f.Provider, "id": f.ID})
	}
	return map[string]any{"model": map[string]any{"favorites": list}}
}

func TestCacheToggleFavorite_GlobalPathAndReconciliation(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "global", "settings.yaml")
	project := filepath.Join(dir, "project-settings.yaml")
	writeAt(t, project, "model:\n  active:\n    provider: openai\n    id: gpt-5\n")
	projectBefore := readAt(t, project)

	c, err := NewCache(map[string]any{}, "/r", []string{global, project})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	gpt5 := Favorite{Provider: "openai", ID: "gpt-5"}
	got, reason, cat, err := c.ToggleFavorite(gpt5, true)
	if reason != ReasonNone || err != nil {
		t.Fatalf("first toggle = (%q, %q, %v), want success", reason, cat, err)
	}
	want := []Favorite{gpt5}
	if !slices.Equal(got, want) || !slices.Equal(c.Favorites(), want) {
		t.Fatalf("first toggle result/cache = (%v, %v), want %v", got, c.Favorites(), want)
	}
	if durable := favoritesOnDisk(t, global); !slices.Equal(durable, want) {
		t.Fatalf("durable global favorites = %v, want %v", durable, want)
	}
	if after := readAt(t, project); after != projectBefore {
		t.Fatalf("project layer changed by a global-only toggle:\n%q\nwant\n%q", after, projectBefore)
	}

	writeAt(t, global, "model:\n  favorites: [{provider: openai, id: gpt-5}, {provider: anthropic, id: opus}]\n")

	gemini := Favorite{Provider: "google", ID: "gemini"}
	got, reason, _, err = c.ToggleFavorite(gemini, true)
	if reason != ReasonNone || err != nil {
		t.Fatalf("reconciling toggle = (%q, %v), want success", reason, err)
	}
	want = []Favorite{gpt5, {Provider: "anthropic", ID: "opus"}, gemini}
	if !slices.Equal(got, want) {
		t.Fatalf("reconciled result = %v, want %v (it dropped the externally added pair)", got, want)
	}
	if !slices.Equal(c.Favorites(), want) {
		t.Fatalf("reconciled cache = %v, want %v", c.Favorites(), want)
	}
	if durable := favoritesOnDisk(t, global); !slices.Equal(durable, want) {
		t.Fatalf("durable favorites = %v, want %v", durable, want)
	}

	got[0] = Favorite{Provider: "tampered", ID: "tampered"}
	if !slices.Equal(c.Favorites(), want) {
		t.Fatalf("mutating the returned list changed the cache: %v", c.Favorites())
	}
}

func TestCacheToggleFavorite_NoLayerFailsClosed(t *testing.T) {
	target := Favorite{Provider: "openai", ID: "gpt-5"}
	cases := []struct {
		name   string
		layers []string
	}{
		{"no layers", nil},
		{"empty first layer", []string{""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewCache(map[string]any{}, "/r", tc.layers)
			if err != nil {
				t.Fatalf("NewCache: %v", err)
			}
			got, reason, cat, err := c.ToggleFavorite(target, true)
			if got != nil || reason != ReasonRereadParseError || cat != "" || err == nil {
				t.Fatalf("= (%v, %q, %q, %v), want (nil, reread_parse_error, \"\", error)", got, reason, cat, err)
			}
			if len(c.Favorites()) != 0 {
				t.Fatalf("cache favorites changed on a fail-closed toggle: %v", c.Favorites())
			}
		})
	}
}

func TestCacheToggleFavorite_NoOpPreservesBytes(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "settings.yaml")
	writeAt(t, global, "model:\n  favorites: [{provider: openai, id: gpt-5}]  # mine\n")
	before := readAt(t, global)

	gpt5 := Favorite{Provider: "openai", ID: "gpt-5"}
	c, err := NewCache(favoritesComposed(gpt5), "/r", []string{global})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	got, reason, _, err := c.ToggleFavorite(gpt5, true)
	if reason != ReasonNone || err != nil {
		t.Fatalf("duplicate add = (%q, %v), want success", reason, err)
	}
	want := []Favorite{gpt5}
	if !slices.Equal(got, want) || !slices.Equal(c.Favorites(), want) {
		t.Fatalf("no-op result/cache = (%v, %v), want %v", got, c.Favorites(), want)
	}
	if after := readAt(t, global); after != before {
		t.Fatalf("no-op toggle rewrote bytes:\n%q\nwant\n%q", after, before)
	}
}

func TestCacheToggleFavorite_PrePublishFailure(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "settings.yaml")
	writeAt(t, global, "model:\n  favorites:\n    - provider: openai\n      id: gpt-5\n")
	before := readAt(t, global)

	gpt5 := Favorite{Provider: "openai", ID: "gpt-5"}
	c, err := NewCache(favoritesComposed(gpt5), "/r", []string{global})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	got, reason, cat, err := c.ToggleFavorite(Favorite{Provider: "anthropic", ID: "opus"}, true)
	if got != nil || reason != ReasonWriteError || cat != fserrors.IOError || !errors.Is(err, sentinel) {
		t.Fatalf("= (%v, %q, %q, %v), want (nil, write_error, io_error, wrap of sentinel)", got, reason, cat, err)
	}
	restore()
	if favs := c.Favorites(); !slices.Equal(favs, []Favorite{gpt5}) {
		t.Fatalf("cache changed on a pre-publish failure: %v", favs)
	}
	if after := readAt(t, global); after != before {
		t.Fatalf("pre-publish failure changed bytes:\n%q\nwant\n%q", after, before)
	}
}

func TestCacheToggleFavorite_ParentSyncFailure(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "settings.yaml")
	writeAt(t, global, "model:\n  favorites:\n    - provider: openai\n      id: gpt-5\n")

	gpt5 := Favorite{Provider: "openai", ID: "gpt-5"}
	c, err := NewCache(favoritesComposed(gpt5), "/r", []string{global})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	sentinel := errors.New("forced parent dir sync failure")
	restore := fsutil.SetSyncDirForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	opus := Favorite{Provider: "anthropic", ID: "opus"}
	got, reason, cat, err := c.ToggleFavorite(opus, true)
	if got != nil || reason != ReasonParentDirError || cat != fserrors.IOError || !errors.Is(err, sentinel) {
		t.Fatalf("= (%v, %q, %q, %v), want (nil, parent_dir_error, io_error, wrap of sentinel)", got, reason, cat, err)
	}
	restore()
	if favs := c.Favorites(); !slices.Equal(favs, []Favorite{gpt5}) {
		t.Fatalf("cache changed on a parent-sync failure: %v", favs)
	}
	want := []Favorite{gpt5, opus}
	if durable := favoritesOnDisk(t, global); !slices.Equal(durable, want) {
		t.Fatalf("durable favorites = %v, want the already-published %v", durable, want)
	}
}
