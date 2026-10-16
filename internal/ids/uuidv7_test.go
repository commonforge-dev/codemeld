// Tests for NewV7 and IsValidV7 canonical-form invariants, validator rejections, and concurrent-mint uniqueness.
package ids

import (
	"sync"
	"testing"
)

func TestNewV7_CanonicalForm(t *testing.T) {
	for i := range 256 {
		got := NewV7()
		if len(got) != 36 {
			t.Fatalf("iter %d: len = %d, want 36 (%q)", i, len(got), got)
		}
		if !IsValidV7(got) {
			t.Fatalf("iter %d: IsValidV7 rejected freshly minted id %q", i, got)
		}
		// Version nibble is the first char of the third group: positions 14.
		if got[14] != '7' {
			t.Fatalf("iter %d: version nibble = %q, want '7' (%q)", i, got[14], got)
		}
		// Variant nibble is the first char of the fourth group: position 19.
		switch got[19] {
		case '8', '9', 'a', 'b':
		default:
			t.Fatalf("iter %d: variant nibble = %q, want one of 8/9/a/b (%q)", i, got[19], got)
		}
		// Lowercase invariant: no uppercase hex.
		for j, c := range got {
			if c >= 'A' && c <= 'F' {
				t.Fatalf("iter %d: uppercase hex at pos %d in %q", i, j, got)
			}
		}
	}
}

func TestNewV7_ConcurrentNoCollisions(t *testing.T) {
	const (
		goroutines = 50
		perG       = 20 // 50 * 20 = 1000 calls
	)
	var (
		mu   sync.Mutex
		seen = make(map[string]struct{}, goroutines*perG)
		wg   sync.WaitGroup
	)
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			local := make([]string, 0, perG)
			for range perG {
				local = append(local, NewV7())
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range local {
				if _, dup := seen[id]; dup {
					t.Errorf("duplicate UUIDv7 in concurrent mint: %q", id)
					return
				}
				seen[id] = struct{}{}
			}
		}()
	}
	wg.Wait()
	if got := len(seen); got != goroutines*perG {
		t.Fatalf("unique ids = %d, want %d", got, goroutines*perG)
	}
}

func TestIsValidV7_Rejections(t *testing.T) {
	// A known-good freshly minted id, used as the base for targeted mutations.
	base := NewV7()
	if !IsValidV7(base) {
		t.Fatalf("base id not valid: %q", base)
	}

	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"too_short", base[:35]},
		{"too_long", base + "0"},
		{"wrong_version_4", replaceAt(base, 14, '4')},
		{"wrong_version_0", replaceAt(base, 14, '0')},
		{"wrong_variant_c", replaceAt(base, 19, 'c')},
		{"wrong_variant_7", replaceAt(base, 19, '7')},
		{"uppercase_hex", replaceAt(base, 0, upperHex(base[0]))},
		{"non_hex_char", replaceAt(base, 0, 'g')},
		{"missing_dash", base[:8] + "X" + base[9:]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if IsValidV7(tc.in) {
				t.Fatalf("IsValidV7(%q) = true, want false", tc.in)
			}
		})
	}
}

func TestIsValidV7_AcceptsAllVariantNibbles(t *testing.T) {
	base := NewV7()
	for _, v := range []byte{'8', '9', 'a', 'b'} {
		s := replaceAt(base, 19, rune(v))
		if !IsValidV7(s) {
			t.Fatalf("IsValidV7(%q) = false for variant nibble %q, want true", s, v)
		}
	}
}

func replaceAt(s string, i int, r rune) string {
	b := []byte(s)
	b[i] = byte(r)
	return string(b)
}

func upperHex(c byte) rune {
	switch {
	case c >= 'a' && c <= 'f':
		return rune(c - ('a' - 'A'))
	case c >= '0' && c <= '9':
		// Already uppercase-equivalent; force a hex letter so the mutation is meaningful.
		return 'A'
	default:
		return 'A'
	}
}
