// Package ids mints and validates the UUIDv7 identifiers used for sessions and records.
package ids

import (
	"regexp"
	"sync"

	"github.com/google/uuid"
)

// uuidV7Pattern matches the strict canonical form: 36 lowercase hex chars,
// version nibble 7, variant nibble in {8,9,a,b}. Uppercase hex is rejected even
// though uuid.Parse accepts it, so every minting site yields the same on-disk shape.
// Compiled once on first use via sync.OnceValue.
var uuidV7Pattern = sync.OnceValue(func() *regexp.Regexp {
	return regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
})

// NewV7 returns a freshly minted UUIDv7 in canonical 36-character lowercase form.
// It panics on a crypto/rand failure rather than returning an unusable id.
func NewV7() string {
	return uuid.Must(uuid.NewV7()).String()
}

// IsValidV7 reports whether s is the exact canonical form produced by NewV7,
// catching hand-edited or corrupted ids at load time.
func IsValidV7(s string) bool {
	if len(s) != 36 {
		return false
	}
	return uuidV7Pattern().MatchString(s)
}
