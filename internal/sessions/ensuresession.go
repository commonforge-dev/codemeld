package sessions

import (
	"fmt"
	"path/filepath"
	"time"

	"codemeld.dev/codemeld/internal/ids"
)

func EnsureSession(home, canonicalFolder string, startedAt time.Time, initialRecords []Record) (*Store, error) {
	return storeForSession(home, newSession(canonicalFolder, startedAt, initialRecords, "", nil))
}

func EnsureChildSession(home string, parent MetadataSnapshot, title string, origin ForkOrigin, records []Record) (*Store, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("sessions.EnsureChildSession: a child session needs at least one initial record to carry parent_id")
	}
	linked := make([]Record, len(records))
	copy(linked, records)
	linked[0] = withParentID(linked[0], origin.RecordID)
	child := newSession(parent.Folder, parent.StartedAt, linked, title, &origin)
	if err := validateLoadable(child); err != nil {
		return nil, fmt.Errorf("sessions.EnsureChildSession: %w", err)
	}
	return storeForSession(home, child)
}

// A child is written before its parent is marked, so it must clear the whole
// load path — serialization, the schema parser, and the record-stream rules —
// before any file exists, not just the provenance rules Marshal repeats.
func validateLoadable(session *Session) error {
	data, err := Marshal(session)
	if err != nil {
		return err
	}
	parsed, err := Unmarshal(data)
	if err != nil {
		return err
	}
	return ValidateRecordStream(parsed.Records)
}

func newSession(canonicalFolder string, startedAt time.Time, initialRecords []Record, title string, forkedFrom *ForkOrigin) *Session {
	updatedAt := startedAt
	if initialRecords != nil {
		updatedAt = now()
	}
	return &Session{
		Metadata: Metadata{
			ID:            ids.NewV7(),
			Folder:        canonicalFolder,
			StartedAt:     startedAt,
			UpdatedAt:     updatedAt,
			SchemaVersion: CurrentSchemaVersion,
			Title:         title,
			TitleSource:   generatedTitleSource(title),
			ForkedFrom:    forkedFrom,
		},
		Records: initialRecords,
	}
}

func generatedTitleSource(title string) string {
	if title == "" {
		return ""
	}
	return TitleSourceGenerated
}

func storeForSession(home string, session *Session) (*Store, error) {
	subdirPath, err := EnsureFolderDir(home, session.Metadata.Folder)
	if err != nil {
		return nil, err
	}

	// UUIDv7's monotonic time prefix gives chronological lexicographic order on the
	// filename for free, useful for --resume listing later.
	path := filepath.Join(subdirPath, session.Metadata.ID+".json")
	return New(path, session), nil
}
