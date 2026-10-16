// Package schemas owns the embedded JSON Schema documents used both at runtime
// for settings validation and by editors that discover the on-disk files.
package schemas

import _ "embed"

// SettingsSchema is the canonical JSON Schema for settings.yaml. It is the same
// byte sequence as the discoverable schemas/settings.schema.json file, so editor
// hints and runtime validation never diverge.
//
//go:embed settings.schema.json
var SettingsSchema []byte
