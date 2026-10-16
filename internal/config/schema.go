// Validates settings.yaml against the embedded JSON Schema, reporting the dotted offending key.
package config

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"codemeld.dev/codemeld/schemas"
)

const schemaURL = "https://codemeld.dev/schemas/settings.schema.json"

var (
	compiledSchema *jsonschema.Schema
	compileOnce    sync.Once
	compileErr     error
)

func settingsSchema() (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemas.SettingsSchema))
		if err != nil {
			compileErr = fmt.Errorf("parse embedded settings schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		if err := c.AddResource(schemaURL, doc); err != nil {
			compileErr = fmt.Errorf("register embedded settings schema: %w", err)
			return
		}
		compiledSchema, compileErr = c.Compile(schemaURL)
	})
	return compiledSchema, compileErr
}

// Validate checks settings.yaml bytes against the embedded JSON Schema, using
// filePath only in error messages. Cross-reference checks (model.active /
// model.last_used) are intentionally not performed here.
func Validate(yamlBytes []byte, filePath string) error {
	sch, err := settingsSchema()
	if err != nil {
		return err
	}

	jsonBytes, err := yaml.YAMLToJSON(yamlBytes)
	if err != nil {
		return fmt.Errorf("%s: parse YAML: %w", filePath, err)
	}

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("%s: decode settings: %w", filePath, err)
	}

	if err := sch.Validate(inst); err != nil {
		var verr *jsonschema.ValidationError
		if as, ok := err.(*jsonschema.ValidationError); ok {
			verr = as
		}
		if verr == nil {
			return fmt.Errorf("%s: %w", filePath, err)
		}
		keys := offendingKeys(verr)
		return fmt.Errorf("%s: schema validation failed at %s: %w", filePath, strings.Join(keys, ", "), verr)
	}
	return nil
}

// offendingKeys walks the validation-error tree and returns the dotted keys of the most specific (leaf) failures, with array indices as path segments.
func offendingKeys(verr *jsonschema.ValidationError) []string {
	seen := map[string]struct{}{}
	var collect func(*jsonschema.ValidationError)
	collect = func(v *jsonschema.ValidationError) {
		if len(v.Causes) == 0 {
			seen[dottedKey(v.InstanceLocation)] = struct{}{}
			return
		}
		for _, c := range v.Causes {
			collect(c)
		}
	}
	collect(verr)

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func dottedKey(loc []string) string {
	if len(loc) == 0 {
		return "(root)"
	}
	return strings.Join(loc, ".")
}
