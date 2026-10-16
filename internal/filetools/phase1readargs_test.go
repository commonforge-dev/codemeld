package filetools

import (
	"strings"
	"testing"
)

func TestValidatePhase1ReadArgs_ExactNames(t *testing.T) {
	if len(phase1ReadSchemas) != 6 {
		t.Fatalf("phase1ReadSchemas has %d entries, want exactly the six Phase-1 read tools", len(phase1ReadSchemas))
	}

	valid := map[string]map[string]any{
		ReadToolName:      {"path": "a.go"},
		GlobToolName:      {"pattern": "**/*.go"},
		GrepToolName:      {"pattern": "func "},
		ListToolName:      {"path": "internal"},
		TreeToolName:      {"path": "internal"},
		FileCountToolName: {"path": "internal"},
	}
	for name, args := range valid {
		t.Run("accepts_"+name, func(t *testing.T) {
			if err := ValidatePhase1ReadArgs(name, args); err != nil {
				t.Fatalf("ValidatePhase1ReadArgs(%q) = %v, want nil", name, err)
			}
		})
	}

	for _, name := range []string{
		"", "Read", "read ", "reads", "globbing", "grep2", "List", "trees", "tree ", "file count",
		"filecount", "file_counts", "read_image", "edit", "bash",
	} {
		t.Run("rejects_"+name, func(t *testing.T) {
			err := ValidatePhase1ReadArgs(name, map[string]any{"path": "a.go", "pattern": "x"})
			if err == nil {
				t.Fatalf("ValidatePhase1ReadArgs(%q) = nil, want a rejection", name)
			}
			if !strings.Contains(err.Error(), "no Phase-1 read argument schema") {
				t.Fatalf("error = %q, want it to name the missing schema", err)
			}
		})
	}
}

func TestValidatePhase1ReadArgs_Accepts(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args map[string]any
	}{
		{"read_path_only", ReadToolName, map[string]any{"path": "a.go"}},
		{"read_offset_limit_float", ReadToolName, map[string]any{"path": "a.go", "offset": float64(1), "limit": float64(ReadMaxLimit)}},
		{"read_offset_limit_int", ReadToolName, map[string]any{"path": "a.go", "offset": 5, "limit": 1}},
		{"glob_pattern_only", GlobToolName, map[string]any{"pattern": "*.go"}},
		{"glob_all_args", GlobToolName, map[string]any{
			"pattern": "**/*.{go,md}", "path": "internal", "limit": GlobMaxLimit,
			"include_hidden": true, "include_ignored": false,
		}},
		{"glob_pattern_with_spaces", GlobToolName, map[string]any{"pattern": " a b.go "}},
		{"grep_pattern_only", GrepToolName, map[string]any{"pattern": "func "}},
		{"grep_all_args", GrepToolName, map[string]any{
			"pattern": "^func", "path": "internal", "include": "*.go", "case_insensitive": true,
			"context": 0, "limit": GrepMaxLimit, "files_only": true, "include_hidden": true, "include_ignored": true,
		}},
		{"list_no_args", ListToolName, map[string]any{}},
		{"list_all_args", ListToolName, map[string]any{
			"path": "internal", "limit": ListMaxLimit, "include_hidden": true, "include_ignored": false,
		}},
		{"tree_no_args", TreeToolName, map[string]any{}},
		{"tree_all_args_ai", TreeToolName, map[string]any{
			"path": "internal", "depth": 0, "limit": TreeMaxLimit, "format": treeFormatAI,
			"include_hidden": false, "include_ignored": true,
		}},
		{"tree_human_format", TreeToolName, map[string]any{"format": treeFormatHuman, "depth": float64(3)}},
		{"file_count_no_args", FileCountToolName, map[string]any{}},
		{"file_count_all_args", FileCountToolName, map[string]any{
			"path": "internal", "kinds": []any{"file", "dir", "symlink", "other"},
			"include_globs": []any{"g_*/**", "**/*.png"}, "exclude_globs": []any{"th_*/**"},
			"group_by": groupByStem, "include_dotfiles": true, "include_ignored": true, "limit": FileCountMaxLimit,
		}},
		{"file_count_empty_glob_lists", FileCountToolName, map[string]any{
			"include_globs": []any{}, "exclude_globs": []any{},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePhase1ReadArgs(tc.tool, tc.args); err != nil {
				t.Fatalf("ValidatePhase1ReadArgs(%q, %v) = %v, want nil", tc.tool, tc.args, err)
			}
		})
	}
}

func TestValidatePhase1ReadArgs_Rejects(t *testing.T) {
	cases := []struct {
		name      string
		tool      string
		args      map[string]any
		wantInMsg string
	}{
		{"read_missing_path", ReadToolName, map[string]any{}, `missing required argument "path"`},
		{"read_non_string_path", ReadToolName, map[string]any{"path": 7}, `argument "path" must be a string`},
		{"read_empty_path", ReadToolName, map[string]any{"path": ""}, "read target rejected: path must be non-empty"},
		{"read_whitespace_path", ReadToolName, map[string]any{"path": "   "}, "read target rejected: path must be non-empty"},
		{"read_unknown_key", ReadToolName, map[string]any{"path": "a.go", "depth": 1}, `unexpected argument "depth"; only path, offset, and limit are accepted`},
		{"read_fractional_offset", ReadToolName, map[string]any{"path": "a.go", "offset": 1.5}, `argument "offset" must be an integer`},
		{"read_non_numeric_limit", ReadToolName, map[string]any{"path": "a.go", "limit": "10"}, `argument "limit" must be an integer`},
		{"read_offset_zero", ReadToolName, map[string]any{"path": "a.go", "offset": 0}, "read target rejected: offset must be >= 1"},
		{"read_limit_zero", ReadToolName, map[string]any{"path": "a.go", "limit": 0}, "read target rejected: limit must be >= 1"},
		{"read_limit_over_max", ReadToolName, map[string]any{"path": "a.go", "limit": ReadMaxLimit + 1}, "read target rejected: limit 10001 exceeds the maximum of 10000"},

		{"glob_missing_pattern", GlobToolName, map[string]any{"path": "internal"}, `missing required argument "pattern"`},
		{"glob_non_string_pattern", GlobToolName, map[string]any{"pattern": 1}, `argument "pattern" must be a string`},
		{"glob_non_string_path", GlobToolName, map[string]any{"pattern": "*.go", "path": 7}, `argument "path" must be a string`},
		{"glob_empty_pattern", GlobToolName, map[string]any{"pattern": ""}, "glob target rejected: pattern must be non-empty"},
		{"glob_malformed_pattern", GlobToolName, map[string]any{"pattern": "[a-"}, `glob target rejected: malformed glob pattern "[a-"`},
		{"glob_unknown_key", GlobToolName, map[string]any{"pattern": "*.go", "offset": 1}, `unexpected argument "offset"; only pattern, path, limit, include_ignored, and include_hidden are accepted`},
		{"glob_non_numeric_limit", GlobToolName, map[string]any{"pattern": "*.go", "limit": true}, `argument "limit" must be an integer`},
		{"glob_limit_zero", GlobToolName, map[string]any{"pattern": "*.go", "limit": 0}, "glob target rejected: limit must be >= 1"},
		{"glob_limit_over_max", GlobToolName, map[string]any{"pattern": "*.go", "limit": GlobMaxLimit + 1}, "glob target rejected: limit 5001 exceeds the maximum of 5000"},
		{"glob_non_bool_include_hidden", GlobToolName, map[string]any{"pattern": "*.go", "include_hidden": "yes"}, `argument "include_hidden" must be a boolean`},
		{"glob_non_bool_include_ignored", GlobToolName, map[string]any{"pattern": "*.go", "include_ignored": 1}, `argument "include_ignored" must be a boolean`},

		{"grep_missing_pattern", GrepToolName, map[string]any{"path": "internal"}, `missing required argument "pattern"`},
		{"grep_non_string_pattern", GrepToolName, map[string]any{"pattern": 1}, `argument "pattern" must be a string`},
		{"grep_non_string_path", GrepToolName, map[string]any{"pattern": "x", "path": 7}, `argument "path" must be a string`},
		{"grep_empty_pattern", GrepToolName, map[string]any{"pattern": ""}, "grep target rejected: pattern must be non-empty"},
		{"grep_uncompilable_pattern", GrepToolName, map[string]any{"pattern": "func("}, "grep target rejected: cannot compile pattern:"},
		{"grep_backreference_pattern", GrepToolName, map[string]any{"pattern": `(a)\1`}, "grep target rejected: cannot compile pattern:"},
		{"grep_uncompilable_pattern_case_insensitive", GrepToolName, map[string]any{"pattern": "func(", "case_insensitive": true}, "grep target rejected: cannot compile pattern:"},
		{"grep_unknown_key", GrepToolName, map[string]any{"pattern": "x", "offset": 1}, `unexpected argument "offset"; only pattern, path, include, case_insensitive, context, limit, files_only, include_ignored, and include_hidden are accepted`},
		{"grep_non_string_include", GrepToolName, map[string]any{"pattern": "x", "include": 1}, `argument "include" must be a string`},
		{"grep_malformed_include", GrepToolName, map[string]any{"pattern": "x", "include": "[a-"}, `grep target rejected: malformed include glob "[a-"`},
		{"grep_non_numeric_context", GrepToolName, map[string]any{"pattern": "x", "context": 1.5}, `argument "context" must be an integer`},
		{"grep_negative_context", GrepToolName, map[string]any{"pattern": "x", "context": -1}, "grep target rejected: context must be >= 0"},
		{"grep_limit_zero", GrepToolName, map[string]any{"pattern": "x", "limit": 0}, "grep target rejected: limit must be >= 1"},
		{"grep_limit_over_max", GrepToolName, map[string]any{"pattern": "x", "limit": GrepMaxLimit + 1}, "grep target rejected: limit 5001 exceeds the maximum of 5000"},
		{"grep_non_bool_case_insensitive", GrepToolName, map[string]any{"pattern": "x", "case_insensitive": "yes"}, `argument "case_insensitive" must be a boolean`},
		{"grep_non_bool_files_only", GrepToolName, map[string]any{"pattern": "x", "files_only": 1}, `argument "files_only" must be a boolean`},
		{"grep_non_bool_include_hidden", GrepToolName, map[string]any{"pattern": "x", "include_hidden": "no"}, `argument "include_hidden" must be a boolean`},
		{"grep_non_bool_include_ignored", GrepToolName, map[string]any{"pattern": "x", "include_ignored": "no"}, `argument "include_ignored" must be a boolean`},

		{"list_unknown_key", ListToolName, map[string]any{"depth": 1}, `unexpected argument "depth"; only path, limit, include_ignored, and include_hidden are accepted`},
		{"list_format_rejected", ListToolName, map[string]any{"format": "ai"}, `unexpected argument "format"`},
		{"list_non_string_path", ListToolName, map[string]any{"path": 5}, `argument "path" must be a string`},
		{"list_non_numeric_limit", ListToolName, map[string]any{"limit": "ten"}, `argument "limit" must be an integer`},
		{"list_fractional_limit", ListToolName, map[string]any{"limit": 1.5}, `argument "limit" must be an integer`},
		{"list_limit_zero", ListToolName, map[string]any{"limit": 0}, "list target rejected: limit must be >= 1"},
		{"list_limit_over_max", ListToolName, map[string]any{"limit": ListMaxLimit + 1}, "list target rejected: limit"},
		{"list_non_bool_include_hidden", ListToolName, map[string]any{"include_hidden": "yes"}, `argument "include_hidden" must be a boolean`},
		{"list_non_bool_include_ignored", ListToolName, map[string]any{"include_ignored": 1}, `argument "include_ignored" must be a boolean`},

		{"tree_unknown_key", TreeToolName, map[string]any{"kinds": []any{"file"}}, `unexpected argument "kinds"; only path, depth, limit, format, include_ignored, and include_hidden are accepted`},
		{"tree_non_string_path", TreeToolName, map[string]any{"path": 5}, `argument "path" must be a string`},
		{"tree_non_numeric_depth", TreeToolName, map[string]any{"depth": "deep"}, `argument "depth" must be an integer`},
		{"tree_fractional_depth", TreeToolName, map[string]any{"depth": 2.5}, `argument "depth" must be an integer`},
		{"tree_negative_depth", TreeToolName, map[string]any{"depth": -1}, "tree target rejected: depth must be >= 0"},
		{"tree_limit_zero", TreeToolName, map[string]any{"limit": 0}, "tree target rejected: limit must be >= 1"},
		{"tree_limit_over_max", TreeToolName, map[string]any{"limit": TreeMaxLimit + 1}, "tree target rejected: limit"},
		{"tree_non_numeric_limit", TreeToolName, map[string]any{"limit": "ten"}, `argument "limit" must be an integer`},
		{"tree_non_string_format", TreeToolName, map[string]any{"format": 7}, `argument "format" must be a string`},
		{"tree_unrecognized_format", TreeToolName, map[string]any{"format": "fancy"}, `argument "format" must be "ai" or "human"`},
		{"tree_non_bool_include_hidden", TreeToolName, map[string]any{"include_hidden": "yes"}, `argument "include_hidden" must be a boolean`},
		{"tree_non_bool_include_ignored", TreeToolName, map[string]any{"include_ignored": 1}, `argument "include_ignored" must be a boolean`},

		{"file_count_unknown_key", FileCountToolName, map[string]any{"depth": 1}, `unexpected argument "depth"; only path, kinds, include_globs, exclude_globs, group_by, include_dotfiles, include_ignored, and limit are accepted`},
		{"file_count_include_hidden_rejected", FileCountToolName, map[string]any{"include_hidden": true}, `unexpected argument "include_hidden"`},
		{"file_count_non_string_path", FileCountToolName, map[string]any{"path": 5}, `argument "path" must be a string`},
		{"file_count_limit_zero", FileCountToolName, map[string]any{"limit": 0}, "file_count target rejected: limit must be >= 1"},
		{"file_count_limit_over_max", FileCountToolName, map[string]any{"limit": FileCountMaxLimit + 1}, "file_count target rejected: limit"},
		{"file_count_non_numeric_limit", FileCountToolName, map[string]any{"limit": "ten"}, `argument "limit" must be an integer`},
		{"file_count_fractional_limit", FileCountToolName, map[string]any{"limit": 1.5}, `argument "limit" must be an integer`},
		{"file_count_non_bool_include_dotfiles", FileCountToolName, map[string]any{"include_dotfiles": "yes"}, `argument "include_dotfiles" must be a boolean`},
		{"file_count_non_bool_include_ignored", FileCountToolName, map[string]any{"include_ignored": 1}, `argument "include_ignored" must be a boolean`},
		{"file_count_kinds_non_array", FileCountToolName, map[string]any{"kinds": "file"}, `argument "kinds" must be an array of strings`},
		{"file_count_kinds_empty", FileCountToolName, map[string]any{"kinds": []any{}}, `argument "kinds" must list at least one kind`},
		{"file_count_kinds_non_string_member", FileCountToolName, map[string]any{"kinds": []any{1}}, `argument "kinds"[0] must be a string`},
		{"file_count_kinds_bad_value", FileCountToolName, map[string]any{"kinds": []any{"folder"}}, `must be one of "file", "dir", "symlink", or "other"`},
		{"file_count_non_string_group_by", FileCountToolName, map[string]any{"group_by": 7}, `argument "group_by" must be a string`},
		{"file_count_unrecognized_group_by", FileCountToolName, map[string]any{"group_by": "size"}, `argument "group_by" must be one of "extension", "top_dir", "dir", "depth", or "stem"`},
		{"file_count_include_globs_non_array", FileCountToolName, map[string]any{"include_globs": "*.go"}, `argument "include_globs" must be an array of strings`},
		{"file_count_include_globs_non_string_member", FileCountToolName, map[string]any{"include_globs": []any{1}}, `argument "include_globs"[0] must be a string`},
		{"file_count_include_globs_empty_member", FileCountToolName, map[string]any{"include_globs": []any{""}}, "file_count target rejected: include_globs contains an empty pattern"},
		{"file_count_include_globs_malformed", FileCountToolName, map[string]any{"include_globs": []any{"["}}, `file_count target rejected: malformed glob pattern "[" in include_globs`},
		{"file_count_exclude_globs_non_array", FileCountToolName, map[string]any{"exclude_globs": "*.go"}, `argument "exclude_globs" must be an array of strings`},
		{"file_count_exclude_globs_non_string_member", FileCountToolName, map[string]any{"exclude_globs": []any{1}}, `argument "exclude_globs"[0] must be a string`},
		{"file_count_exclude_globs_empty_member", FileCountToolName, map[string]any{"exclude_globs": []any{""}}, "file_count target rejected: exclude_globs contains an empty pattern"},
		{"file_count_exclude_globs_malformed", FileCountToolName, map[string]any{"exclude_globs": []any{"["}}, `file_count target rejected: malformed glob pattern "[" in exclude_globs`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePhase1ReadArgs(tc.tool, tc.args)
			if err == nil {
				t.Fatalf("ValidatePhase1ReadArgs(%q, %v) = nil, want a rejection", tc.tool, tc.args)
			}
			if !strings.Contains(err.Error(), tc.wantInMsg) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.wantInMsg)
			}
		})
	}
}

func TestValidatePhase1ReadArgs_NoFilesystemAccess(t *testing.T) {
	cases := []struct {
		tool string
		args map[string]any
	}{
		{ReadToolName, map[string]any{"path": "/nonexistent/dir/missing.go"}},
		{GlobToolName, map[string]any{"pattern": "*.go", "path": "/nonexistent/dir"}},
		{GrepToolName, map[string]any{"pattern": "x", "path": "/etc"}},
		{ListToolName, map[string]any{"path": "/nonexistent/dir"}},
		{TreeToolName, map[string]any{"path": "/nonexistent/dir"}},
		{FileCountToolName, map[string]any{"path": "/nonexistent/dir"}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			if err := ValidatePhase1ReadArgs(tc.tool, tc.args); err != nil {
				t.Fatalf("ValidatePhase1ReadArgs(%q) = %v, want nil (validation performs no I/O)", tc.tool, err)
			}
		})
	}
}
