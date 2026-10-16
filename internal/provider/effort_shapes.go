package provider

import (
	"encoding/json"
	"strings"
)

type effortShape struct {
	optionsPath  []string
	optionFields []string
	defaultPath  []string
	gatePath     []string
}

var effortShapes = []effortShape{
	{
		optionsPath: []string{"model_spec", "capabilities", "reasoningEffortOptions"},
		defaultPath: []string{"model_spec", "capabilities", "defaultReasoningEffort"},
		gatePath:    []string{"model_spec", "capabilities", "supportsReasoningEffort"},
	},
	{
		optionsPath: []string{"reasoning", "supported_efforts"},
		defaultPath: []string{"reasoning", "default_effort"},
	},
	{
		optionsPath: []string{"supported_reasoning_levels"},
		// "level" is the spelling cache entries written before the "effort" key still carry.
		optionFields: []string{"effort", "level"},
		defaultPath:  []string{"default_reasoning_level"},
	},
}

type effortNode interface {
	child(key string) (effortNode, bool)
	list() ([]effortNode, bool)
	text() (string, bool)
	flag() (bool, bool)
}

type rawNode struct {
	raw    json.RawMessage
	fields map[string]json.RawMessage
}

func (n rawNode) child(key string) (effortNode, bool) {
	fields := n.fields
	if fields == nil {
		if err := json.Unmarshal(n.raw, &fields); err != nil {
			return nil, false
		}
	}
	v, ok := fields[key]
	if !ok {
		return nil, false
	}
	return rawNode{raw: v}, true
}

func (n rawNode) list() ([]effortNode, bool) {
	var items []json.RawMessage
	if err := json.Unmarshal(n.raw, &items); err != nil {
		return nil, false
	}
	out := make([]effortNode, len(items))
	for i, item := range items {
		out[i] = rawNode{raw: item}
	}
	return out, true
}

func (n rawNode) text() (string, bool) {
	var s string
	if err := json.Unmarshal(n.raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func (n rawNode) flag() (bool, bool) {
	var b bool
	if err := json.Unmarshal(n.raw, &b); err != nil {
		return false, false
	}
	return b, true
}

type anyNode struct {
	value any
}

func (n anyNode) child(key string) (effortNode, bool) {
	obj, ok := n.value.(map[string]any)
	if !ok {
		return nil, false
	}
	v, ok := obj[key]
	if !ok {
		return nil, false
	}
	return anyNode{value: v}, true
}

func (n anyNode) list() ([]effortNode, bool) {
	items, ok := n.value.([]any)
	if !ok {
		return nil, false
	}
	out := make([]effortNode, len(items))
	for i, item := range items {
		out[i] = anyNode{value: item}
	}
	return out, true
}

func (n anyNode) text() (string, bool) {
	s, ok := n.value.(string)
	return s, ok
}

func (n anyNode) flag() (bool, bool) {
	b, ok := n.value.(bool)
	return b, ok
}

func effortCapabilitiesFromRawFields(fields map[string]json.RawMessage) map[string]any {
	return effortCapabilities(rawNode{fields: fields})
}

func effortCapabilitiesFromValue(value any) map[string]any {
	return effortCapabilities(anyNode{value: value})
}

func effortCapabilities(root effortNode) map[string]any {
	for _, shape := range effortShapes {
		if caps := shape.extract(root); caps != nil {
			return caps
		}
	}
	return nil
}

func (s effortShape) extract(root effortNode) map[string]any {
	if len(s.gatePath) > 0 {
		gate, ok := walkEffortPath(root, s.gatePath)
		if !ok {
			return nil
		}
		if enabled, ok := gate.flag(); !ok || !enabled {
			return nil
		}
	}
	node, ok := walkEffortPath(root, s.optionsPath)
	if !ok {
		return nil
	}
	items, ok := node.list()
	if !ok {
		return nil
	}
	advertised := make([]string, 0, len(items))
	for _, item := range items {
		if v, ok := s.optionValue(item); ok {
			advertised = append(advertised, v)
		}
	}
	options := sanitizeEffortOptions(advertised)
	if len(options) == 0 {
		return nil
	}
	out := map[string]any{
		configuredSupportsReasoningEffortCapKey: true,
		configuredReasoningEffortOptionsCapKey:  options,
	}
	if def, ok := s.defaultEffort(root); ok {
		out[configuredDefaultReasoningEffortCapKey] = def
	}
	return out
}

func (s effortShape) optionValue(item effortNode) (string, bool) {
	if len(s.optionFields) == 0 {
		return item.text()
	}
	for _, field := range s.optionFields {
		node, ok := item.child(field)
		if !ok {
			continue
		}
		if v, ok := node.text(); ok && validEffortToken(v) {
			return v, true
		}
	}
	return "", false
}

func (s effortShape) defaultEffort(root effortNode) (string, bool) {
	if len(s.defaultPath) == 0 {
		return "", false
	}
	node, ok := walkEffortPath(root, s.defaultPath)
	if !ok {
		return "", false
	}
	v, ok := node.text()
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxEffortOptionLength {
		return "", false
	}
	return v, true
}

func walkEffortPath(node effortNode, path []string) (effortNode, bool) {
	for _, key := range path {
		next, ok := node.child(key)
		if !ok {
			return nil, false
		}
		node = next
	}
	return node, true
}
