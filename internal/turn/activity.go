package turn

import "codemeld.dev/codemeld/internal/toolactivity"

func ToolActivityLines(calls []AssembledToolCall) []string {
	lines := make([]string, len(calls))
	for i := range calls {
		lines[i] = formatToolActivity(calls[i])
	}
	return lines
}

func formatToolActivity(call AssembledToolCall) string {
	return toolactivity.Format(call.Name, call.Arguments)
}
