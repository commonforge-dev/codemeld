package bootstrap

import (
	"context"
	"fmt"

	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
)

func (d *productionToolDispatcher) setAskUser(ask func(context.Context, tui.QuestionRequest) (tui.QuestionResult, error)) {
	d.askUser = ask
}

func (d *productionToolDispatcher) dispatchAskUser(ctx context.Context, arguments string) (turn.ToolResult, error) {
	req, err := decodeAskUserRequest(arguments)
	if err != nil {
		return inbandToolError(err), nil
	}
	res, err := d.askUser(ctx, req)
	if err != nil {
		// The cancellation identity is the context's, not the form's: a form failure racing a
		// cancelled turn would otherwise be recorded as a failed turn rather than an
		// interrupted one.
		if cerr := ctx.Err(); cerr != nil {
			return turn.ToolResult{}, cerr
		}
		return inbandToolError(fmt.Errorf("%s could not be shown: %w", provider.AskUserToolName, err)), nil
	}
	encoded, err := res.Encode()
	if err != nil {
		return turn.ToolResult{}, err
	}
	return turn.ToolResult{Content: encoded}, nil
}

// The provider package owns the only strict ask_user checker, so dispatch and /resume replay
// cannot drift apart; this maps an accepted request onto the form's own request type.
func decodeAskUserRequest(arguments string) (tui.QuestionRequest, error) {
	decoded, err := provider.DecodeAskUserRequest(arguments)
	if err != nil {
		return tui.QuestionRequest{}, err
	}
	req := tui.QuestionRequest{Context: decoded.Context, Questions: make([]tui.QuestionSpec, 0, len(decoded.Questions))}
	for _, q := range decoded.Questions {
		req.Questions = append(req.Questions, tui.QuestionSpec(q))
	}
	return req, nil
}
