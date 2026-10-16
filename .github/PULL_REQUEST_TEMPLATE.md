# Summary

<!-- What changed, and why? -->

## Linked Issue

<!-- Link the issue this closes, if any. -->

## How Was This Tested?

Run the standard Go checks that apply to your change:

- [ ] `go build ./...`
- [ ] `go test ./...`
- [ ] `go test -race ./...` if this touches concurrency, shared state, or event loops
- [ ] `go vet ./...`
- [ ] `gofmt -l .` is clean

<!-- Maintainers may also run golangci-lint or `mise run check` before merging. -->

## AI Assistance

- Was an LLM used to create these changes:
- If an LLM was used, did you have a different model family verify the work (N/A if no LLM used):

## Checklist

- [ ] Tests were added or updated for behavior changes.
- [ ] Documentation was updated where behavior changed.
- [ ] The diff contains no secrets, API keys, local settings, or session dumps.
- [ ] Comments explain why the code exists when the reason is not obvious.
- [ ] I agree that my contribution is licensed under the MIT License.
