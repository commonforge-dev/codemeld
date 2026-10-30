# Contributing to codemeld

Thanks for helping. These reports help the most.

## Report bugs and errors

Open a GitHub issue with the bug template. Say what you did, what you expected, and what happened
instead.

## Report prompts you think were unnecessary

If codemeld asked permission for a command you think it should have allowed on its own, open a
GitHub issue with the bug template. The template has no special fields for this, so put the
details in "What happened?" and "Steps to reproduce":

- the command text;
- the mode: `plan`, `build`, or `auto-edits`;
- whether you used the TUI or headless `codemeld run`;
- the prompt text codemeld showed.

Remove secrets, tokens, and private paths before you post.

## Report commands that ran without asking

The reverse matters too: a command codemeld ran without asking that you think should have asked.

First check whether it was expected. In Plan and Auto edits, on a Linux host where codemeld's
startup self-test passed, commands run inside a sandbox, and the sandbox, not a prompt, is what
allows them. A command running there without a prompt is normal.

If a command ran without a prompt where one is required, or got past the sandbox or the project
folder limits, treat it as a possible security issue. Report it privately as described in
[`SECURITY.md`](SECURITY.md), not with the public bug template. When unsure whether something is a
security issue, use the private route.

## Suggest features

Open a GitHub issue with the feature request template.

## Sending a code change

See [`contributing/setup.md`](contributing/setup.md) to build and test codemeld.

## License and conduct

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE). Please also follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

**Found a security issue?** Do not open a public issue — follow the private
disclosure path in [`SECURITY.md`](SECURITY.md).
