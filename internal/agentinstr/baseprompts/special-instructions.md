<!-- Per-model special-instruction blocks. Each `## <slug>` H2 heading starts a
named block; the heading line names the block (its slug) and everything until the next
`## ` heading or EOF is that block's instruction text. A block is applied only to the
models listed for it in modelSpecialInstructions (special.go), so it rides only in those
models' prompt-cached prefix. Keep each block short. Text before the first heading (this
comment) belongs to no block and is never emitted. -->

## latex-math

When you write mathematics in a response to the user, use plain text with Unicode
symbols, not LaTeX. Use characters such as ×, ÷, √, ≈, ≠, ≤, ≥, ±, π, ∑, and
superscripts/subscripts directly.
Do not use LaTeX math delimiters — `\(`, `\)`, `\[`, `\]`, or `$…$` — and do not use
LaTeX commands such as `\times`, `\frac`, `\sqrt`, or `\cdot`. For example, write
"5 × 2 = 10" and "√2 ≈ 1.41", not `\(5 \times 2 = 10\)` or `\[\sqrt{2} \approx 1.41\]`.
In a terminal those delimiters and commands render as literal backslash sequences, so
plain text with Unicode reads correctly. This rule applies to your terminal-facing
responses only; it does not govern how mathematics is written in project files, which
keep the project's own formats and conventions.
