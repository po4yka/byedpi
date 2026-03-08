# Rust Skills -- Codex Compatibility

These skills were authored for Claude Code. When using them in Codex, apply these mappings:

## Tool Mapping

| Skill Reference | Codex Equivalent |
|----------------|-----------------|
| `LSP(goToDefinition, ...)` | `rg` for symbol definitions, or `rust-analyzer` CLI |
| `LSP(findReferences, ...)` | `rg` for text references, or `rust-analyzer` CLI |
| `LSP(hover, ...)` | Read source + doc comments directly |
| `Read` | Read the file directly |
| `Edit` | Edit/write the file directly |
| `Grep` / `rg` | Use `rg` (ripgrep) in shell |
| `Glob` / `fd` | Use `fd` or `find` in shell |
| `Agent` (subagent) | Execute the steps sequentially (no subagent support) |

## Frontmatter Notes

- `allowed-tools`: Informational only -- indicates which tools the skill was designed around
- `user-invocable`: Claude Code-specific; Codex uses description-based routing instead
- `globs`: Claude Code-specific file triggers; Codex routes by description match

## LSP-Heavy Skills

These skills reference LSP operations extensively. Translate to CLI equivalents:
- `rust-code-navigator`, `rust-call-graph`, `rust-symbol-analyzer`
- `rust-trait-explorer`, `rust-refactor-helper`

For these, use `cargo doc`, `rg`, and direct source reading as alternatives.
