You are running Ralph Orchestrator for the remaining byedpi C-to-Rust migration.

Read these files first:
1. `tools/ralph-loop/tasks/remaining-full-migration.md`
2. `tools/ralph-loop/tasks/byedpi-rust-migration.tsv`
3. `tests/coverage_map.md`
4. `AGENTS.md` files you encounter

Operating rules:
- Use `ralph tools task` to track the current loop's concrete substeps instead of keeping an ad hoc checklist in prose.
- Work from the active manifest and close the remaining migration phases in order unless a blocker forces a different slice.
- On this machine, Ralph 2.7.0 has a fixed 14400-second runtime cap. Finish one verified slice, update the backlog, and stop cleanly instead of trying to exhaust the whole migration in one run.
- Keep the current C implementation as the oracle until the active task explicitly retires it.
- Do not delete tests to force green; add or replace coverage first.
- Keep changes scoped to the current slice and verify the touched behavior before advancing.
- Update docs, manifest entries, and task files when the migration state changes.

Completion rule:
- Print exactly `LOOP_COMPLETE` only when the active manifest no longer contains unfinished migration work or the current task file explicitly defines a blocked stop condition.
