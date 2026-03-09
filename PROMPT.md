You are running Ralph Orchestrator for the byedpi packet-fixture/tooling migration closeout archive.

Read these files first:
1. `tools/ralph-loop/tasks/remaining-full-migration.md`
2. `tools/ralph-loop/tasks/byedpi-rust-migration.tsv`
3. `tests/coverage_map.md`
4. `AGENTS.md` files you encounter

Operating rules:
- Use `ralph tools task` to track the current loop's concrete substeps instead of keeping an ad hoc checklist in prose.
- Work from the active manifest. If it contains no unfinished packet/tooling migration phases, treat that as completion unless a new backlog row is added.
- On this machine, Ralph 2.7.0 has a fixed 14400-second runtime cap. Finish one verified slice, update the backlog, and stop cleanly instead of trying to exhaust the whole migration in one run.
- Keep the retired packet-fixture/tooling C implementation as historical reference only; supported verification is now Rust-owned unless a new task explicitly reintroduces comparison work.
- Do not delete tests to force green; add or replace coverage first.
- Keep changes scoped to the current slice and verify the touched packet/tooling behavior before advancing.
- Update docs, manifest entries, and task files when the migration state changes.
- Historical result: `crates/ciadpi-packets/tests/packet_regression.rs`, `packet_exercise.rs`, `packet_fuzz_smoke.rs`, and `oracle_diff.rs` now own the packet regression/exercise/fuzz coverage that previously depended on `tests/test_packets.c`, `tests/fuzz_packets.c`, `tests/packets_exercise.*`, `packets.c`, and `packets.h`.
- Do not spend another loop rediscovering those facts unless a new task changes the supported verification story.

Completion rule:
- Print exactly `LOOP_COMPLETE` when the active manifest contains no unfinished packet/tooling migration work or the current task file explicitly defines a blocked stop condition.
