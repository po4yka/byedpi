Goal

Archive the completed byedpi packet-fixture/tooling migration and define the completion signal for future Ralph relaunches.

Current status

- The runtime, install, CI, and explicit Linux runtime gates are Rust-owned.
- Packet verification and tooling are Rust-owned:
  - `make test-packets` runs `crates/ciadpi-packets/tests/packet_regression.rs` and `packet_exercise.rs`
  - `make fuzz-packets` runs `crates/ciadpi-packets/tests/packet_fuzz_smoke.rs`
  - `crates/ciadpi-packets/tests/oracle_diff.rs` retains the committed packet fixture byte-oracle coverage
- The residual packet C helper surface (`packets.c`, `packets.h`, `tests/fuzz_packets.c`, `tests/packets_exercise.c`, `tests/packets_exercise.h`, and the already-retired `tests/test_packets.c`) has been removed.
- `tools/ralph-loop/tasks/byedpi-rust-migration.tsv` no longer contains unfinished packet/tooling migration phase rows.

Required operating model

- Use `tools/ralph-loop/tasks/byedpi-rust-migration.tsv` as the active backlog source of truth.
- If the manifest contains no unfinished packet/tooling migration phases, treat the migration as complete and stop cleanly.
- Only reopen this archive if a new backlog row is added for a concrete follow-up.

Acceptance criteria

- The active manifest contains no unfinished packet-fixture/tooling migration phases.
- Supported verification no longer depends on compiling or running the retired C packet toolchain unless a new explicit exception is documented.
- Coverage docs reflect the post-C packet verification story.

Verification

- `cargo test --workspace`
- `cargo test -p ciadpi-packets`
- `make test-packets`
- `make fuzz-packets`
- `make test`
- `make cutover-gates`
- `make transition-safety-gates`

Loop stop rule

- Print `LOOP_COMPLETE` once the manifest remains empty of unfinished packet/tooling migration phases and the documented verification has passed for the completion slice.
