Goal

Retire the remaining packet-fixture/tooling C surface and leave byedpi with Rust-owned packet verification and tooling.

Result

- Landed.
- `make test-packets` is Rust-owned via `crates/ciadpi-packets/tests/packet_regression.rs` and `packet_exercise.rs`.
- `make fuzz-packets` is Rust-owned via `crates/ciadpi-packets/tests/packet_fuzz_smoke.rs`.
- `crates/ciadpi-packets/tests/oracle_diff.rs` continues to own the committed packet byte-oracle fixtures for the same mutation primitives.
- The residual packet C helper files have been retired:
  - `packets.c`
  - `packets.h`
  - `tests/fuzz_packets.c`
  - `tests/packets_exercise.c`
  - `tests/packets_exercise.h`
  - `tests/test_packets.c`

Verification

- `cargo test --workspace`
- `cargo test -p ciadpi-packets`
- `make test-packets`
- `make fuzz-packets`
- `make test`
- `make cutover-gates`
- `make transition-safety-gates`

Backlog effect

- Phase 9 is complete and no longer appears as an unfinished row in `tools/ralph-loop/tasks/byedpi-rust-migration.tsv`.
- The master `remaining-full-migration` record now serves as an archive/completion check unless a new follow-up row is added later.
