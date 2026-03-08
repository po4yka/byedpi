Goal

After Linux parity is proven, switch the Linux-facing default binary from C to Rust while retaining the C implementation as hidden oracle infrastructure for one release cycle.

Primary gaps to close

- Promote `ciadpi-rs` to the default Linux `ciadpi` artifact.
- Keep the C binary buildable as an oracle helper for tests and diffing during the transition window.
- Tighten CI and release checks so Linux cutover requires green parity, routed desync, and benchmark gates.
- Update docs and build wiring without changing user-visible behavior beyond the implementation language.

Expected files

- `Makefile`
- `Cargo.toml`
- `.github/workflows/ci.yml`
- `README.md`
- `tests/coverage_map.md`

Constraints

- Do not do this task until the prior Linux parity tasks are green.
- Keep rollback simple: if parity is not proven, stop and report the blocker instead of forcing the rename.

Acceptance criteria

- Linux users build and run the Rust binary under the `ciadpi` name.
- C remains available to the test harness as an oracle-only binary path.
- CI documents and enforces the cutover rules.

Verification

- `cargo test --workspace`
- `make test`
- Any renamed binary or packaging checks added by the task
