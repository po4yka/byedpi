Status

Completed in `b6dd43d` (`Complete Rust runtime migration slice`).
Retained as historical Ralph task context; no longer part of the active manifest.

Goal

Implement the remaining Rust runtime process-management and socket bootstrap features that are already exposed by the CLI: daemon mode, pidfile handling, and TCP Fast Open.

Primary gaps to close

- Parse and honor `-w` / `--pidfile` in Rust.
- Implement `-D` / `--daemon` with behavior that matches the C binary closely enough for Linux parity tests.
- Implement `-F` / `--tfo` for outbound TCP sockets in the Rust runtime.
- Add black-box and contract coverage for success and failure cases, including pidfile overwrite or cleanup behavior if the C binary defines it.

Expected files

- `main.c`
- `extend.c`
- `crates/ciadpi-config/src/lib.rs`
- `crates/ciadpi-bin/src/main.rs`
- `crates/ciadpi-bin/src/runtime.rs`
- `crates/ciadpi-bin/src/platform/linux.rs`
- `tests/test_contract.py`
- `tests/test_rust_binary_parity.py`
- `tests/coverage_map.md`

Constraints

- Preserve the current CLI text and exit behavior.
- Keep platform-specific process and socket code inside `ciadpi-bin`.
- Avoid broad runtime refactors in this task.

Acceptance criteria

- `ciadpi-rs` accepts and executes `--daemon`, `--pidfile`, and `--tfo` with parity-focused tests.
- Non-Linux behavior is explicitly stubbed or rejected in a controlled way if that matches the current migration policy.

Verification

- `cargo test --workspace`
- `make test-rust-binary-parity`
- `make test`
