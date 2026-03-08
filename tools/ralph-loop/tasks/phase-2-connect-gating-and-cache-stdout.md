Status

Completed in `b6dd43d` (`Complete Rust runtime migration slice`).
Retained as historical Ralph task context; no longer part of the active manifest.

Goal

Port the remaining upstream-connect gating behavior from C into Rust, including delayed connect decisions and stdout cache dumping.

Primary gaps to close

- Implement `delay_conn` behavior so Rust defers the upstream connect until it has enough request bytes for host or protocol-based policy decisions.
- Match the C request buffering rules for SOCKS and HTTP CONNECT paths while delayed connect is active.
- Implement `--cache-file -` behavior so the Rust binary can dump the cache to stdout in the same format as C.
- Add regression coverage for buffering boundaries, invalid early data, and cache stdout round-trips.

Expected files

- `extend.c`
- `proxy.c`
- `crates/ciadpi-bin/src/runtime.rs`
- `crates/ciadpi-bin/src/runtime_policy.rs`
- `crates/ciadpi-config/src/lib.rs`
- `tests/test_auto_runtime.py`
- `tests/test_contract.py`
- `tests/test_rust_runtime_subset.py`

Constraints

- Preserve the current cache file format and stdout text exactly where practical.
- Keep the connect-gating logic explicit and testable instead of burying it inside ad hoc socket loops.

Acceptance criteria

- Rust only opens the upstream socket once the same request information is available as in C.
- `--cache-file -` matches the C output for identical runtime state.
- Contract and runtime tests cover both delayed and immediate connect paths.

Verification

- `cargo test --workspace`
- `make test-rust-runtime`
- `make test-rust-auto-runtime`
- `make test`
