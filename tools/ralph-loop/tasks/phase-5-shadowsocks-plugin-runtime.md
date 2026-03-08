Status

Completed in `b6dd43d` (`Complete Rust runtime migration slice`).
Retained as historical Ralph task context; no longer part of the active manifest.

Goal

Finish Shadowsocks plugin runtime mode in the Rust binary so env-based startup is not just parsed but works end to end with parity coverage.

Primary gaps to close

- Match the C runtime behavior when `SS_LOCAL_PORT` and `SS_PLUGIN_OPTIONS` are used to start the proxy.
- Ensure protect-path auto-detection and any plugin-specific defaults behave the same in Rust as in C.
- Add or extend integration coverage that boots the Rust binary from environment variables instead of explicit CLI flags.

Expected files

- `main.c`
- `proxy.c`
- `crates/ciadpi-config/src/lib.rs`
- `crates/ciadpi-bin/src/main.rs`
- `crates/ciadpi-bin/src/runtime.rs`
- `tests/test_contract.py`
- `tests/test_rust_binary_parity.py`
- `tests/test_rust_runtime_subset.py`

Constraints

- Keep the external contract unchanged for existing Shadowsocks users.
- Use the current C environment bootstrap as the source of truth.

Acceptance criteria

- Rust can be launched through the plugin environment path and behaves the same as C for equivalent inputs.
- The parity suite covers env startup success and failure cases.

Verification

- `cargo test --workspace`
- `make test-rust-binary-parity`
- `make test-rust-runtime`
- `make test`
