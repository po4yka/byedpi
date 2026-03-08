Goal

Port the remaining adaptive runtime policy behavior from the C implementation into Rust so `ciadpi-rs` matches the Linux oracle for cache promotion, priority ordering, and auto-trigger policy decisions.

Primary gaps to close

- Port `AUTO_NOPOST` and `AUTO_SORT` semantics completely.
- Port the adaptive priority fields used by the C runtime: `pri`, `fail_count`, and any detect-mask/cache-promotion bookkeeping still missing in Rust.
- Match the C rules for when fallback groups are promoted into cache and when cached routes are reused or downgraded.
- Keep the cache file format unchanged.

Expected files

- `extend.c`
- `crates/ciadpi-bin/src/runtime_policy.rs`
- `crates/ciadpi-bin/src/runtime.rs`
- `crates/ciadpi-config/src/lib.rs`
- `tests/test_auto_runtime.py`
- `tests/test_contract.py`
- `tests/coverage_map.md`

Constraints

- Keep the current C runtime as the oracle. Do not change the C behavior unless a bug in the oracle is proven and covered first.
- Keep the Rust policy logic deterministic and testable outside the socket layer when possible.
- Do not rename `ciadpi-rs`.

Acceptance criteria

- Rust and C behave the same for grouped `--auto` modes, cache promotion, cache fallback reuse, and failure-driven priority changes.
- New or expanded tests fail before the implementation and pass after it.
- Coverage map reflects the new parity claims.

Verification

- `cargo test --workspace`
- `make test-rust-auto-runtime`
- `make test-rust-binary-parity`
- `make test`
