Goal

Replace the remaining ad hoc runtime model in Rust with behavior that matches the C connection lifecycle and limit handling more closely, especially around `max_open` and connection churn.

Primary gaps to close

- Port `max_open` and related connection admission or lifecycle rules from the C runtime.
- Reduce the current thread-per-client behavior where it causes observable divergence from the C binary or blocks parity work.
- Keep the Rust runtime architecture compatible with the stated `mio`/`socket2` migration direction.
- Extend churn and resource-limit tests so regressions are visible.

Expected files

- `proxy.c`
- `conev.c`
- `mpool.c`
- `crates/ciadpi-bin/src/runtime.rs`
- `crates/ciadpi-bin/src/platform/linux.rs`
- `tests/test_proxy_integration.py`
- `tests/test_rust_runtime_subset.py`
- `tests/coverage_map.md`

Constraints

- Scope the refactor to behavior needed for parity; avoid rewriting unrelated runtime pieces.
- Preserve working SOCKS, HTTP CONNECT, UDP relay, and desync coverage.

Acceptance criteria

- Rust enforces the same or intentionally equivalent connection-limit behavior as C.
- Connection churn tests cover the ported behavior and stay green.

Verification

- `cargo test --workspace`
- `make test-rust-runtime`
- `make test-integration`
- `make test`
