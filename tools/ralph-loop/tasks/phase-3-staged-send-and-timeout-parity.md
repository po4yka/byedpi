Status

Completed across `6ebce53` (`Port Rust timeout runtime parity`) and `5e30192` (`Port Rust staged send parity`).
Retained as historical Ralph task context; no longer part of the active manifest.

Goal

Match the remaining C send staging and timeout behavior in Rust so desync execution and long-lived sessions behave the same under partial writes, retries, and timeout-driven triggers.

Primary gaps to close

- Port the remaining `--wait-send` behavior that coordinates staged fake, split, or urgent writes with socket readiness.
- Port `timeout_count_limit` and `timeout_bytes_limit` semantics from the C session loop.
- Review whether any retransmit-sensitive desync flows in Rust still diverge from C because the send loop is too simplified, then cover the fixed behavior with tests.
- Keep the routed Linux `fake`, `md5sig`, and `drop-sack` suite green after the runtime changes.

Expected files

- `extend.c`
- `desync.c`
- `proxy.c`
- `crates/ciadpi-bin/src/runtime.rs`
- `crates/ciadpi-bin/src/platform/linux.rs`
- `crates/ciadpi-desync/src/lib.rs`
- `tests/test_desync_runtime.py`
- `tests/test_linux_routed_runtime.py`
- `tests/test_rust_runtime_subset.py`

Constraints

- Do not weaken routed Linux assertions to hide behavioral drift.
- Keep `ciadpi-desync` pure; OS waiting and socket interaction stay in `ciadpi-bin`.

Acceptance criteria

- Rust desync execution follows the same staged send and timeout-driven decision points as C.
- Existing routed Linux tests still pass, and any newly found edge case gets a permanent regression test.

Verification

- `cargo test --workspace`
- `make test-rust-desync-runtime`
- `make test-rust-linux-routed-runtime`
- `make test-rust-runtime`
- `make test`
