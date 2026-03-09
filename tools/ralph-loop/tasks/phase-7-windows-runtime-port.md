Goal

Port the deferred Windows runtime and service integration after Linux cutover is stable.

Closeout status

- Phase 7 was completed on 2026-03-09. The active migration manifest now advances to phase 8 (`rust-only-final-cutover`), and this task file remains as the archived closeout record.
- The native Windows validation gap is documented via `.ralph/specs/20260309T030547Z-codex-remaining-full-migration-22a588/phase-7-native-windows-validation.md`.
- The Linux protect-path regression gate was stabilized on 2026-03-09 by hardening `tests/test_linux_runtime_features.py::LinuxProtectPathTests::test_protect_path_receives_outbound_socket_fd` to correlate the protected socket's bound local port with the echo server's observed client port, while still checking the connected peer when the kernel exposes it. After that change, repeated narrow protect-path runs, `make test-linux-runtime-features`, `cargo test --workspace`, `make test-windows-cross-check`, and the full `make test` sweep all passed in this environment.

Phase scope

- Port the Windows socket and service behavior previously handled by `win_service.c` and the Windows branches in the C runtime.
- Preserve the public CLI and service-facing behavior for Windows users.
- Reuse Linux-proven pure Rust crates and keep platform-specific work inside `ciadpi-bin::platform::windows`.
- Add Windows CI or documented manual verification if the environment cannot be provisioned in CI yet.

Current verification surface

- `crates/ciadpi-bin/src/platform/windows.rs` now carries Windows-only parity tests for the service name (`ByeDPI`), running/stopped service status contracts, stop/shutdown/interrogate control handling, saved CLI argument reuse, executable-directory working-directory reset, and service exit-code propagation.
- `make test-windows-cross-check` compiles those Windows-only tests for `x86_64-pc-windows-gnu`, which keeps the Rust Windows service path linkable in CI even though this Linux-hosted workflow cannot execute the resulting binaries natively.
- `.ralph/specs/20260309T030547Z-codex-remaining-full-migration-22a588/phase-7-native-windows-validation.md` now records the native Windows manual validation procedure for the Rust `ByeDPI` service path, including service install/start/stop checks, relative-path argument reuse, and a listening-port assertion.
- `cargo test --workspace` and `make test` remain the Linux regression gates that protect the shared Rust runtime while the Windows-specific layer lands.

Expected files

- `proxy.c`
- `crates/ciadpi-bin/src/platform/`
- `.github/workflows/ci.yml`
- Windows-facing test or verification docs

Constraints

- Do not regress Linux parity while adding Windows code.
- Keep unsafe code minimal and well-contained.

Acceptance criteria

- Windows runtime behavior is implemented in Rust with documented verification.
- Windows verification documents both the cross-target parity coverage that exists today and any remaining native Windows execution gap.
- Linux cutover remains green.

Verification

- `cargo test --workspace`
- `make test-windows-cross-check`
- `make test`
