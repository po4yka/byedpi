Goal

Port the deferred Windows runtime and service integration after Linux cutover is stable.

Primary gaps to close

- Port Windows socket and service behavior now handled by `win_service.c` and the Windows branches in the C runtime.
- Preserve the public CLI and service-facing behavior for Windows users.
- Reuse Linux-proven pure Rust crates and keep platform-specific work inside `ciadpi-bin::platform::windows`.
- Add Windows CI or documented manual verification if the environment cannot be provisioned in CI yet.

Expected files

- `win_service.c`
- `win_service.h`
- `proxy.c`
- `crates/ciadpi-bin/src/platform/`
- `.github/workflows/ci.yml`
- Windows-facing test or verification docs

Constraints

- Do not regress Linux parity while adding Windows code.
- Keep unsafe code minimal and well-contained.

Acceptance criteria

- Windows runtime behavior is implemented in Rust with documented verification.
- Linux cutover remains green.

Verification

- `cargo test --workspace`
- Windows-specific checks added by the task
- `make test`
