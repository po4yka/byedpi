Goal

Retire the remaining C runtime/oracle infrastructure after Windows Rust parity is proven, leaving byedpi in a fully Rust-owned state.

Current status

- Phase 7 is archived as complete, and phase 8 is now archived as complete as well; `tools/ralph-loop/tasks/byedpi-rust-migration.tsv` has no active migration phases.
- Default developer and CI verification is now Rust-owned: `make test` and `make cutover-gates` cover the supported default path, while `make transition-runtime-gates` and `make transition-safety-gates` retain the heavier explicit Rust-owned runtime/safety coverage.
- The installed Ralph 2.7.0 CLI on this machine had a fixed 14400-second runtime cap, so phase 8 was completed through narrow relaunchable slices rather than one long unattended loop.

Slice status (2026-03-09)

- Default verification and the surviving explicit runtime/safety gates are all Rust-owned.
- `make test` now covers the Rust-owned default path only: packet corpus regressions, proxy/runtime Linux checks that no longer require the hidden C runtime, Rust-only workspace/unit coverage including the committed-fixture `oracle_diff` integrations, and migration/install smoke.
- The four crate-local Rust `oracle_diff` suites now read committed fixture data under `tests/corpus/rust-fixtures/` instead of shelling out to `tests/bin/oracle_*`, so `cargo test --workspace` and `make test-rust-oracle-diff` are Rust-owned.
- `make test-transition-runtime` is now the canonical explicit runtime target: `test-desync-runtime` is Rust-owned via committed desync fixtures, and routed Linux parity is also Rust-owned after replacing the old hidden-C preflight with a self-hosted runtime probe. The legacy alias targets referenced earlier in this archive were retired before closeout.
- `make cutover-gates` remains the default Linux/CI entrypoint and no longer builds `tests/bin/ciadpi-oracle` implicitly; the supported explicit runtime/safety gates remain available for heavier operational coverage.

Final closeout state

- `test-desync-runtime` still provides unique live runtime parity, but it is now fully Rust-owned: the `mod-http`, `tlsminor`, and `tlsrec` stream assertions load committed expectations from `tests/corpus/rust-fixtures/desync_oracle.json`, while the `oob` stream check and the tcpdump-backed loopback wire assertions continue to execute only the Rust binary under live sockets. It should remain an explicit non-default Linux gate for now because it is heavier and environment-sensitive, not because it still depends on hidden C.
- `test-linux-routed-runtime` still provides unique multi-namespace routed parity for `fake`, `md5sig`, and `drop-sack`, but it is now Rust-owned end to end; it stays explicit only because the namespace/runtime preflight remains environment-sensitive.
- `make transition-runtime-gates` now covers only the explicit Rust-owned runtime suite, and `make transition-safety-gates` replaces the retired legacy C sanitizer lane with Rust-owned packet/proxy/desync safety smoke.
- The dead C-only helper surface has been retired: the old `oracles` target, the unused C oracle helper sources under `tests/oracle_*`, the Windows C service helper pair `win_service.c` / `win_service.h`, and the dead root-level legacy runtime sources/headers are gone. Residual C files still exercised by supported verification are limited to the packet-fixture/tooling subset (`packets.c`, `packets.h`, `tests/test_packets.c`, `tests/fuzz_packets.c`, and `tests/packets_exercise.*`).
- `cargo clippy --workspace --all-targets -- -D warnings` now exits 0 on the current tree, so the remaining phase-8 closeout work is repository/archive hygiene rather than lint debt.
- The migration-era alias targets (`make test-transition-oracles`, `make transition-oracle-gates`, `make test-sanitize`, and `make transition-c-sanitize-gates`) have been retired. The supported explicit gate names are now only `make test-transition-runtime`, `make transition-runtime-gates`, and `make transition-safety-gates`.

Historical gaps closed during phase 8

- Removed the hidden C oracle runtime and obsolete C build/install paths from normal development, CI, and release flows.
- Replaced the remaining C-based oracle checks with Rust-owned golden vectors, differential fixtures, or contract tests.
- Deleted or archived obsolete C runtime/service sources once they were no longer required for supported verification.
- Simplified docs, build wiring, and migration notes to describe the final Rust-only architecture.

Completed first implementation slice

- Slice name: decouple default cutover gates from the hidden C oracle.
- Result: landed. `make test`, `make cutover-gates`, and default Linux CI no longer compile the hidden C oracle implicitly; the retained oracle-backed coverage is now isolated behind `make test-transition-oracles` and `make transition-oracle-gates`.

Completed second implementation slice

- Slice name: replace Rust `oracle_diff` integrations with Rust-owned fixtures.
- Result: landed. The `ciadpi-config`, `ciadpi-session`, `ciadpi-desync`, and `ciadpi-packets` integration suites now load committed fixture data, and `make test-rust-oracle-diff` no longer depends on `make oracles`.

Completed third implementation slice

- Slice name: reassess remaining explicit transition-oracle backlog.
- Result: landed. The remaining hidden-C backlog is now narrowed to the four Python parity suites plus `make test-sanitize`; `make test-rust-oracle-diff` is documented as Rust-owned even though `make test-transition-oracles` still groups it for operator convenience. The reassessment also identified `tests/test_rust_binary_parity.py` as the smallest remaining explicit oracle slice because it only protects CLI help/version/parse-failure parity that already overlaps with `crates/ciadpi-bin/tests/cli.rs` and `tests/test_contract.py::CliContractTests`.

Completed fourth implementation slice

- Slice name: retire the explicit Rust-vs-C CLI parity target.
- Result: landed. `crates/ciadpi-bin/tests/cli.rs` now covers the remaining `--fake-offset` help marker and invalid-argument diagnostic shape from the retired Python parity test, `tests/test_rust_binary_parity.py` has been removed, and `make test-transition-oracles` now lists only the still genuinely hidden-C-backed runtime/contract suites plus the Rust-owned `test-rust-oracle-diff` helper.

Completed fifth implementation slice

- Slice name: reassess remaining explicit oracle backlog after CLI parity cutover.
- Result: landed. The remaining transition suite is now ranked by unique hidden-C value instead of by historical grouping: `test-contract` is the smallest next retirement target because its CLI/config/protocol/desync-plan assertions are already duplicated by Rust-owned tests, while `test-desync-runtime`, `test-linux-routed-runtime`, and `test-sanitize` still protect live runtime or toolchain behavior that is not yet otherwise covered.

Completed sixth implementation slice

- Slice name: retire the explicit `test-contract` parity target.
- Result: landed. The final `test-contract`-only assertions now live in `crates/ciadpi-session/tests/oracle_diff.rs` and `crates/ciadpi-desync/tests/oracle_diff.rs`, `tests/test_contract.py` has been removed, and both `make test-transition-oracles` and `make test-sanitize` now skip that retired parity path while keeping the remaining live-runtime and routed hidden-C checks explicit.

Completed seventh implementation slice

- Slice name: reassess remaining explicit oracle backlog after test-contract cutover.
- Result: landed. The surviving hidden-C touch points are now ranked by the exact oracle dependency they still carry instead of by whole-suite names: `test-desync-runtime` depends on `oracle_desync` only for three plan-vector assertions, `test-linux-routed-runtime` depends on `ciadpi-oracle` only for its routed fake-path preflight/skip heuristic, and `test-sanitize` remains the only fully C-toolchain-backed target. That narrows the next retirement order to desync plan vectors first, routed preflight second, and sanitizer/toolchain cleanup last.

Completed eighth implementation slice

- Slice name: retire the `oracle_desync` dependency from `test-desync-runtime`.
- Result: landed. `tests/test_desync_runtime.py` now loads committed desync expectations from `tests/corpus/rust-fixtures/desync_oracle.json` for the `mod-http`, `tlsminor`, and `tlsrec` stream assertions, `make test-desync-runtime` no longer depends on `make oracles`, and the live runtime/OOB/tcpdump coverage remains an explicit gate without shelling out to `tests/bin/oracle_desync`.

Completed ninth implementation slice

- Slice name: reassess remaining explicit oracle backlog after desync-runtime cutover.
- Result: landed. The explicit transition suite is now ranked by why each target remains outside the default Rust-owned gates: `test-desync-runtime` stays explicit only because it is a heavier live-runtime/tcpdump Linux gate, `test-linux-routed-runtime` is now the sole hidden-C runtime dependency because of its `ciadpi-oracle` preflight heuristic, and `test-sanitize` remains the final C-toolchain-backed blocker because it still requires `clang` and sanitizer-only C binaries.

Completed tenth implementation slice

- Slice name: retire the routed fake-path preflight from `test-linux-routed-runtime`.
- Result: landed. `tests/test_linux_routed_runtime.py` now runs its preflight against the Rust `ciadpi` binary itself under a one-shot environment guard instead of shelling out to `tests/bin/ciadpi-oracle`, `make test-linux-routed-runtime` no longer depends on `make oracles`, and the routed fake/md5sig/drop-sack assertions remain intact while skipping unsupported environments through a Rust-owned preflight.

Completed eleventh implementation slice

- Slice name: reassess remaining explicit gates after routed cutover.
- Result: landed. `test-desync-runtime` and `test-linux-routed-runtime` are now explicitly documented as Rust-owned Linux runtime gates that stay outside `make test` only because of runtime weight and environment sensitivity, while `make test-sanitize` is now the sole remaining C-backed transition blocker and the only reason `make transition-oracle-gates` still needs the legacy toolchain path.

Completed twelfth implementation slice

- Slice name: split the legacy sanitizer gate from the Rust-owned explicit runtime gates.
- Result: landed. `make transition-oracle-gates` now runs only the Rust-owned explicit Linux runtime checks, `make transition-c-sanitize-gates` owns the remaining legacy C sanitizer smoke, `make test-sanitize` stays as a compatibility alias, the stale `oracles` dependency was removed from the sanitizer job, the sanitizer compiler now falls back to `cc` when `clang` is unavailable, and the C sanitizer lane now leaves `AUTO` parity to the Rust-owned `make test-auto-runtime` gate instead of duplicating it under sanitizer.

Completed thirteenth implementation slice

- Slice name: retire the remaining legacy C sanitizer path.
- Result: landed. `make transition-safety-gates` now owns the packet/proxy/desync safety smoke on the Rust binary, the old `make test-sanitize` and `make transition-c-sanitize-gates` entrypoints are compatibility aliases to that Rust-owned gate, nightly CI now calls the Rust-owned target directly, and the Makefile no longer builds sanitized legacy C binaries.

Completed fourteenth implementation slice

- Slice name: decide the end state for the remaining explicit Rust-owned runtime gates and retire dead C helpers.
- Result: landed. `test-desync-runtime` and `test-linux-routed-runtime` remain explicit by design because they are heavy, environment-sensitive operational gates; `make test` now owns the committed-fixture `test-rust-oracle-diff` coverage; `make test-transition-runtime` / `make transition-runtime-gates` are the canonical explicit runtime targets with the old oracle names kept only as compatibility aliases; and the dead C oracle helper sources plus the unused Windows C service helper pair have been removed.

Completed fifteenth implementation slice

- Slice name: retire the remaining migration-era alias targets and archive phase 8.
- Result: landed. The old alias targets (`make test-transition-oracles`, `make transition-oracle-gates`, `make test-sanitize`, and `make transition-c-sanitize-gates`) have been removed because no supported CI or repo automation still called them, the residual C inventory was re-confirmed as packet-fixture/tooling only, the manifest now has no active migration phases, and the final supported explicit gates are the canonical Rust-owned targets (`make test-transition-runtime`, `make transition-runtime-gates`, and `make transition-safety-gates`).

Expected files

- `Makefile`
- `README.md`
- `tests/coverage_map.md`
- `tools/ralph-loop/tasks/`
- `.ralph/specs/20260309T030547Z-codex-remaining-full-migration-22a588/`

Constraints

- Do not start this phase until phase 7 has established adequate Windows verification.
- Do not remove C-backed coverage until a Rust-owned replacement is in place.
- Keep the final verification story reproducible from the repository.
- Keep the oracle-backed suites runnable during the transition, but move them behind explicit targets instead of the default cutover gates.
- End the loop once one verified slice lands and the next slice is written down; do not spend the full runtime cap on backlog grooming.

Acceptance criteria

- Normal build, install, and CI flows no longer depend on compiling the C runtime.
- Any surviving C files are either test fixtures only or explicitly documented as out of scope.
- Docs and task records reflect that the migration is complete.

Slice acceptance criteria

- `make test` and `make cutover-gates` no longer require `make oracles` or `tests/bin/ciadpi-oracle` as an implicit dependency.
- Any remaining C oracle checks run through clearly named explicit targets or workflows, with docs explaining that they are temporary transition coverage.
- Coverage docs identify which parity surfaces are still backed by the hidden C oracle and which gates are already Rust-only.

Remaining after phase 8

- No unfinished migration phases remain.
- Keep the heavy Rust-owned runtime gates explicit unless a later operational decision promotes them into the default path.
- Preserve the documented packet-fixture/tooling C assets unless a separate cleanup slice replaces that verification surface.

Verification

- `cargo test --workspace`
- `make test`
- `make test-windows-cross-check`
- `make cutover-gates`
- `make transition-runtime-gates`
- `make transition-safety-gates`

First-slice verification

- Planning/doc slice: `cargo test --workspace`, `make test`, `make test-windows-cross-check`
- Implementation slice: `cargo test --workspace`, `make test`, `make cutover-gates`, `make test-windows-cross-check`, plus the explicit oracle-only target(s) retained for transition coverage
