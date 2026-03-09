Goal

Drive the remaining byedpi migration from mixed C/Rust implementation to a fully Rust-owned runtime and release surface.

Current status

- Phase 7 (`windows-runtime-port`) is already complete and archived.
- Phase 8 (`rust-only-final-cutover`) is archived as complete; `tools/ralph-loop/tasks/byedpi-rust-migration.tsv` now has no active migration phases.
- The installed Ralph 2.7.0 CLI on this machine enforced a fixed 14400-second maximum runtime, so the meta task was executed as a sequence of small, relaunchable slices instead of one uninterrupted loop.

Archived closeout scope

- The final heavy Linux runtime suites remained explicit only where their runtime cost or environment sensitivity justified it.
- The release verification path was made independent of dead legacy C runtime/build artifacts and stale oracle target names.
- The leftover C runtime/oracle build, sanitizer, and Windows service infrastructure were retired once Rust-owned verification covered the same release surface.
- The repository, CI, docs, and release process were left in a Rust-first state, with the residual C surface limited to documented packet-fixture/tooling assets.

Final archived gate layout

- `test-desync-runtime` remains an explicit Linux gate because it exercises live sockets and optional `tcpdump` capture, but it is now Rust-owned and no longer a hidden-C blocker.
- `test-linux-routed-runtime` is now Rust-owned end to end, including the routed fake-path preflight that decides whether this environment should skip the namespace suite, but it remains an explicit Linux runtime gate because the environment sensitivity is still real.
- `make transition-runtime-gates` is the canonical explicit runtime gate, and `make test-transition-runtime` remains the matching direct target.
- `make transition-safety-gates` replaces the retired legacy C sanitizer lane with Rust-owned packet/proxy/desync safety smoke.
- Dead C oracle helpers, the old `win_service.c` Windows helper, and the unreferenced root-level legacy C runtime sources and headers have been removed. Supported verification now uses only the packet-fixture/tooling subset (`packets.c`, `packets.h`, `tests/test_packets.c`, `tests/fuzz_packets.c`, and `tests/packets_exercise.*`).
- The migration-era alias targets (`make test-transition-oracles`, `make transition-oracle-gates`, `make test-sanitize`, and `make transition-c-sanitize-gates`) are retired; future automation should call the canonical Rust-owned targets directly.

Archive notes

- `tools/ralph-loop/tasks/byedpi-rust-migration.tsv` was the active backlog source of truth during the migration run and now remains as the archive index.
- `ralph tools task` tracked the relaunchable closeout slices that finished phase 8 under the Ralph 2.7.0 runtime cap.
- The manifest and task docs were updated as each slice landed; the archive now records a completed migration rather than an active backlog.

Archived execution order

1. Completed each atomic slice of phase 8 (`rust-only-final-cutover`).
2. Updated the manifest/task docs after each verified slice.
3. Relaunched until no active migration phases remained, then archived the backlog.

Migration closeout result

- The Rust migration is complete: the active manifest is empty, the public runtime/install surface is Rust-owned, and the residual C surface is limited to the documented packet-fixture/tooling files.

Constraints

- Do not retire the C oracle until Rust verification is strong enough to replace it.
- Do not regress Linux cutover gates while explicit transition coverage is still being retired.
- Keep platform-specific unsafe code minimal and documented.

Acceptance criteria

- The active manifest contains no unfinished migration phases.
- The public `ciadpi` runtime and supported packaging paths are Rust-owned.
- Windows service/runtime behavior remains implemented in Rust with documented verification.
- The repository no longer relies on compiling the C runtime for normal build, test, or release flows unless a remaining exception is documented in the final task doc.
- Coverage docs reflect the final post-migration state.

Verification

- `cargo test --workspace`
- `make test`
- `make test-windows-cross-check`
- `make cutover-gates`
- `make transition-runtime-gates`
- `make transition-safety-gates`

Archive outcome

- The run stopped after each verified slice to respect Ralph's fixed runtime cap.
- The archived closeout state now has no next migration slice because the manifest is empty.
