# Ralph Loop Infrastructure for byedpi

This repository includes a repo-local Ralph project configuration, a launcher for byedpi migration closeout work, and archived specs for the completed migration phases.
It is designed for the upstream `ralph-orchestrator` CLI: <https://github.com/mikeyobrien/ralph-orchestrator>.

## Prerequisites

- `ralph` CLI installed and authenticated
- `codex` CLI installed and authenticated
- Optional: `claude` CLI if you want to run the same loop catalog against Claude instead
- Optional: `mingw-w64` if you want the full Windows cross-link checks locally

## Files

- `ralph.yml`: repo-local Ralph configuration recognized by upstream `ralph`
- `PROMPT.md`: default repo prompt for migration closeout/archive checks
- `scripts/ralph-loop`: generic Ralph wrapper for this repository
- `scripts/ralph-rust-migration`: byedpi-specific launcher for migration backlog and closeout checks
- `tools/ralph-loop/templates/`: task and prompt templates
- `tools/ralph-loop/tasks/`: active manifest plus archived migration task specs

Generated runtime state is kept out of git:

- `.ralph-loop/runs/<run-id>/`
- `.ralph/agent/<run-id>/`
- `.ralph/specs/<run-id>/`
- `.worktrees/<loop-id>/`

## Recommended launch flow

1. Run environment checks:

```bash
scripts/ralph-rust-migration doctor
scripts/ralph-rust-migration preflight
```

2. Review the current backlog or completion state:

```bash
scripts/ralph-rust-migration list
```

3. Start the master closeout loop only when you explicitly want backlog orchestration:

```bash
scripts/ralph-rust-migration start full
```

4. Resume an interrupted run bundle with a tighter iteration budget when needed:

```bash
scripts/ralph-rust-migration relaunch <run-id> --max-iterations 36
```

The project-specific launcher defaults to Codex, `builtin:feature`, and manual merge mode because closeout tasks can still touch shared packet verification, docs, and tooling files.
`start phase <n>` only applies to phases still present in the active manifest. Completed phases are kept as archived task specs. Use `start task <id>` when you want a single loop.
On this machine, Ralph 2.7.0 enforces a fixed 14400-second maximum runtime. Prefer a narrow backlog row or task-specific launch over broad historical loops, land one verified slice, and relaunch.

## Migration status

Completed phases:

- Phase 1: runtime policy parity; daemon, pidfile, and TFO
- Phase 2: delayed connect and cache stdout
- Phase 3: staged send and timeout parity
- Phase 4: connection limits and runtime lifecycle
- Phase 5: Shadowsocks plugin runtime mode
- Phase 6: Linux cutover and oracle retention
- Phase 7: Windows runtime port
- Phase 8: Rust-only final cutover
- Phase 9: packet-fixture/tooling Rustification

Active manifest:

- No unfinished packet/tooling migration phases remain.

Meta loop entry:

- `remaining-full-migration`: archived closeout record for the packet/tooling migration

## Notes

- `scripts/ralph-loop start` accepts either `--task "<text>"` or `--task-file <path>`.
- `scripts/ralph-rust-migration full` targets the master `remaining-full-migration` task instead of launching every phase separately.
- `scripts/ralph-rust-migration list` shows the active manifest, including the master meta-loop entry.
- Every generated run bundle records the exact `ralph run` command in `launch.txt`.
- `scripts/ralph-rust-migration relaunch <run-id>` resumes a saved run bundle with `ralph run --continue`; it does not try to override runtime because Ralph 2.7.0 does not expose that flag.
- Phase 9 is fully landed: `make test-packets` and `make fuzz-packets` are Rust-owned via `ciadpi-packets`, and `tests/fuzz_packets.c`, `tests/packets_exercise.*`, `packets.c`, and `packets.h` have been retired.
- The Rust `ciadpi` binary is the Linux-facing default, the runtime migration is archived as complete, and the active manifest currently contains no unfinished packet/tooling phases.
