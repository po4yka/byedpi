# Ralph Loop Infrastructure for byedpi

This repository includes a repo-local Ralph project configuration, a launcher for the remaining C-to-Rust migration backlog, and archived specs for completed migration phases.
It is designed for the upstream `ralph-orchestrator` CLI: <https://github.com/mikeyobrien/ralph-orchestrator>.

## Prerequisites

- `ralph` CLI installed and authenticated
- `codex` CLI installed and authenticated
- Optional: `claude` CLI if you want to run the same loop catalog against Claude instead
- Optional: `mingw-w64` if you want the full Windows cross-link checks locally

## Files

- `ralph.yml`: repo-local Ralph configuration recognized by upstream `ralph`
- `PROMPT.md`: default repo prompt for the full remaining migration
- `scripts/ralph-loop`: generic Ralph wrapper for this repository
- `scripts/ralph-rust-migration`: byedpi-specific launcher for the remaining migration backlog
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

2. Review the current backlog:

```bash
scripts/ralph-rust-migration list
```

3. Prepare the full remaining migration loop without starting it:

```bash
scripts/ralph-rust-migration dry-run full
```

4. Start the master remaining-migration loop:

```bash
scripts/ralph-rust-migration start full
```

5. Start the active implementation phases individually when needed:

```bash
scripts/ralph-rust-migration start all
```

6. Resume an interrupted run bundle with a tighter iteration budget when needed:

```bash
scripts/ralph-rust-migration relaunch <run-id> --max-iterations 90
```

The project-specific launcher defaults to Codex, `builtin:feature`, and manual merge mode because the remaining migration phases still touch overlapping runtime, CI, and packaging files.
`start phase <n>` only applies to phases still present in the active manifest. Completed phases are kept as archived task specs. Use `start task <id>` when you want a single loop.
On this machine, Ralph 2.7.0 enforces a fixed 14400-second maximum runtime. Prefer `start phase 8` or `start task rust-only-final-cutover` over broad historical loops, land one verified slice, and relaunch.

## Migration status

Completed phases:

- Phase 1: runtime policy parity; daemon, pidfile, and TFO
- Phase 2: delayed connect and cache stdout
- Phase 3: staged send and timeout parity
- Phase 4: connection limits and runtime lifecycle
- Phase 5: Shadowsocks plugin runtime mode
- Phase 6: Linux cutover and oracle retention

Remaining phases in the active manifest:

- Phase 8: Rust-only final cutover

Meta loop entry:

- `remaining-full-migration`: drives the remaining active phase backlog to completion using the active manifest

## Notes

- `scripts/ralph-loop start` accepts either `--task "<text>"` or `--task-file <path>`.
- `scripts/ralph-rust-migration full` targets the master `remaining-full-migration` task instead of launching every phase separately.
- `scripts/ralph-rust-migration list` shows the active manifest, including the master meta-loop entry.
- Every generated run bundle records the exact `ralph run` command in `launch.txt`.
- `scripts/ralph-rust-migration relaunch <run-id>` resumes a saved run bundle with `ralph run --continue`; it does not try to override runtime because Ralph 2.7.0 does not expose that flag.
- The Rust `ciadpi` binary is already the Linux-facing default. Phase 7 (`windows-runtime-port`) is archived as complete, and the remaining active backlog is phase 8 (`rust-only-final-cutover`) to retire the hidden C oracle/runtime.
