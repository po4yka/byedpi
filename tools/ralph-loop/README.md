# Ralph Loop Infrastructure for byedpi

This repository includes a local Ralph loop launcher, an active task catalog for the remaining Rust cutover backlog, and archived specs for the completed C-to-Rust migration phases.

## Prerequisites

- `ralph` CLI installed and authenticated
- `codex` CLI installed and authenticated
- Optional: `claude` CLI if you want to run the same loop catalog against Claude instead

## Files

- `scripts/ralph-loop`: generic Ralph wrapper for this repository
- `scripts/ralph-rust-migration`: byedpi-specific launcher for the remaining migration backlog
- `tools/ralph-loop/config/ralph.core.yml`: Ralph defaults and guardrails
- `tools/ralph-loop/templates/`: task and prompt templates
- `tools/ralph-loop/tasks/`: active manifest plus archived migration task specs

Generated runtime state is kept out of git:

- `.ralph-loop/runs/<run-id>/`
- `.ralph/agent/<run-id>/`
- `.ralph/specs/<run-id>/`
- `.worktrees/<loop-id>/`

## Recommended launch flow

1. Review the current backlog:

```bash
scripts/ralph-rust-migration list
```

2. Prepare the remaining backlog without starting a real loop:

```bash
scripts/ralph-rust-migration dry-run all
```

3. Start the Linux cutover task against Codex:

```bash
scripts/ralph-rust-migration start task linux-cutover-and-oracle-retention
```

4. Start every remaining task:

```bash
scripts/ralph-rust-migration start all
```

The project-specific launcher defaults to Codex and manual merge mode because the remaining cutover tasks still touch overlapping build, CI, and packaging files.
`start phase <n>` only applies to phases still present in the active manifest. Completed phases are kept as archived task specs. Use `start task <id>` when you want a single loop.

## Migration status

Completed phases:

- Phase 1: runtime policy parity; daemon, pidfile, and TFO
- Phase 2: delayed connect and cache stdout
- Phase 3: staged send and timeout parity
- Phase 4: connection limits and runtime lifecycle
- Phase 5: Shadowsocks plugin runtime mode

Remaining phases in the active manifest:

- Phase 6: Linux cutover and oracle retention
- Phase 7: Windows runtime port

## Notes

- `scripts/ralph-loop start` accepts either `--task "<text>"` or `--task-file <path>`.
- `scripts/ralph-rust-migration list` shows only the remaining active backlog; completed phases stay documented in the archived task specs.
- Every generated run bundle records the exact `ralph run` command in `launch.txt`.
- The Rust `ciadpi` binary is the Linux-facing default during phase 6 work, and the C runtime remains available as hidden oracle infrastructure for diffing and rollback.
