# Ralph Loop Infrastructure for byedpi

This repository includes a local Ralph loop launcher and a task catalog for finishing the remaining C-to-Rust migration with Codex as the backend.

## Prerequisites

- `ralph` CLI installed and authenticated
- `codex` CLI installed and authenticated
- Optional: `claude` CLI if you want to run the same loop catalog against Claude instead

## Files

- `scripts/ralph-loop`: generic Ralph wrapper for this repository
- `scripts/ralph-rust-migration`: byedpi-specific launcher for the remaining migration backlog
- `tools/ralph-loop/config/ralph.core.yml`: Ralph defaults and guardrails
- `tools/ralph-loop/templates/`: task and prompt templates
- `tools/ralph-loop/tasks/`: migration task specs and manifest

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

2. Prepare the first batch without starting a real loop:

```bash
scripts/ralph-rust-migration dry-run phase 1
```

3. Start a single task against Codex:

```bash
scripts/ralph-rust-migration start task runtime-policy-parity
```

4. Start a whole phase:

```bash
scripts/ralph-rust-migration start phase 1
```

The project-specific launcher defaults to Codex and manual merge mode because the remaining runtime tasks touch overlapping files.
`start phase <n>` launches one Ralph loop for every task in that phase. Use `start task <id>` when you want a single loop.

## Manifest phases

- Phase 1: runtime policy parity; daemon, pidfile, and TFO
- Phase 2: delayed connect and cache stdout
- Phase 3: staged send and timeout parity
- Phase 4: connection limits and runtime lifecycle
- Phase 5: Shadowsocks plugin runtime mode
- Phase 6: Linux cutover and oracle retention
- Phase 7: Windows runtime port

## Notes

- `scripts/ralph-loop start` accepts either `--task "<text>"` or `--task-file <path>`.
- Every generated run bundle records the exact `ralph run` command in `launch.txt`.
- The current C implementation remains the Linux oracle until the phase 6 cutover task is complete.
