# SAFE — Sandboxed Agent For Engineering

A single-container sandbox for running AI coding agents (Claude Code, opencode, …) with cilium-style FQDN filtering, secret containment, and a curated tool set.

Drop-in usage: `safe claude [args...]` works like `claude [args...]` but inside a hardened container with `$PWD` mounted as the workspace and a default-deny network.

See [`docs/plans/2026-05-15-safe-design.md`](docs/plans/2026-05-15-safe-design.md) for the architecture and [`docs/plans/2026-05-15-safe-implementation.md`](docs/plans/2026-05-15-safe-implementation.md) for the implementation plan.

Status: **early implementation** — not yet usable.
