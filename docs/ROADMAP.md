# SAFE Roadmap / feature requests

Live list of things deliberately deferred. Order is not priority.

## Per-project tool version managers

We have **pyenv** (Python) and **fnm** (Node) baked in. Go uses its native
`toolchain` directive in `go.mod` (`GOMODCACHE` lives on the persistent
project cache, so toolchains cache cross-run).

Languages with native version pinning that we have NOT integrated:

- **Rust** — `rust-toolchain.toml` / `rust-toolchain` file pins channel
  + version. Idiomatic manager is `rustup`. Adding requires:
  - Install `rustup-init` in Dockerfile, set `RUSTUP_HOME=/opt/rustup`,
    `CARGO_HOME` somewhere under the persistent cache volume.
  - Bind-mount `<cwd>/.safe/tools/rust/` → `/opt/rustup/toolchains/`.
  - safe-init invokes `rustup toolchain install <version>` on first run
    when `agents.<n>.tools.rust` is set.
  - Allowlist additions: `static.rust-lang.org`, `forge.rust-lang.org`,
    `dl.rust-lang.org`.

- **Ruby** — `.ruby-version` file is convention. `rbenv` is the manager
  most projects use. Pattern mirrors pyenv exactly:
  - Install `rbenv` + `ruby-build` plugin in Dockerfile.
  - Bind-mount `<cwd>/.safe/tools/ruby/` → `/opt/rbenv/versions/`.
  - safe-init invokes `rbenv install <version>` on first run.
  - Allowlist: `cache.ruby-lang.org`, `rubygems.org`.

Both follow the existing pyenv/fnm template; ~half-day each.

## Other deferred items

(seed; add as we go)

- **CI integration tests** for the full safe-claude cold start path.
- **`safe prune`** subcommand to clean up old project-keyed docker volumes.
- **Auto-detect tools version from project files** (`.python-version`,
  `.nvmrc`, `pyproject.toml [requires-python]`, `package.json engines.node`)
  when `agents.<n>.tools.*` is not set explicitly in safe.yaml.
- **Drop dropped-cap-via-prctl from agent** (we already drop bounding set;
  could also drop inheritable/permitted/effective via libcap-ng before exec).
