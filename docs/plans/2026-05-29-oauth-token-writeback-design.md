# Design: OAuth token write-back + host pre-refresh + 401 retry

**Status:** Approved design, pending implementation plan.
**Date:** 2026-05-29
**Branch:** `fix/keypipe-handshake-tty-passthrough` (design committed here; implementation may move to its own branch).

## Problem

`safe claude` (OAuth mode) forces a re-login on a later run. Root cause: the
keyholder refreshes OAuth tokens **in memory only** and never persists the
rotated refresh token back to the host. Anthropic rotates refresh tokens on
each refresh and invalidates the old one, so the first in-container refresh
orphans the host's stored refresh token. The next run loads the now-dead
token → refresh fails → forced re-login.

Secondary gaps:
- The host reads credentials strictly read-only; there is no return channel.
- `OAuthTokenSource.ForceRefresh` exists but is never wired in — a mid-session
  `401` from upstream is passed straight to the agent instead of triggering a
  refresh + retry.
- `/login` inside the sandbox cannot fix it: the agent is architecturally
  isolated from real auth, the keyholder reads credentials once at startup and
  never re-reads, and the OAuth flow's network/keychain paths are blocked in
  the locked-down container.

All changes are **oauth-mode only**; apikey mode skips this entire path.

## Approach (chosen: A — keyholder-owned bind-mounted write-back file)

The return channel is a per-run file `.safe/<runid>/writeback/credentials.json`,
bind-mounted to `/run/safe/writeback/credentials.json`, chowned by `safe-init`
to `keyholder:keyholder` mode `0600` (parent dir `0700`, keyholder-owned).

Rejected alternatives:
- **B — symmetric TCP return channel:** in-container loopback/gateway is shared
  across uids, so the agent (1000) could read the rotated token or inject a
  poisoned one. Worse on security and complexity.
- **C — `docker cp` after exit:** races `--rm` container teardown; reintroduces
  the permission question. The bind mount avoids the race.

Approach A reuses the file-permission + uid-separation primitive SAFE already
trusts (mirrors the inbound bootstrap, reversed), adds no network surface, and
survives ungraceful container death because the file is rewritten on every
refresh.

## Data flow

1. **Host pre-refresh, before launch** (`cmd/safe/run.go:resolveAuthSecret`):
   read the blob from keychain/secret-tool/file; if the access token is within
   the refresh skew of expiry, the host refreshes (it has open internet),
   persists the rotated blob back to the source, then pipes the fresh blob in.
   Handles the common short-session case so the keyholder often never refreshes.
2. **Keyholder write-back, during the session:** on every successful refresh
   (in-memory pre-expiry refresh **and** the new 401 retry), the keyholder
   writes the current blob to the write-back file atomically (`tmp` + `rename`).
3. **Host persists on exit:** after `docker run` returns, the host reads the
   write-back file, validates it, and updates the same source it read from.
   Newest-wins: the keyholder's exit value supersedes the host's pre-refresh
   value. Absent/empty file → skip (normal for short sessions).

## Components touched

- `internal/keyholder/oauth.go` — retain the original raw blob; add
  `PatchCredentials(orig []byte, creds *OAuthCredentials) ([]byte, error)` that
  overwrites only `claudeAiOauth.{accessToken,refreshToken,expiresAt}` while
  **preserving all other fields** (scopes, subscriptionType, …); add a
  `Snapshot()` accessor.
- `internal/keyholder/writeback.go` *(new)* — `WriteBack(path string, blob []byte)`
  atomic write; called after each refresh.
- `internal/keyholder/transport.go` *(new)* — `refreshingTransport`, an
  `http.RoundTripper` that buffers the request body, sends, and on a `401`
  (oauth only) calls `ForceRefresh`, re-applies the new Bearer header, triggers
  a write-back, and retries **once**. Wired via `ProxyConfig.Transport`.
- `cmd/safe-keyholder/main.go` — pass the write-back path + original blob into
  the token source and transport.
- `cmd/safe/run.go` — host pre-refresh; post-exit read+validate+persist; a small
  `CredentialStore` abstraction (read/write) with macOS-keychain
  (`security add-generic-password -U`), Linux-secret-service (`secret-tool store`),
  and file backends, extending the existing readers.
- `internal/dockerrun/builder.go` — add the write-back bind mount + a path
  constant (mirrors `BootstrapPort`).
- `cmd/safe-init/main.go` — create/chown the write-back file to `keyholder`
  before spawning workers.
- Docs: `SECURITY.md` (new channel + threat note), `ARCHITECTURE.md` (decision
  entry), `COMPONENTS.md` (file map).

## Error handling

- Write-back file absent/empty on exit → skip keychain update.
- Write-back blob fails validation (malformed JSON, empty `accessToken`/
  `refreshToken`) → log warning, **do not overwrite** (anti-poisoning guard).
- Host pre-refresh network failure → non-fatal; proceed with existing blob.
- Keychain write failure → non-fatal warning; worst case re-login next run.
- 401 retry: buffer request body to allow one resend; if the second attempt
  also 401s, pass it through (genuine auth failure). Buffering is bounded by
  request size (Anthropic requests are JSON, not streaming uploads); responses
  stream normally since the branch is on status before the body.

## Threat model / security implications

- **New integrity edge:** credentials previously flowed strictly host→container
  (read-only on the host). Write-back lets the in-container keyholder influence
  what's stored in the host login keychain, under the **fixed** service name
  `Claude Code-credentials`. It cannot write any other keychain item nor
  arbitrary host files — the channel is one chowned file the host parses, not a
  shell.
- **Who could abuse it:** only a compromised keyholder, which requires the
  already-"game-over" tier in `SECURITY.md` (container-root escape **plus** a
  seccomp `ptrace`/`process_vm_*` bypass to touch uid 201). Such an attacker
  already owns the live token; the marginal gain is poisoning the *stored*
  token, contained to one keychain entry.
- **Agent (uid 1000) unaffected:** can neither read nor write the `0600`
  keyholder-owned file (plain DAC uid check, holds even without `hidepid`), and
  there is no network listener to reach. Isolation from the secret is unchanged.
- **Mitigation:** strict host-side validation before any keychain write
  (well-formed Claude JSON, non-empty rotated tokens, never overwrite a good
  entry with empty/garbage) + fixed service name.
- **Confidentiality unchanged:** the rotated token returned is the user's own
  credential going back to the user's own keychain — no new disclosure.

## Testing

- Unit: `PatchCredentials` preserves unknown fields + updates the three;
  round-trip stability.
- Unit: validation rejects empty/missing tokens, accepts a good blob.
- Unit: keyholder writes the write-back file atomically on refresh.
- Unit: `refreshingTransport` — httptest upstream returns 401 then 200; assert
  ForceRefresh fired, header rewritten, one retry, write-back triggered.
- Unit: host pre-refresh persists when near expiry, skips when fresh.
- Unit: `CredentialStore` file backend read/write round-trip; keychain backends
  are thin shell wrappers verified manually.
- Manual (macOS): run `safe claude`, force a refresh, exit, confirm the keychain
  entry updated and a subsequent run does **not** re-login.

## Out of scope

- Changing the inbound bootstrap (TCP + READY handshake stays as just built).
- Multi-account / non-Claude OAuth providers.
- Encrypting the write-back file at rest (it is `0600` on a per-run dir the host
  owns and deletes on exit; same exposure as the inbound blob today).
