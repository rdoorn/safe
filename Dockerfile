# SAFE runtime image. Built with `docker buildx` for multi-arch.
# (No `# syntax=docker/dockerfile:X.Y` directive — we don't use any features
# beyond what BuildKit's built-in frontend supports, and the directive forces
# a docker-hub fetch that fails offline / behind restrictive firewalls.)
#
# Stages:
#   1. builder  — compiles the five Go binaries.
#   2. runtime  — Debian slim + curated tools + agent + SAFE binaries.

ARG GO_VERSION=1.25.5
# Debian stable (13/trixie). "forky-slim" was an unreleased codename that
# is no longer available on docker hub — pin to trixie-slim instead.
ARG DEBIAN_TAG=trixie-slim
ARG CLAUDE_CODE_VERSION=latest

# -------------------------------------------------------------------- #
# Stage 1: builder
# -------------------------------------------------------------------- #
FROM golang:${GO_VERSION}-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 make build && ls -la bin/

# -------------------------------------------------------------------- #
# Stage 2: runtime
# -------------------------------------------------------------------- #
FROM debian:${DEBIAN_TAG}

ARG TARGETARCH
ARG GO_VERSION
ARG CLAUDE_CODE_VERSION

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# --- Base system + curated CLI tools (Node from Debian forky) ---
# pyenv build deps included so `pyenv install <version>` works on first
# project use; fnm needs unzip to extract its downloads.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates nftables iproute2 procps \
      git curl wget jq yq make unzip xz-utils \
      build-essential libcap2-bin \
      python3 python3-pip python3-venv \
      nodejs npm \
      ripgrep fd-find \
      bash-completion vim-tiny less \
      libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
      libffi-dev liblzma-dev tk-dev \
 && rm -rf /var/lib/apt/lists/*

# Friendly alias: Debian ships fd-find as `fdfind` to avoid an apt collision.
RUN ln -s /usr/bin/fdfind /usr/local/bin/fd

# --- Go toolchain (for agent-side go build) ---
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) GO_ARCH=amd64 ;; \
      arm64) GO_ARCH=arm64 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" \
      | tar -C /usr/local -xz; \
    ln -s /usr/local/go/bin/go /usr/local/bin/go; \
    ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt

# --- Claude Code ---
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}

# --- pnpm: the only npm-compat package manager the agent should reach for ---
# Pin per the project's "at least 7 days old" rule (overrides global LTS).
ARG PNPM_VERSION=9.15.0
RUN npm install -g pnpm@${PNPM_VERSION}

# --- RTK: Rust Token Killer (token-efficient command output for LLM agents) ---
# Pin per the "at least 7 days old" rule. v0.40.0 released 2026-05-13 (12d old).
# Assets: rtk-x86_64-unknown-linux-musl.tar.gz (amd64, static musl)
#         rtk-aarch64-unknown-linux-gnu.tar.gz  (arm64, dynamic gnu)
ARG RTK_VERSION=v0.40.0
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) RTK_TARBALL=rtk-x86_64-unknown-linux-musl.tar.gz ;; \
      arm64) RTK_TARBALL=rtk-aarch64-unknown-linux-gnu.tar.gz ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    mkdir -p /tmp/rtk-extract; \
    curl -fsSL "https://github.com/rtk-ai/rtk/releases/download/${RTK_VERSION}/${RTK_TARBALL}" \
      -o "/tmp/rtk-extract/${RTK_TARBALL}"; \
    curl -fsSL "https://github.com/rtk-ai/rtk/releases/download/${RTK_VERSION}/checksums.txt" \
      -o /tmp/rtk-extract/checksums.txt; \
    cd /tmp/rtk-extract && grep "${RTK_TARBALL}" checksums.txt | sha256sum -c -; \
    tar -xzf "/tmp/rtk-extract/${RTK_TARBALL}" -C /tmp/rtk-extract; \
    install -m0755 /tmp/rtk-extract/rtk /usr/local/bin/rtk; \
    rm -rf /tmp/rtk-extract

# --- pyenv: per-project Python versions ---
# Lives at /opt/pyenv (rootfs, read-only at runtime). Installed Python
# versions go to /opt/pyenv/versions, which SAFE bind-mounts from the
# host's <cwd>/.safe/tools/python so installs persist per-project.
ARG PYENV_VERSION=v2.4.21
RUN git clone --depth 1 --branch ${PYENV_VERSION} https://github.com/pyenv/pyenv.git /opt/pyenv \
 && rm -rf /opt/pyenv/.git

# --- fnm: per-project Node versions ---
# Static binary download. FNM_DIR is set per-session by safe-init to
# point at the project-local volume; the CLI itself lives in /usr/local/bin.
ARG FNM_VERSION=v1.38.1
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) FNM_ARCH=linux ;; \
      arm64) FNM_ARCH=arm64 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/Schniz/fnm/releases/download/${FNM_VERSION}/fnm-${FNM_ARCH}.zip" -o /tmp/fnm.zip; \
    unzip -j /tmp/fnm.zip fnm -d /usr/local/bin/; \
    rm /tmp/fnm.zip; \
    chmod 0755 /usr/local/bin/fnm

# --- SAFE binaries ---
COPY --from=builder /src/bin/safe        /usr/local/bin/safe
COPY --from=builder /src/bin/safe-init   /usr/sbin/safe-init
COPY --from=builder /src/bin/safe-fw     /usr/sbin/safe-fw
COPY --from=builder /src/bin/safe-dns    /usr/sbin/safe-dns
COPY --from=builder /src/bin/safe-keyholder /usr/sbin/safe-keyholder

# --- Users + groups ---
# firewall (200): safe-dns       (gid 100 is taken by Debian's "users" group)
# keyholder (201): safe-keyholder
# agent (1000): the AI agent and any tools it spawns
RUN set -eux; \
    groupadd --system --gid 200 firewall; \
    useradd  --system --uid 200 --gid 200 --no-create-home firewall; \
    groupadd --system --gid 201 keyholder; \
    useradd  --system --uid 201 --gid 201 --no-create-home keyholder; \
    groupadd --gid 1000 agent; \
    useradd  --uid 1000 --gid 1000 --home-dir /home/agent --create-home --shell /bin/bash agent

# --- File capability and permission lockdown for safe-dns ---
# safe-dns needs CAP_NET_ADMIN to add/remove nftables set elements at
# runtime. All other binaries run with zero capabilities.
#
# We restrict safe-dns to mode 0750 owned by root:firewall so only the
# firewall user (and root, i.e. safe-init) can execute it. This is the
# narrow replacement for --security-opt no-new-privileges, which the
# container does not set because it would disable file capabilities.
RUN chgrp firewall /usr/sbin/safe-dns \
 && chmod 0750 /usr/sbin/safe-dns \
 && setcap cap_net_admin+ep /usr/sbin/safe-dns

# --- Lock down nft to firewall group only ---
# nft is shipped because safe-fw/safe-dns use it. The agent uid has no
# CAP_NET_ADMIN so any nft invocation from the agent would be inert
# anyway, but removing it from PATH for the agent is cheap attack-surface
# reduction. Same root:firewall 0750 pattern as safe-dns.
RUN chgrp firewall /usr/sbin/nft \
 && chmod 0750 /usr/sbin/nft

# --- Directories ---
RUN mkdir -p /etc/safe /var/log/safe /run/safe /workspace \
 && chown firewall:firewall /var/log/safe \
 && chmod 0700 /var/log/safe \
 && chmod 0755 /run/safe \
 && chown agent:agent /workspace

# --- Hardening pass ---
# Strip setuid/setgid bits across the image (file caps stay — they aren't
# setuid). Remove sudo / su / their config so even root binaries can't be
# escalated to. su is part of util-linux on Debian; we replace it with a
# no-op stub so anything that looks for it fails fast.
RUN set -eux; \
    find / -xdev -perm /6000 -type f -print -exec chmod a-sx {} \; 2>/dev/null || true; \
    rm -f /usr/bin/sudo /usr/bin/su /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true

# --- Lock down npm-family + apt for the agent uid ---
# Agent uses pnpm exclusively. npm and yarn binaries are left in the image
# (claude-code's internals may invoke them at install time during image build)
# but the agent uid can't exec them at runtime. apt is similarly locked: only
# safe-init (root) can install packages; the agent cannot.
# chmod follows symlinks on Linux, so this affects the underlying JS files.
RUN set -eux; \
    for f in /usr/local/bin/npm /usr/local/bin/yarn /usr/bin/yarn \
             /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-key \
             /usr/bin/dpkg /usr/sbin/dpkg-reconfigure; do \
      if [ -e "$f" ]; then chgrp root "$f" && chmod 0750 "$f"; fi; \
    done

# --- Image labels ---
LABEL org.opencontainers.image.title="safe-runtime" \
      org.opencontainers.image.description="SAFE: Sandboxed Agent For Engineering — single-container AI agent sandbox" \
      org.opencontainers.image.source="https://github.com/rdoorn/safe"

# safe-init is PID 1. It refuses to run as non-root, so don't override
# USER here; Docker's --user flag should also be left alone.
ENTRYPOINT ["/usr/sbin/safe-init"]
