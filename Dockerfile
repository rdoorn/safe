# syntax=docker/dockerfile:1.7
# SAFE runtime image. Built with `docker buildx` for multi-arch.
#
# Stages:
#   1. builder  — compiles the five Go binaries.
#   2. runtime  — Debian slim + curated tools + agent + SAFE binaries.

ARG GO_VERSION=1.25.5
ARG DEBIAN_TAG=forky-slim
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
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates nftables iproute2 procps \
      git curl wget jq make \
      build-essential libcap2-bin \
      python3 python3-pip python3-venv \
      nodejs npm \
      ripgrep fd-find \
      bash-completion vim-tiny less \
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

# --- Image labels ---
LABEL org.opencontainers.image.title="safe-runtime" \
      org.opencontainers.image.description="SAFE: Sandboxed Agent For Engineering — single-container AI agent sandbox" \
      org.opencontainers.image.source="https://github.com/rdoorn/safe"

# safe-init is PID 1. It refuses to run as non-root, so don't override
# USER here; Docker's --user flag should also be left alone.
ENTRYPOINT ["/usr/sbin/safe-init"]
