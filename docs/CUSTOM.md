# Building a Custom SAFE Runtime Image

The published `safe-runtime` image ships a curated tool set (git, ripgrep, fd, jq, Go, Python, Node, Claude Code). To add more tools — `gh`, Terraform, a database client, an SDK — build your own image *on top of* the official one and point `safe.yaml` at it.

## Example

```dockerfile
# myorg/safe-runtime-custom
FROM ghcr.io/<org>/safe-runtime:0.1.0

USER root

# Anything you can install via apt — pin versions if you care.
RUN apt-get update && apt-get install -y --no-install-recommends \
      terraform=1.7.* \
      postgresql-client-15 \
      awscli \
 && rm -rf /var/lib/apt/lists/*

# Or grab a binary directly. Verify the checksum.
RUN curl -fsSL https://example.com/tool-v1.2.3-linux-amd64 -o /usr/local/bin/tool \
 && echo "<sha256>  /usr/local/bin/tool" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/tool

# Drop back to agent so the layer stays usable.
USER agent
```

Build and point SAFE at it:

```bash
docker build -t myorg/safe-runtime-custom:dev .

# In your safe.yaml (project or global):
agents:
  claude:
    image: myorg/safe-runtime-custom:dev
```

## Don'ts

- **Don't add packages with setuid binaries.** SAFE's hardening pass strips setuid bits during image build of the base, but a layer added afterwards reintroduces them. If you need root for setup, do it in a build stage and copy the result over to a clean later stage.
- **Don't add `sudo` or `su`.** SAFE removes them deliberately. Adding them back defeats the no-new-privileges hardening.
- **Don't bake credentials into the image.** Use a runtime mount or a keyholder-style proxy for any new secrets.
- **Don't add packages that require capabilities** SAFE doesn't grant. The container runs with `--cap-drop ALL --cap-add NET_ADMIN`. Tools that need `CAP_NET_RAW` (ping, raw sockets) won't work. That's by design.

## Validating your image

Run `safe --doctor` with your custom image set in `safe.yaml`:

```bash
ANTHROPIC_API_KEY=sk-... safe --doctor
```

This confirms the image is pullable, Docker is reachable, and your config is valid.

After that, drop into the sandbox and poke around:

```bash
safe --shell
# inside the container:
$ which terraform
/usr/bin/terraform
$ curl https://api.anthropic.com   # should resolve and connect (auth error from upstream)
$ curl https://evil.com            # should fail with DNS NXDOMAIN
$ find / -perm /4000 -type f 2>/dev/null  # should be empty
```
