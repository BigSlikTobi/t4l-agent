# OpenClaw bootstrap

## What the owner does

Raw OpenClaw cannot accept host software from an unauthenticated phone. The
owner must approve one bootstrap plugin install in OpenClaw Control UI or run:

```bash
openclaw plugins install npm:@t4l-trainer/openclaw-t4l-connect@0.3.0 --pin --force
```

That exact package is public and pins the signed T4L v0.3.1 release. The source
policy intentionally remains a fail-closed placeholder; production packages
are staged with the real release key and manifest before publication.

The user flow is:

1. Enter the existing OpenClaw Gateway URL in T4L Trainer.
2. The app creates a phone key and one ten-minute pairing code.
3. Send `/t4l connect XXXX-XXXX` through an authenticated owner channel.
4. The pre-model plugin verifies the owner, installs the signed connector, and
   adopts the original request. The phone keeps the same URL and code.
5. The phone proves its key and receives only `chat`, `sync`, and `status`.
6. The app runs the post-pair setup operation. That installs and verifies the
   MCP entry and current T4L instructions.

No provider key, OpenClaw operator token, connector runtime token, MCP key, or
SSH credential reaches the phone.

If host installation fails after owner confirmation, the installer rolls back
and keeps that phone request for the rest of its 30-minute completion window.
Fix the host problem, then resend the exact same `/t4l connect XXXX-XXXX`
command. The same request, code, and operation are retried. The phone must not
create a replacement pairing.

## Host requirements

- OpenClaw `>=2026.7.1-2` and `<2027.0.0`.
- CPython 3.11, 3.12, or 3.13.
- v1 release target: Linux x86_64 with glibc 2.17 or newer, or macOS arm64.
- A user systemd session on Linux, or a user launchd session on macOS.
- One stable OpenClaw agent ID. Ambiguous multi-agent profiles must set
  `agentId` in the plugin config once.
- A trusted way for the owner to send the command before the model sees it.

The signed wheelhouse includes `pip==26.1.2`. The installer creates the venv
with `--without-pip` and runs that pinned wheel directly. A Debian or Ubuntu
host therefore does not need a manual `pythonX.Y-venv` install just to provide
`ensurepip`.

The installer resolves the real OpenClaw executable during owner approval and
stores absolute executable and config paths. `OPENCLAW_STATE_DIR` and
`OPENCLAW_CONFIG_PATH` win when present. Otherwise it follows `OPENCLAW_HOME`,
then `HOME`, and the active OpenClaw profile.

## Network modes

There is no T4L relay in this release.

- Existing HTTPS: keep the Gateway behind the user's current trusted HTTPS
  reverse proxy. The plugin registers only T4L routes.
- Tailscale Serve: expose the existing Gateway inside the tailnet. T4L does not
  enable Funnel or make it public.
- Direct local: `http://localhost` and loopback IPs are allowed on the same
  machine. Remote plain HTTP is rejected before tokens or signed requests are
  proxied.

The public authority and scheme are forwarded only through the loopback proxy.
The connector accepts those headers only from a loopback peer. The app keeps
the exact address it entered.

## Isolation

Each coach gets its own root identity, pairing store, port, service, release
tree, secrets, database, operations, snapshots, logs, and chat state. The
installer probes a large high-port range and persists the chosen port. A root
already claimed by another agent fails closed.

Use a separate OpenClaw profile, state directory, public hostname, and T4L root
for each coach. Sharing an OpenClaw profile mixes plugin and skill config and is
not supported.

## Lean agent policy

Post-pair setup applies these settings only to the selected T4L agent:

- no OpenClaw workspace/bootstrap prompt injection;
- no OpenClaw skill injection;
- the minimal tool profile plus `web_search` for missing exercise-video data;
- no heartbeat turns.

The T4L coach loop supplies one purpose-specific instruction slice and one
deduplicated phone context per turn. Each native call uses a fresh session key,
so old OpenClaw session history is not replayed. Durable coaching notes are
captured in the same model response instead of a second model call. Provider,
model, and reasoning settings are preserved. Uninstall restores the four prior
policy areas when they were not changed after T4L applied them.

## Lifecycle commands

- `/t4l verify` checks the exact service definition, signed release identity,
  live connector identity, MCP, plugin config, and current instructions.
- `/t4l update` installs the policy-pinned signed host release, restarts the
  service, applies and verifies its runtime setup through the loopback-only
  host API, then commits the new host marker.
- `/t4l uninstall` first removes T4L runtime setup through the loopback-only
  host API. It removes host files only after that operation reports
  `uninstalled`. The bootstrap plugin remains so a later phone can reconnect.

Commands are owner-only and are handled before the model. Duplicate commands
reuse the same operation. Update and uninstall cannot run together. Operations,
snapshots, and quarantine state survive a Gateway or host restart. A failed
update restores the prior release and reapplies its runtime setup.

## Current external gates

The code and deterministic packaging tools exist. Production still needs:

- an offline wheelhouse built for every declared v1 OS, CPU, and Python target;
- a real long-lived Ed25519 release public key in the staged plugin;
- immutable HTTPS artifact and manifest URLs;
- npm publication of the pinned bootstrap package;
- a live Gateway test against OpenClaw `2026.7.1-2` for Slack and web chat;
- systemd and launchd install tests on real hosts.

Until those gates are complete, the checked-in plugin is a development package
and deliberately fails full installation.
