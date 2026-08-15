# T4L Agent

T4L Agent runs the T4L connector and the in-app coach loop.

## Runtime owns the AI

T4L has no preferred provider, model, or reasoning mode. It uses the agent that
the customer already configured in their runtime.

- T4L does not request, store, or validate provider credentials.
- T4L does not switch the runtime's model or reasoning setting.
- Provider, model, and reasoning labels are optional display metadata only.
- Coach turns run through the configured runtime's native agent interface.
- T4L still owns pairing, phone scopes, context sync, and typed plan validation.

The current production adapter executes OpenClaw agent turns without
`--deliver`. It does not pass a provider, model, or reasoning override. The
runtime therefore uses its own active configuration.

## Hands-off OpenClaw bootstrap

The user does one host-approved action before opening T4L Trainer: install the
small `t4l-connect` bootstrap plugin into an existing OpenClaw Gateway. Raw
OpenClaw cannot safely let an unauthenticated phone install host software.

The production command is:

```bash
openclaw plugins install npm:@t4l-trainer/openclaw-t4l-connect@0.2.0 --pin --force
```

`@t4l-trainer/openclaw-t4l-connect@0.2.0` is public and pins the signed T4L
v0.3.0 release. The checked-in source policy remains a fail-closed build
placeholder so an unstaged source package cannot masquerade as production. For
local development, build the tarball and install its absolute path:

```bash
cd openclaw_plugins/t4l-connect
T4L_ALLOW_PLACEHOLDER_PACKAGE=development-only npm pack
openclaw plugins install \
  npm-pack:/absolute/path/t4l-openclaw-t4l-connect-0.2.0.tgz --force
```

After that, the app needs only the existing Gateway address. It discovers the
bootstrap, creates the phone key and code, and shows `/t4l connect CODE`. The
owner sends that message in Slack or another authenticated OpenClaw owner
channel. The command is handled before the model. It starts the deterministic
host installer, adopts the same pairing request, and switches the same Gateway
URL to the connector. No second code is required.

The phone never receives SSH credentials, a provider key, an OpenClaw admin
token, the connector runtime token, or the MCP key.

OpenClaw `2026.7.1-2` through the compatible 2026.x API range is required. When
a Gateway has one configured agent, its stable ID is discovered. A Gateway with
multiple ambiguous agents must set the plugin's `agentId` once in OpenClaw
Control UI.

See [the bootstrap operations guide](docs/OPENCLAW_BOOTSTRAP.md) and
[the signed release guide](docs/RELEASES.md).

Hermes is not enabled for secure pairing or coach execution in this build.
Its available integration does not expose the verified pre-model owner hook and
native non-delivering agent boundary this flow requires. Startup fails closed.

## Advanced manual install

The Python packages are distributed through the signed GitHub release and
offline wheelhouse, not PyPI. The signed installer is the normal path. For a
manual development install, build both local wheels, then make pipx preinstall
the exact server wheel before it installs the agent wheel:

```bash
cd /absolute/path/to/t4l-server
python -m build

cd /absolute/path/to/t4l-agent
python -m build
export PIPX_DEFAULT_PYTHON=python3.12
pipx install \
  --python python3.12 \
  --preinstall /absolute/path/to/t4l-server/dist/t4l_server-0.8.0-py3-none-any.whl \
  /absolute/path/to/t4l-agent/dist/t4l_agent-0.3.0-py3-none-any.whl
```

This advanced development command may fetch third-party dependencies from
PyPI. The production host installer instead uses the signed offline wheelhouse.

The Python wheel deliberately does not contain a second copy of the OpenClaw
plugin. Install the pinned plugin into the same OpenClaw profile first. Then run
`openclaw --profile coach-01 plugins inspect t4l-connect --runtime --json` and
copy the absolute `install.installPath` value. A missing, relative, symlinked, or
digest-mismatched path is rejected before the connector starts.

For a manual development run, omit `--bootstrap-plugin-preinstalled`. That
flag is reserved for the signed host installer. The manual path must let
`t4l-agent` set the installed plugin's loopback connector route and restart the
Gateway.

Use the real OpenClaw agent ID and profile. A normal single-agent OpenClaw
profile usually has agent ID `main`; the profile name is a separate value.
Point `--agent-home-dir`, `--agent-state-dir`, and `--agent-config-path` at the
existing bot rather than creating a second empty OpenClaw state tree.

Run one isolated connector with the exact plugin path:

```bash
export T4L_CONNECTOR_RUNTIME_TOKEN='<random-runtime-only-secret>'

t4l-agent run \
  --agent-id main \
  --agent-name Atlas \
  --agent-runtime openclaw \
  --agent-profile coach-01 \
  --agent-home-dir /home/openclaw \
  --agent-state-dir /home/openclaw/.openclaw-coach-01 \
  --agent-config-path /home/openclaw/.openclaw-coach-01/openclaw.json \
  --data-dir /srv/t4l-agents/coach-01/server-data \
  --instruction-bundle-dir /opt/t4l-agent-instructions \
  --openclaw-plugin-dir /absolute/path/from/install.installPath \
  --connector-owner-id slack:T0123456789:U0123456789 \
  --port 8787
```

For the authenticated OpenClaw admin web chat, the current canonical owner ID
is `webchat:gateway:operator-admin`. Slack uses
`slack:<workspace-or-account-id>:<user-id>`. Add one
`--connector-owner-id` per trusted owner channel.

When the process reports the connector ready, enter the existing public
OpenClaw Gateway URL in T4L Trainer. Do not enter the loopback port. The
installed plugin keeps the phone on the Gateway origin and proxies only the
T4L routes to this connector.

The server binds to `127.0.0.1` by default. The phone uses the public HTTPS
reverse-proxy URL and a one-time pairing code. It never receives the runtime's
model credentials, connector runtime token, or MCP key.

To bind outside loopback, `--allow-public-bind` is required. That acknowledgement
does not replace TLS. Pairing still requires HTTPS.

`t4l-agent run --server-only` is rejected. Pairing and setup are not exposed
without the active in-app coach loop.

## What `ready` proves

Post-pair setup reports `ready` only after every live check succeeds:

- OpenClaw Gateway is healthy and completes one isolated, non-delivering agent
  turn with its current runtime configuration;
- the local T4L MCP probe returns explicit `{"ok": true}`;
- OpenClaw loads the expected command from the isolated profile;
- the installed plugin path and content digest match the release-pinned plugin;
- the installed instruction digest contains the coach intro, YouTube Short,
  superset, and circuit rules.

The check proves the connected runtime can answer. It does not care which
provider, model, or reasoning mode produced the answer. Failed setup is rolled
back and is never reported as ready.

## Multiple agents on one VPS

The bootstrap derives a separate install root, connector port, service, release
tree, secrets, database, operation log, and pairing store per stable agent ID.
It probes automatic ports before starting. Give every OpenClaw agent a unique:

- agent ID and profile;
- home, state, and data directory;
- port and public HTTPS hostname;
- connector runtime token and owner allowlist.

Do not share state directories, runtime profiles, broker data, tokens, chat
sessions, or logs between agents.

## Phone credential boundary

The phone credential is a T4L connector Ed25519/DPoP token scoped exactly to
`chat`, `sync`, and `status`. It is not a native OpenClaw Gateway device token,
and this build does not call native `device.pair.*` or `device.token.*` APIs.

OpenClaw Gateway operator scopes cannot express only the three T4L REST scopes.
The separate T4L capability token keeps Gateway admin and MCP authority off the
phone. See the official OpenClaw
[operator scopes](https://docs.openclaw.ai/gateway/operator-scopes) and
[Gateway protocol](https://docs.openclaw.ai/gateway/protocol) documentation.

## In-app onboarding and plans

After pairing, the phone creates one hidden onboarding control turn. The coach
introduces the verified runtime identity, explains that the phone owns accepted
state, and asks the first missing setup question. Provider/model/reasoning are
shown only when the runtime reports them.

After the athlete confirms the shown `SETUP SUMMARY`, the coach writes one
strict pending `athlete_setup_draft.v1`. The phone may edit and accept it, then
publishes a fresh context revision and one exact first-plan request.

Plans remain review-only proposals until the phone accepts them. The configured
runtime may use its own research tools when the trusted exercise catalog is
missing. Every selected YouTube Short still has to pass the host's URL and title
verification before storage. No provider-specific search API is called by T4L.

## Commands

```bash
t4l-agent run [options]
t4l-agent chat-loop \
  --server-url http://127.0.0.1:8787 \
  --api-key "$T4L_SERVER_API_KEY" \
  --agent-id coach-01 \
  --agent-profile coach-01 \
  --instruction-bundle-dir /opt/t4l-agent-instructions
t4l-agent runtime-adapter < request.json
t4l-agent licenses
```

The setup bridge invokes `t4l-agent runtime-adapter` with one JSON action on
stdin. Secret values never appear in that JSON or argv. Only credential
environment-variable names cross this boundary.

## Environment

| Variable | Meaning |
|---|---|
| `T4L_CONNECTOR_RUNTIME_TOKEN` | Internal runtime-to-connector pairing credential. |
| `T4L_SERVER_API_KEY` | Optional fixed MCP credential. Generated when absent. |
| `T4L_INSTRUCTION_BUNDLE_DIR` | Instruction path for advanced `chat-loop` use. |
| `T4L_AGENT_POLL_SECONDS` | Chat poll interval. Defaults to `3`. |

Provider credentials stay entirely inside the customer's configured runtime.
They are not T4L environment variables.

## Validation boundary

Automated tests use runtime fakes. Before production, run a live pinned
OpenClaw `2026.7.1-2` test for owner and non-owner channel commands, web-chat
pairing, account identity, Gateway restart, non-delivering coach execution, MCP,
and connector error handling.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ../t4l-server
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
mypy
pytest
node --test openclaw_plugins/t4l-connect/test/*.test.mjs
python -m build
twine check dist/*
```
