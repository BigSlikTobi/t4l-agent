# Signed release process

The production release graph must stay acyclic. The npm bootstrap package is
not an artifact inside the manifest it verifies.

## Required pipeline

1. Create an immutable release ID and version.
2. Stage the npm plugin with the exact HTTPS manifest URL, key ID, and long-lived
   Ed25519 public key. Never put the private key in the repository.
3. Compute the staged plugin digest over the exact packaged file list.
4. Stamp that digest into `runtime_adapter.py`.
5. Build `t4l-agent` 0.3.x and `t4l-server` 0.8.x wheels from that stamped tree.
6. Build one complete offline wheelhouse. It must contain all transitive wheels
   for Linux x86_64 and macOS arm64 on CPython 3.11, 3.12, and 3.13. This
   includes PyYAML, cryptography, cffi, and pycparser where required.
7. Build the pinned instruction archive.
8. On every declared target, create a fresh venv with networking disabled and
   install only from the wheelhouse. Run connector startup, manifest, MCP,
   setup, chat, video-link, superset, circuit, update, rollback, and uninstall
   smoke tests.
9. Upload artifacts to immutable HTTPS URLs and construct the four-artifact
   manifest: agent wheel, server wheel, wheelhouse archive, and instructions.
10. Sign the canonical manifest with the offline Ed25519 private key.
11. Pack the same staged npm plugin. The prepack guard rejects placeholder
    policy. Confirm the tarball policy and plugin digest again.
12. Publish the immutable manifest and pinned npm version. Never point release
    policy at a mutable Git branch.

Repository URLs in the manifest are metadata only. The installer never runs
`git clone`, checks out `main`, or executes repository scripts.

## Tooling

`scripts/release_tools.py` stages a non-placeholder plugin, computes its digest,
stamps the runtime adapter, packs the plugin, and signs a manifest from exact
artifact files. It refuses placeholder keys, missing artifacts, non-HTTPS URLs,
or a private key that does not match the staged public key.

Example staging step:

```bash
python scripts/release_tools.py stage-plugin \
  --source openclaw_plugins/t4l-connect \
  --destination build/release/plugin \
  --policy release-policy.production.json \
  --staging-root build/release \
  --stamp-runtime-adapter \
    build/release/agent-source/src/t4l_agent/runtime_adapter.py
```

Build the exact locked 15-wheel dependency archive from a staging directory
that contains only the pinned wheels:

```bash
python scripts/release_tools.py build-wheelhouse \
  --source build/release/dependency-wheels \
  --output build/release/t4l-python-wheelhouse.tar.gz
```

Each of the six native runners then creates its own bound receipt. The smoke
executable must run a real isolated OpenClaw install, load, owner command, and
uninstall cycle. It prints the exact `t4l_plugin_lifecycle_smoke.v1` JSON
contract:

```bash
python scripts/release_tools.py verify-target \
  --target linux-x64-cp311 \
  --release-id t4l-agent-0.3.0 \
  --version 0.3.0 \
  --agent-wheel build/release/t4l_agent-0.3.0-py3-none-any.whl \
  --server-wheel build/release/t4l_server-0.8.0-py3-none-any.whl \
  --wheelhouse build/release/t4l-python-wheelhouse.tar.gz \
  --instructions build/release/t4l-instructions.tar.gz \
  --staged-plugin build/release/plugin \
  --output build/verification-receipts/linux-x64-cp311.json \
  --plugin-smoke-command /protected-ci/bin/t4l-openclaw-smoke
```

`verify-target` checks the native OS, CPU, Python, and Linux glibc floor. It
creates a clean venv, installs with `pip --no-index` from the locked wheelhouse,
checks exact package versions and instruction markers, and accepts lifecycle
evidence only for the staged plugin digest. The CI job still needs an outbound
network firewall. `--no-index` closes pip's index path but is not a host-wide
network sandbox.

Example signing step:

```bash
export T4L_RELEASE_PRIVATE_KEY='<base64url raw Ed25519 private key>'
python scripts/release_tools.py sign-manifest \
  --build-input release-build.json \
  --policy release-policy.production.json \
  --verification-receipts build/verification-receipts \
  --staged-plugin build/plugin \
  --pack-output dist \
  --output dist/t4l-release.json
```

The final signing command refuses to sign or pack until all six declared target
receipts match the exact wheelhouse, instruction archive, and staged plugin
digest. The receipts must come from network-disabled clean-install jobs. These
helpers do not publish artifacts. Receipt files are evidence from a protected
CI runner or a manual release operator; plain JSON is not a cryptographic
attestation. Cross-platform jobs, publication, key custody, and that protected
runner boundary remain external release gates.
