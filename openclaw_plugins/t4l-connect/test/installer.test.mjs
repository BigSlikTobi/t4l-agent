import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";

import {
  HostInstaller,
  atomicText,
  canonicalJson,
  renderLaunchdPlist,
  renderSystemdUnit,
  runProcess,
  validateReleasePolicy,
  verifyReleaseManifest,
} from "../dist/installer.js";

function signedRelease() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const artifacts = [
    ["t4l-agent-wheel", "python-wheel", "agent.whl"],
    ["t4l-server-wheel", "python-wheel", "server.whl"],
    ["t4l-python-wheelhouse", "python-wheelhouse-tar", "wheelhouse.tar.gz"],
    ["t4l-instructions", "instruction-bundle-tar", "instructions.tar.gz"],
  ].map(([name, kind, filename], index) => {
    const bytes = Buffer.from(`artifact-${index}`);
    return {
      name,
      kind,
      filename,
      url: `https://release.example.test/${filename}`,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.length,
      bytes,
    };
  });
  const unsigned = {
    schema: "t4l_release_manifest.v1",
    releaseId: "t4l-agent-0.3.0",
    version: "0.3.0",
    minOpenClawVersion: "2026.7.1-2",
    sourceRepositories: [
      { url: "https://github.com/BigSlikTobi/t4l-agent", commit: "a".repeat(40) },
    ],
    artifacts: artifacts.map(({ bytes, ...artifact }) => artifact),
  };
  const signature = sign(null, Buffer.from(canonicalJson(unsigned)), privateKey).toString("base64url");
  const manifest = { ...unsigned, signature: { algorithm: "Ed25519", keyId: "release-key-01", value: signature } };
  const bytes = Buffer.from(JSON.stringify(manifest));
  const der = publicKey.export({ format: "der", type: "spki" });
  const policy = {
    schema: "t4l_release_policy.v1",
    releaseId: manifest.releaseId,
    version: manifest.version,
    manifestUrl: "https://release.example.test/t4l-release.json",
    signingKeyId: "release-key-01",
    signingPublicKey: der.subarray(-32).toString("base64url"),
  };
  return {
    artifacts,
    bytes,
    manifestSha256: createHash("sha256").update(bytes).digest("hex"),
    policy,
  };
}

test("verifies one pinned signed manifest and its complete offline wheelhouse", () => {
  const release = signedRelease();
  const policy = validateReleasePolicy(release.policy);
  const manifest = verifyReleaseManifest(release.bytes, policy, "OpenClaw 2026.7.1-2");
  assert.equal(manifest.artifacts.length, 4);
  assert.ok(manifest.artifacts.some((item) => item.name === "t4l-python-wheelhouse"));
  assert.throws(
    () => verifyReleaseManifest(release.bytes, policy, "OpenClaw 2026.7.1-1"),
    /compatible 2026\.x API range/,
  );
  const tampered = JSON.parse(release.bytes.toString("utf8"));
  tampered.artifacts[0].url = "https://evil.example.test/agent.whl";
  assert.throws(
    () => verifyReleaseManifest(Buffer.from(JSON.stringify(tampered)), policy, "OpenClaw 2026.7.1-2"),
    /signature/,
  );
});

test("systemd rendering rejects newline injection and applies a private umask", () => {
  const base = {
    agentId: "coach-01",
    envFile: "/srv/t4l/secrets.env",
    root: "/srv/t4l/coach-01",
    stateDir: "/srv/openclaw/coach-01",
    homeDir: "/srv/home/coach-01",
    configPath: "/etc/openclaw/coach-01.json",
    environment: { PATH: "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin" },
    command: ["/srv/t4l/current/bin/t4l-agent", "run"],
  };
  assert.match(renderSystemdUnit(base), /UMask=0077/);
  assert.match(renderSystemdUnit(base), /PATH=\/opt\/homebrew\/bin/);
  const plist = renderLaunchdPlist({
    label: "ai.t4l.agent.coach-01-abc123",
    command: base.command,
    environment: base.environment,
    logFile: "/srv/t4l/logs/service.log",
  });
  assert.match(plist, /<key>PATH<\/key>/);
  assert.match(plist, /\/opt\/homebrew\/bin:\/usr\/bin/);
  assert.match(renderSystemdUnit(base), /"\/etc\/openclaw"/);
  assert.throws(
    () => renderSystemdUnit({ ...base, envFile: "/srv/good\nExecStart=/bin/evil" }),
    /control characters/,
  );
});

test("subprocess runner terminates a hung command", async () => {
  const result = await runProcess(
    [process.execPath, "-e", "setInterval(() => {}, 1000)"],
    { timeoutMs: 30 },
  );
  assert.equal(result.code, 124);
  assert.match(result.stderr, /timed out/);
});

test("atomic host writes reject symlink destinations", async () => {
  const root = await mkdtemp(join(tmpdir(), "t4l-installer-symlink-"));
  try {
    const victim = join(root, "victim.env");
    const destination = join(root, "secrets.env");
    await writeFile(victim, "KEEP=1\n");
    await symlink(victim, destination);
    await assert.rejects(() => atomicText(destination, "OVERWRITE=1\n"), /unsafe output/);
    assert.equal(await readFile(victim, "utf8"), "KEEP=1\n");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("dry-run generates isolated service command without provider settings", async () => {
  const root = await mkdtemp(join(tmpdir(), "t4l-installer-"));
  const release = signedRelease();
  const policyPath = join(root, "policy.json");
  await writeFile(policyPath, JSON.stringify(release.policy));
  const byUrl = new Map([
    [release.policy.manifestUrl, release.bytes],
    ...release.artifacts.map((item) => [item.url, item.bytes]),
  ]);
  const fetchImpl = async (url) => {
    const bytes = byUrl.get(String(url));
    if (!bytes) throw new Error(`unexpected URL ${url}`);
    return new Response(bytes, {
      status: 200,
      headers: { "content-length": String(bytes.length) },
    });
  };
  const request = {
    schema: "t4l_host_install_request.v1",
    action: "install",
    operationId: "op_abcdefgh1234",
    agentId: "coach-01",
    agentName: "Coach",
    profile: "coach-01",
    root: join(root, "state", "coach-01"),
    homeDir: join(root, "home", "coach-01"),
    serviceHomeDir: join(root, "service-home"),
    stateDir: join(root, "openclaw", "coach-01"),
    configPath: join(root, "openclaw", "coach-01", "custom.json"),
    pluginDir: new URL("..", import.meta.url).pathname,
    releasePolicyPath: policyPath,
    ownerIdentity: "slack:default:u123",
    openclawExecutable: process.execPath,
    nodeExecutable: process.execPath,
    pythonExecutable: process.execPath,
    serviceMode: "none",
    port: 19001,
    dryRun: true,
  };
  request.rootIdentity = createHash("sha256")
    .update([
      "t4l-bootstrap-root.v2",
      request.profile,
      request.agentId,
      resolve(request.root),
      resolve(request.stateDir),
      resolve(request.configPath),
    ].join("\0"))
    .digest("hex");
  request.serviceId = `${request.agentId}-${request.rootIdentity.slice(0, 12)}`;
  try {
    await mkdir(join(request.root, "bootstrap"), { recursive: true });
    await writeFile(
      join(request.root, "bootstrap", "identity.json"),
      JSON.stringify({
        schema: "t4l_bootstrap_root_identity.v2",
        agentId: request.agentId,
        profile: request.profile,
        stateDir: request.stateDir,
        configPath: request.configPath,
        serviceId: request.serviceId,
        rootIdentity: request.rootIdentity,
      }),
    );
    const installer = new HostInstaller({
      fetchImpl,
      platform: "linux",
      run: async (argv) =>
        argv.at(-1) === "--version"
          ? { code: 0, stdout: "OpenClaw 2026.7.1-2", stderr: "" }
          : { code: 0, stdout: "", stderr: "" },
    });
    const result = await installer.execute(request);
    assert.equal(result.ok, true);
    const duplicate = await installer.execute(request);
    assert.equal(duplicate.ok, true);
    assert.equal(duplicate.idempotent, true);
    assert.equal(duplicate.resumed, true);
    const service = JSON.parse(
      await readFile(join(request.root, "service-command.json"), "utf8"),
    );
    const joined = service.command.join(" ");
    assert.doesNotMatch(joined, /provider|model|reasoning/i);
    assert.match(joined, /--release-state-file/);
    assert.match(joined, new RegExp(`--runtime-executable ${process.execPath}`));
    assert.equal(service.environment.PATH.split(":")[0], dirname(process.execPath));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("install bootstraps pinned pip without host ensurepip", async () => {
  const scratch = await mkdtemp(join(tmpdir(), "t4l-installer-no-ensurepip-"));
  const release = signedRelease();
  const policyPath = join(scratch, "policy.json");
  const root = join(scratch, "state", "coach-01");
  const byUrl = new Map([
    [release.policy.manifestUrl, release.bytes],
    ...release.artifacts.map((item) => [item.url, item.bytes]),
  ]);
  const commands = [];
  try {
    await writeFile(policyPath, JSON.stringify(release.policy));
    const request = {
      schema: "t4l_host_install_request.v1",
      action: "install",
      operationId: "op_noensurepip1234",
      agentId: "coach-01",
      agentName: "Coach",
      profile: "coach-01",
      root,
      homeDir: join(scratch, "home", "coach-01"),
      serviceHomeDir: join(scratch, "service-home"),
      stateDir: join(scratch, "openclaw", "coach-01"),
      configPath: join(scratch, "openclaw", "coach-01", "custom.json"),
      pluginDir: new URL("..", import.meta.url).pathname,
      releasePolicyPath: policyPath,
      ownerIdentity: "slack:default:u123",
      openclawExecutable: "/opt/openclaw/bin/openclaw",
      nodeExecutable: process.execPath,
      pythonExecutable: "/usr/bin/python3.12",
      serviceMode: "systemd",
      port: 19001,
    };
    const installer = new HostInstaller({
      platform: "linux",
      uid: 1000,
      sleep: async () => {},
      fetchImpl: async (url) => {
        if (String(url).includes("127.0.0.1:19001")) {
          return new Response(JSON.stringify({
            agentId: "coach-01",
            installation: {
              targetRelease: {
                releaseId: release.policy.releaseId,
                version: release.policy.version,
                manifestSha256: release.manifestSha256,
              },
            },
          }), { status: 200 });
        }
        const bytes = byUrl.get(String(url));
        if (!bytes) throw new Error(`unexpected URL ${url}`);
        return new Response(bytes, {
          status: 200,
          headers: { "content-length": String(bytes.length) },
        });
      },
      run: async (argv, options = {}) => {
        commands.push({ argv, options });
        if (argv.at(-1) === "--version") {
          return argv[0].includes("openclaw")
            ? { code: 0, stdout: "OpenClaw 2026.7.1-2", stderr: "" }
            : { code: 0, stdout: "Python 3.12.4", stderr: "" };
        }
        if (argv[1]?.endsWith("extract_instructions.py")) {
          await mkdir(argv[3], { recursive: true });
          if (argv[3].endsWith("wheelhouse")) {
            await writeFile(join(argv[3], "pip-26.1.2-py3-none-any.whl"), "pinned");
          }
          return { code: 0, stdout: "", stderr: "" };
        }
        if (argv[1] === "-m" && argv[2] === "venv") {
          await mkdir(join(argv.at(-1), "bin"), { recursive: true });
          await writeFile(join(argv.at(-1), "bin", "python"), "python");
        }
        return { code: 0, stdout: "", stderr: "" };
      },
    });

    const result = await installer.execute(request);

    assert.equal(result.ok, true);
    const venv = commands.find((item) => item.argv[1] === "-m" && item.argv[2] === "venv");
    assert.ok(venv);
    assert.equal(venv.argv[3], "--without-pip");
    const pip = commands.find((item) => item.argv[1] === "-m" && item.argv[2] === "pip");
    assert.ok(pip);
    assert.match(pip.options.env.PYTHONPATH, /pip-26\.1\.2-py3-none-any\.whl$/);
    assert.equal(pip.options.env.PIP_NO_INDEX, "1");
    assert.ok(pip.argv.includes("--no-index"));
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});

test("host request rejects traversal and provider controls before mutation", async () => {
  const root = await mkdtemp(join(tmpdir(), "t4l-installer-invalid-"));
  const base = {
    schema: "t4l_host_install_request.v1",
    action: "install",
    operationId: "op_../../escape",
    agentId: "coach-01",
    profile: "coach-01",
    root: join(root, "state", "coach-01"),
    homeDir: join(root, "home"),
    serviceHomeDir: join(root, "service-home"),
    stateDir: join(root, "openclaw"),
    configPath: join(root, "openclaw", "custom.json"),
    pluginDir: root,
    releasePolicyPath: join(root, "policy.json"),
    ownerIdentity: "slack:default:u123",
    openclawExecutable: process.execPath,
    pythonExecutable: process.execPath,
    port: 19001,
  };
  try {
    await assert.rejects(() => new HostInstaller().execute(base), /operationId/);
    await assert.rejects(
      () => new HostInstaller().execute({ ...base, operationId: "op_abcdefgh", model: "forced" }),
      /forbidden/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("package declares exact OpenClaw host compatibility", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );
  assert.equal(packageJson.peerDependencies.openclaw, ">=2026.7.1-2 <2027.0.0");
  assert.equal(packageJson.openclaw.compat.pluginApi, ">=2026.7.1-2");
  assert.equal(packageJson.openclaw.install.minHostVersion, ">=2026.7.1-2");
});

test("a failed same-release repair preserves the active release and secrets", async () => {
  const scratch = await mkdtemp(join(tmpdir(), "t4l-installer-rollback-"));
  const root = join(scratch, "state", "coach-01");
  const stateDir = join(scratch, "openclaw", "coach-01");
  const oldRelease = join(root, "releases", "t4l-agent-0.3.0-active");
  const release = signedRelease();
  const policyPath = join(scratch, "policy.json");
  const oldSecrets = "T4L_CONNECTOR_RUNTIME_TOKEN=old-runtime\n";
  const oldGatewayEnv = "KEEP_ME=yes\nT4L_CONNECTOR_RUNTIME_TOKEN=old-gateway\nMCP_T4L_API_KEY=old-mcp\n";
  const installed = {
    schema: "t4l_host_install_state.v1",
    agentId: "coach-01",
    profile: "coach-01",
    port: 19001,
    serviceMode: "none",
    releaseDir: oldRelease,
    releaseId: release.policy.releaseId,
    version: release.policy.version,
    manifestSha256: release.manifestSha256,
    signingKeyId: release.policy.signingKeyId,
  };
  try {
    await mkdir(oldRelease, { recursive: true });
    await writeFile(join(oldRelease, "release.json"), JSON.stringify({ releaseId: "corrupt" }));
    await symlink(oldRelease, join(root, "current"));
    await writeFile(join(root, "installed.json"), JSON.stringify(installed));
    await writeFile(join(root, "secrets.env"), oldSecrets);
    await mkdir(stateDir, { recursive: true });
    await writeFile(join(stateDir, ".env"), oldGatewayEnv);
    await writeFile(policyPath, JSON.stringify(release.policy));
    const byUrl = new Map([
      [release.policy.manifestUrl, release.bytes],
      ...release.artifacts.map((item) => [item.url, item.bytes]),
    ]);
    const request = {
      schema: "t4l_host_install_request.v1",
      action: "update",
      operationId: "op_repair12345678",
      agentId: "coach-01",
      agentName: "Coach",
      profile: "coach-01",
      root,
      homeDir: join(scratch, "home", "coach-01"),
      serviceHomeDir: join(scratch, "service-home"),
      stateDir,
      configPath: join(stateDir, "custom.json"),
      pluginDir: new URL("..", import.meta.url).pathname,
      releasePolicyPath: policyPath,
      ownerIdentity: "slack:default:u123",
      openclawExecutable: process.execPath,
      pythonExecutable: process.execPath,
      serviceMode: "none",
      port: 19001,
      dryRun: true,
    };
    const installer = new HostInstaller({
      platform: "linux",
      sleep: async () => {},
      installedStateWriter: async () => {
        throw new Error("injected final marker failure");
      },
      fetchImpl: async (url) => {
        const bytes = byUrl.get(String(url));
        if (!bytes) return new Response("{}", { status: 503 });
        return new Response(bytes, {
          status: 200,
          headers: { "content-length": String(bytes.length) },
        });
      },
      run: async (argv) =>
        argv.at(-1) === "--version"
          ? { code: 0, stdout: "OpenClaw 2026.7.1-2", stderr: "" }
          : { code: 0, stdout: "", stderr: "" },
    });
    await assert.rejects(
      () => installer.execute(request),
      /injected final marker failure; previous state restored/,
    );
    assert.equal(await readlink(join(root, "current")), oldRelease);
    assert.equal(await readFile(join(root, "secrets.env"), "utf8"), oldSecrets);
    assert.equal(await readFile(join(stateDir, ".env"), "utf8"), oldGatewayEnv);
    assert.deepEqual(JSON.parse(await readFile(join(root, "installed.json"), "utf8")), installed);
    assert.equal((await readFile(join(oldRelease, "release.json"), "utf8")).includes("corrupt"), true);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});

test("host update restarts the service and applies the pinned runtime release", async () => {
  const scratch = await mkdtemp(join(tmpdir(), "t4l-installer-update-"));
  const root = join(scratch, "state", "coach-01");
  const stateDir = join(scratch, "openclaw", "coach-01");
  const serviceHomeDir = join(scratch, "service-home");
  const oldRelease = join(root, "releases", "old-release");
  const release = signedRelease();
  const policyPath = join(scratch, "policy.json");
  const byUrl = new Map([
    [release.policy.manifestUrl, release.bytes],
    ...release.artifacts.map((item) => [item.url, item.bytes]),
  ]);
  const actions = [];
  const commands = [];
  try {
    await mkdir(oldRelease, { recursive: true });
    await mkdir(stateDir, { recursive: true });
    await writeFile(join(oldRelease, "release.json"), JSON.stringify({
      schema: "t4l_installed_release.v1",
      releaseId: "old-release",
      version: "0.2.0",
      manifestSha256: "d".repeat(64),
    }));
    await symlink(oldRelease, join(root, "current"));
    await writeFile(join(root, "installed.json"), JSON.stringify({
      schema: "t4l_host_install_state.v1",
      agentId: "coach-01",
      profile: "coach-01",
      port: 19001,
      serviceMode: "systemd",
      releaseDir: oldRelease,
      releaseId: "old-release",
      version: "0.2.0",
      manifestSha256: "d".repeat(64),
      signingKeyId: "old-key",
    }));
    await writeFile(
      join(root, "secrets.env"),
      "T4L_CONNECTOR_RUNTIME_TOKEN=runtime\nT4L_SERVER_API_KEY=server\nMCP_T4L_API_KEY=server\n",
    );
    await writeFile(policyPath, JSON.stringify(release.policy));
    const request = {
      schema: "t4l_host_install_request.v1",
      action: "update",
      operationId: "op_updateactive1234",
      agentId: "coach-01",
      agentName: "Coach",
      profile: "coach-01",
      root,
      homeDir: join(scratch, "home", "coach-01"),
      serviceHomeDir,
      stateDir,
      configPath: join(stateDir, "custom.json"),
      pluginDir: new URL("..", import.meta.url).pathname,
      releasePolicyPath: policyPath,
      ownerIdentity: "slack:default:u123",
      openclawExecutable: process.execPath,
      pythonExecutable: "/usr/bin/python3",
      serviceMode: "systemd",
      port: 19001,
    };
    const installer = new HostInstaller({
      platform: "linux",
      sleep: async () => {},
      run: async (argv) => {
        commands.push(argv);
        if (argv[0] === "/usr/bin/python3" && argv.at(-1) === "--version") {
          return { code: 0, stdout: "Python 3.12.4", stderr: "" };
        }
        if (argv[0] === process.execPath && argv.at(-1) === "--version") {
          return { code: 0, stdout: "OpenClaw 2026.7.1-2", stderr: "" };
        }
        if (argv[1]?.endsWith("extract_instructions.py")) {
          await mkdir(argv[3], { recursive: true });
          if (argv[3].endsWith("wheelhouse")) {
            await writeFile(
              join(argv[3], "pip-26.1.2-py3-none-any.whl"),
              "pinned",
            );
          }
        }
        return { code: 0, stdout: "", stderr: "" };
      },
      fetchImpl: async (url, init = {}) => {
        const artifact = byUrl.get(String(url));
        if (artifact) {
          return new Response(artifact, {
            status: 200,
            headers: { "content-length": String(artifact.length) },
          });
        }
        if (String(url).endsWith("/.well-known/t4l-agent")) {
          return new Response(JSON.stringify({
            agentId: "coach-01",
            installation: {
              targetRelease: {
                releaseId: release.policy.releaseId,
                version: release.policy.version,
                manifestSha256: release.manifestSha256,
              },
            },
          }), { status: 200, headers: { "content-type": "application/json" } });
        }
        if (String(url).endsWith("/v1/setup/runtime-action")) {
          const action = JSON.parse(init.body).action;
          actions.push(action);
          return new Response(JSON.stringify({
            schema: "t4l_setup_operation.v2",
            operationId: `op_runtime${action}5678`,
            action,
            status: "ready",
            terminal: true,
          }), { status: 202, headers: { "content-type": "application/json" } });
        }
        throw new Error(`unexpected URL ${url}`);
      },
    });

    const result = await installer.execute(request);

    assert.equal(result.ok, true);
    assert.deepEqual(actions, ["update", "verify"]);
    assert.ok(commands.some((argv) => argv[0] === "systemctl" && argv.includes("restart")));
    const installed = JSON.parse(await readFile(join(root, "installed.json"), "utf8"));
    assert.equal(installed.releaseId, release.policy.releaseId);
    assert.equal(installed.manifestSha256, release.manifestSha256);
    actions.length = 0;
    const reconcile = await installer.execute({
      ...request,
      operationId: "op_updatesamedrift12",
    });
    assert.equal(reconcile.ok, true);
    assert.equal(reconcile.idempotent, true);
    assert.deepEqual(actions, ["update", "verify"]);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});

test("uninstall removes only T4L Gateway secrets and keeps bootstrap isolated", async () => {
  const scratch = await mkdtemp(join(tmpdir(), "t4l-installer-uninstall-"));
  const root = join(scratch, "state", "coach-01");
  const stateDir = join(scratch, "openclaw", "coach-01");
  const releaseDir = join(root, "releases", "old-release");
  try {
    await mkdir(releaseDir, { recursive: true });
    await mkdir(stateDir, { recursive: true });
    await writeFile(join(root, "service-command.json"), "{}\n");
    await writeFile(
      join(root, "secrets.env"),
      "T4L_CONNECTOR_RUNTIME_TOKEN=runtime\nT4L_SERVER_API_KEY=secret\n",
    );
    await writeFile(join(root, "installed.json"), JSON.stringify({ agentId: "coach-01" }));
    await writeFile(
      join(stateDir, ".env"),
      "KEEP_ME=yes\nT4L_CONNECTOR_RUNTIME_TOKEN=runtime\nMCP_T4L_API_KEY=mcp\n",
    );
    await symlink(releaseDir, join(root, "current"));
    let runtimeUninstallCalled = false;
    const result = await new HostInstaller({
      platform: "linux",
      fetchImpl: async (url, init) => {
        assert.match(String(url), /\/v1\/setup\/runtime-action$/);
        assert.equal(init.headers["x-t4l-runtime-token"], "runtime");
        runtimeUninstallCalled = true;
        return new Response(
          JSON.stringify({
            schema: "t4l_setup_operation.v2",
            operationId: "op_runtimeuninstall1",
            action: "uninstall",
            status: "uninstalled",
            terminal: true,
          }),
          { status: 202, headers: { "content-type": "application/json" } },
        );
      },
    }).execute({
      schema: "t4l_host_install_request.v1",
      action: "uninstall",
      operationId: "op_uninstall12345",
      agentId: "coach-01",
      agentName: "Coach",
      profile: "coach-01",
      root,
      homeDir: join(scratch, "home", "coach-01"),
      serviceHomeDir: join(scratch, "service-home"),
      stateDir,
      configPath: join(stateDir, "custom.json"),
      pluginDir: new URL("..", import.meta.url).pathname,
      releasePolicyPath: join(scratch, "policy.json"),
      ownerIdentity: "slack:default:u123",
      openclawExecutable: process.execPath,
      pythonExecutable: process.execPath,
      serviceMode: "none",
      port: 19001,
    });
    assert.equal(result.ok, true);
    assert.equal(runtimeUninstallCalled, true);
    assert.equal(await readFile(join(stateDir, ".env"), "utf8"), "KEEP_ME=yes\n");
    await assert.rejects(() => readFile(join(root, "installed.json")), /ENOENT/);
    assert.equal((await readFile(join(root, "bootstrap", "operations", "op_uninstall12345.json"), "utf8")).includes("completed"), true);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});

test("a host failure after runtime uninstall reapplies the old runtime", async () => {
  const scratch = await mkdtemp(join(tmpdir(), "t4l-uninstall-rollback-"));
  const root = join(scratch, "state", "coach-01");
  const stateDir = join(scratch, "openclaw", "coach-01");
  const releaseDir = join(root, "releases", "old-release");
  const installed = { schema: "t4l_host_install_state.v1", agentId: "coach-01" };
  try {
    await mkdir(releaseDir, { recursive: true });
    await mkdir(stateDir, { recursive: true });
    await writeFile(join(root, "service-command.json"), "{}\n");
    await writeFile(
      join(root, "secrets.env"),
      "T4L_CONNECTOR_RUNTIME_TOKEN=runtime\nT4L_SERVER_API_KEY=secret\n",
    );
    await writeFile(join(root, "installed.json"), JSON.stringify(installed));
    await writeFile(
      join(stateDir, ".env"),
      "KEEP_ME=yes\nT4L_CONNECTOR_RUNTIME_TOKEN=runtime\nMCP_T4L_API_KEY=secret\n",
    );
    await symlink(releaseDir, join(root, "current"));
    const actions = [];
    const installer = new HostInstaller({
      platform: "linux",
      hostMutationHook: async (stage) => {
        assert.equal(stage, "runtime-uninstalled");
        throw new Error("injected host cleanup failure");
      },
      fetchImpl: async (url, init) => {
        assert.match(String(url), /\/v1\/setup\/runtime-action$/);
        const action = JSON.parse(init.body).action;
        actions.push(action);
        return new Response(
          JSON.stringify({
            schema: "t4l_setup_operation.v2",
            operationId: `op_runtime${action}1234`,
            action,
            status: action === "uninstall" ? "uninstalled" : "ready",
            terminal: true,
          }),
          { status: 202, headers: { "content-type": "application/json" } },
        );
      },
    });
    await assert.rejects(
      () => installer.execute({
        schema: "t4l_host_install_request.v1",
        action: "uninstall",
        operationId: "op_uninstallrollback1",
        agentId: "coach-01",
        agentName: "Coach",
        profile: "coach-01",
        root,
        homeDir: join(scratch, "home", "coach-01"),
        serviceHomeDir: join(scratch, "service-home"),
        stateDir,
        configPath: join(stateDir, "custom.json"),
        pluginDir: new URL("..", import.meta.url).pathname,
        releasePolicyPath: join(scratch, "policy.json"),
        ownerIdentity: "slack:default:u123",
        openclawExecutable: process.execPath,
        pythonExecutable: process.execPath,
        serviceMode: "none",
        port: 19001,
      }),
      /injected host cleanup failure/,
    );
    assert.deepEqual(actions, ["uninstall", "update", "verify"]);
    assert.deepEqual(
      JSON.parse(await readFile(join(root, "installed.json"), "utf8")),
      installed,
    );
    assert.equal(await readlink(join(root, "current")), releaseDir);
    assert.match(await readFile(stateDir + "/.env", "utf8"), /KEEP_ME=yes/);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});
