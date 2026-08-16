import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { test } from "node:test";

import {
  createT4LConnectPlugin,
  resolveRuntimeIdentity,
  stablePort,
} from "../dist/index.js";
import {
  BootstrapPairingStore,
  acquireLock,
  resolveAgentId,
  resolveStateRoot,
} from "../dist/bootstrap.js";

function responseRecorder() {
  return {
    headers: {},
    chunks: [],
    setHeader(name, value) {
      this.headers[name] = value;
    },
    write(value) {
      this.chunks.push(Buffer.from(value));
    },
    end(value) {
      if (value) this.chunks.push(Buffer.from(value));
      this.ended = true;
    },
    json() {
      return JSON.parse(Buffer.concat(this.chunks).toString("utf8"));
    },
  };
}

function request(method, url, body = null, headers = {}) {
  const stream = Readable.from(body === null ? [] : [Buffer.from(JSON.stringify(body))]);
  stream.method = method;
  stream.url = url;
  stream.headers = { host: "coach.example.test", ...headers };
  stream.socket = { encrypted: true, remoteAddress: "203.0.113.8" };
  return stream;
}

function register(
  root,
  fetchImpl,
  spawnImpl = () => ({ unref() {} }),
  pluginConfig = {},
) {
  const routes = new Map();
  let command;
  createT4LConnectPlugin(fetchImpl, { spawnImpl }).register({
    pluginConfig: { agentId: "coach-01", installRoot: root, ...pluginConfig },
    registerCommand(value) {
      command = value;
    },
    registerHttpRoute(value) {
      routes.set(`${value.match}:${value.path}`, value.handler);
    },
  });
  return { command, routes };
}

test("preinstall discovery and pairing use the final connector contract", async () => {
  const root = await mkdtemp(join(tmpdir(), "t4l-bootstrap-test-"));
  try {
    const { routes } = register(root, async () => {
      throw new Error("connector is not installed");
    });
    const discoveryResponse = responseRecorder();
    await routes.get("exact:/.well-known/t4l-agent")(
      request("GET", "/.well-known/t4l-agent"),
      discoveryResponse,
    );
    const discovery = discoveryResponse.json();
    assert.equal(discovery.schema, "t4l_agent_bootstrap.v1");
    assert.equal(discovery.agentId, "coach-01");
    assert.equal(discovery.connectorInstalled, false);
    assert.ok(discovery.capabilities.includes("bootstrap-pairing-adoption"));
    assert.ok(
      discovery.capabilities.includes("nutrition-guidance-block-v1"),
    );
    assert.equal(routes.has("exact:/health"), false);

    const publicKey = Buffer.alloc(32, 7).toString("base64url");
    const pairingResponse = responseRecorder();
    await routes.get("exact:/v1/pairing/requests")(
      request("POST", "/v1/pairing/requests", {
        devicePublicKey: publicKey,
        deviceName: "iPhone",
        platform: "ios",
      }),
      pairingResponse,
    );
    const pairing = pairingResponse.json();
    assert.equal(pairingResponse.statusCode, 201);
    assert.match(pairing.code, /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    assert.equal(
      pairing.deviceId,
      `dev_${createHash("sha256").update(publicKey).digest("hex").slice(0, 24)}`,
    );
    assert.equal(Buffer.from(pairing.challenge, "base64url").length, 32);
    const identity = JSON.parse(
      await readFile(join(root, "bootstrap", "identity.json"), "utf8"),
    );
    assert.equal(identity.schema, "t4l_bootstrap_root_identity.v2");
    assert.match(identity.rootIdentity, /^[a-f0-9]{64}$/);
    assert.match(identity.serviceId, /^coach-01-[a-f0-9]{12}$/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a second phone cannot supersede the active public pairing", async () => {
  const root = await mkdtemp(join(tmpdir(), "t4l-bootstrap-active-"));
  try {
    const { routes } = register(root, async () => {
      throw new Error("not installed");
    });
    const create = routes.get("exact:/v1/pairing/requests");
    const first = responseRecorder();
    await create(
      request("POST", "/v1/pairing/requests", {
        devicePublicKey: Buffer.alloc(32, 1).toString("base64url"),
        deviceName: "First phone",
        platform: "ios",
      }),
      first,
    );
    assert.equal(first.statusCode, 201);
    const second = responseRecorder();
    await create(
      request("POST", "/v1/pairing/requests", {
        devicePublicKey: Buffer.alloc(32, 2).toString("base64url"),
        deviceName: "Other phone",
        platform: "ios",
      }),
      second,
    );
    assert.equal(second.statusCode, 409);
    assert.equal(second.json().error.code, "pairing_in_progress");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("five wrong owner codes persistently lock the active request", async () => {
  const root = await mkdtemp(join(tmpdir(), "t4l-bootstrap-lock-"));
  const previousHome = process.env.HOME;
  const previousState = process.env.OPENCLAW_STATE_DIR;
  process.env.HOME = root;
  process.env.OPENCLAW_STATE_DIR = join(root, "openclaw-state");
  try {
    const { routes, command } = register(root, async () => {
      throw new Error("not installed");
    });
    const publicKey = Buffer.alloc(32, 9).toString("base64url");
    const response = responseRecorder();
    await routes.get("exact:/v1/pairing/requests")(
      request("POST", "/v1/pairing/requests", {
        devicePublicKey: publicKey,
        deviceName: "iPhone",
        platform: "ios",
      }),
      response,
    );
    const pairing = response.json();
    const owner = {
      agentId: "coach-01",
      senderId: "U123",
      channel: "slack",
      accountId: "default",
      isAuthorizedSender: true,
      senderIsOwner: true,
    };
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const result = await command.handler({ ...owner, args: "connect ZZZZ-ZZZZ" });
      assert.match(result.text, /invalid or expired/i);
    }
    const locked = await command.handler({ ...owner, args: `connect ${pairing.code}` });
    assert.match(locked.text, /locked/i);
    const saved = JSON.parse(
      await readFile(join(root, "bootstrap", "pairings", `${pairing.requestId}.json`), "utf8"),
    );
    assert.equal(saved.failedAttempts, 5);
    assert.equal(saved.status, "locked");
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousState === undefined) delete process.env.OPENCLAW_STATE_DIR;
    else process.env.OPENCLAW_STATE_DIR = previousState;
    await rm(root, { recursive: true, force: true });
  }
});

test("installed proxy forwards phone authorization and exact path", async () => {
  const root = await mkdtemp(join(tmpdir(), "t4l-bootstrap-proxy-"));
  try {
    const identity = resolveRuntimeIdentity(root, "coach-01");
    const releaseDir = join(root, "releases", "release-01");
    const manifestSha256 = "a".repeat(64);
    await mkdir(releaseDir, { recursive: true });
    await writeFile(join(releaseDir, "release.json"), JSON.stringify({
      schema: "t4l_installed_release.v1",
      releaseId: "release-01",
      version: "0.3.0",
      manifestSha256,
    }));
    await symlink(releaseDir, join(root, "current"));
    await writeFile(join(root, "installed.json"), JSON.stringify({
      schema: "t4l_host_install_state.v1",
      agentId: "coach-01",
      profile: "default",
      serviceId: identity.serviceId,
      rootIdentity: identity.rootIdentity,
      port: 19111,
      releaseDir,
      releaseId: "release-01",
      version: "0.3.0",
      manifestSha256,
    }));
    const captured = [];
    const { routes } = register(root, async (url, init) => {
      captured.push({ url, init });
      if (url.endsWith("/.well-known/t4l-agent")) {
        return new Response(JSON.stringify({
          agentId: "coach-01",
          installation: {
            targetRelease: {
              releaseId: "release-01",
              version: "0.3.0",
              manifestSha256,
            },
          },
        }), { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({ status: "connected" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const res = responseRecorder();
    await routes.get("exact:/v1/session")(
      request("GET", "/v1/session", null, {
        authorization: "Bearer phone-token",
        "x-t4l-device-id": "dev_123",
      }),
      res,
    );
    const externalProxy = captured.at(-1);
    assert.equal(externalProxy.url, "http://127.0.0.1:19111/v1/session");
    assert.equal(externalProxy.init.headers.authorization, "Bearer phone-token");
    assert.equal(externalProxy.init.headers["x-t4l-device-id"], "dev_123");
    assert.equal(externalProxy.init.headers["x-forwarded-proto"], "https");
    assert.equal(externalProxy.init.headers["x-forwarded-host"], "coach.example.test");
    assert.equal(res.statusCode, 200);

    const local = request("GET", "/v1/session", null, {
      authorization: "Bearer phone-token",
      host: "127.0.0.1:18787",
    });
    local.socket = { encrypted: false, remoteAddress: "127.0.0.1" };
    await routes.get("exact:/v1/session")(local, responseRecorder());
    const localProxy = captured.at(-1);
    assert.equal(localProxy.init.headers["x-forwarded-proto"], "http");
    assert.equal(localProxy.init.headers["x-forwarded-host"], "127.0.0.1:18787");

    const insecure = request("GET", "/v1/session", null, {
      authorization: "Bearer phone-token",
    });
    insecure.socket = { encrypted: false, remoteAddress: "203.0.113.8" };
    const rejected = responseRecorder();
    await routes.get("exact:/v1/session")(insecure, rejected);
    assert.equal(rejected.statusCode, 403);
    assert.equal(rejected.json().error.code, "https_required");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("default state roots are profile-isolated and stale locks recover", async () => {
  const home = await mkdtemp(join(tmpdir(), "t4l-bootstrap-home-"));
  const previous = {
    HOME: process.env.HOME,
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
    OPENCLAW_PROFILE: process.env.OPENCLAW_PROFILE,
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
  };
  try {
    process.env.HOME = home;
    delete process.env.OPENCLAW_HOME;
    process.env.OPENCLAW_PROFILE = "coach-a";
    delete process.env.OPENCLAW_STATE_DIR;
    assert.equal(
      resolveStateRoot({}, "coach-01"),
      join(home, ".openclaw-coach-a", "t4l", "coach-01"),
    );
    process.env.OPENCLAW_HOME = join(home, "runtime-home");
    assert.equal(
      resolveStateRoot({}, "coach-01"),
      join(home, "runtime-home", ".openclaw-coach-a", "t4l", "coach-01"),
    );
    const lockPath = join(home, "state", "installer.lock");
    await mkdir(join(home, "state"), { recursive: true });
    await writeFile(lockPath, "99999999\n");
    const release = await acquireLock(lockPath);
    await release();
    await assert.rejects(() => readFile(lockPath), /ENOENT/);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await rm(home, { recursive: true, force: true });
  }
});

test("a stock OpenClaw config resolves the native main agent", () => {
  assert.equal(
    resolveAgentId({ config: { agents: { defaults: { model: "customer/model" } } } }, {}),
    "main",
  );
  assert.equal(
    resolveAgentId({ config: { agents: { entries: { atlas: {} } } } }, {}),
    "atlas",
  );
  assert.throws(
    () => resolveAgentId({ config: { agents: { entries: { one: {}, two: {} } } } }, {}),
    /multiple OpenClaw agents/,
  );
  assert.equal(
    resolveAgentId({ config: { agents: { list: [{ id: "legacy" }] } } }, {}),
    "legacy",
  );
});

test("automatic ports isolate agents across the full high-port range", () => {
  const root = "/srv/openclaw/.openclaw/t4l";
  const first = stablePort("coach-01", `${root}/coach-01`);
  const second = stablePort("coach-02", `${root}/coach-02`);
  assert.ok(first >= 20000 && first < 60000);
  assert.ok(second >= 20000 && second < 60000);
  assert.notEqual(first, second);
});

test("three OpenClaw profiles with implicit main get distinct roots and services", async () => {
  const home = await mkdtemp(join(tmpdir(), "t4l-bootstrap-three-profiles-"));
  const previous = {
    HOME: process.env.HOME,
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
    OPENCLAW_PROFILE: process.env.OPENCLAW_PROFILE,
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
    OPENCLAW_CONFIG_PATH: process.env.OPENCLAW_CONFIG_PATH,
  };
  try {
    process.env.HOME = home;
    delete process.env.OPENCLAW_HOME;
    delete process.env.OPENCLAW_STATE_DIR;
    delete process.env.OPENCLAW_CONFIG_PATH;
    const identities = [];
    for (const profile of ["one", "two", "three"]) {
      process.env.OPENCLAW_PROFILE = profile;
      const root = resolveStateRoot({}, "main");
      identities.push(resolveRuntimeIdentity(root, "main"));
    }
    assert.equal(new Set(identities.map((item) => item.root)).size, 3);
    assert.equal(new Set(identities.map((item) => item.rootIdentity)).size, 3);
    assert.equal(new Set(identities.map((item) => item.serviceId)).size, 3);
    assert.ok(identities.every((item) => item.serviceId.startsWith("main-")));
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await rm(home, { recursive: true, force: true });
  }
});

test("custom agent IDs keep the actual default OpenClaw profile", async () => {
  const root = await mkdtemp(join(tmpdir(), "t4l-bootstrap-profile-"));
  const previous = {
    HOME: process.env.HOME,
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
    OPENCLAW_PROFILE: process.env.OPENCLAW_PROFILE,
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
    OPENCLAW_CONFIG_PATH: process.env.OPENCLAW_CONFIG_PATH,
  };
  try {
    process.env.HOME = root;
    process.env.OPENCLAW_HOME = join(root, "runtime-home");
    delete process.env.OPENCLAW_PROFILE;
    delete process.env.OPENCLAW_STATE_DIR;
    process.env.OPENCLAW_CONFIG_PATH = join(root, "runtime-config", "coach.json");
    let requestPath;
    let spawnCount = 0;
    const { routes, command } = register(
      join(root, "install", "coach-01"),
      async () => {
        throw new Error("not installed");
      },
      (_executable, argv) => {
        spawnCount += 1;
        requestPath = argv.at(-1);
        return { unref() {} };
      },
      { openclawExecutable: process.execPath, pythonExecutable: process.execPath },
    );
    const pairingResponse = responseRecorder();
    await routes.get("exact:/v1/pairing/requests")(
      request("POST", "/v1/pairing/requests", {
        devicePublicKey: Buffer.alloc(32, 4).toString("base64url"),
        deviceName: "iPhone",
        platform: "ios",
      }),
      pairingResponse,
    );
    const result = await command.handler({
      agentId: "coach-01",
      args: `connect ${pairingResponse.json().code}`,
      senderId: "U123",
      channel: "slack",
      accountId: "default",
      isAuthorizedSender: true,
      senderIsOwner: true,
    });
    assert.match(result.text, /installation started/i);
    const host = JSON.parse(await readFile(requestPath, "utf8"));
    assert.equal(host.profile, "default");
    assert.equal(host.homeDir, join(root, "runtime-home"));
    assert.equal(host.serviceHomeDir, root);
    assert.equal(host.stateDir, join(root, "runtime-home", ".openclaw"));
    assert.equal(host.configPath, join(root, "runtime-config", "coach.json"));
    assert.equal(host.openclawExecutable, process.execPath);
    assert.equal(host.nodeExecutable, process.execPath);
    assert.match(host.serviceId, /^coach-01-[a-f0-9]{12}$/);
    assert.match(host.rootIdentity, /^[a-f0-9]{64}$/);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await command.handler({
        agentId: "coach-01",
        args: `connect ${pairingResponse.json().code}`,
        senderId: "attacker",
        channel: "slack",
        accountId: "default",
        isAuthorizedSender: true,
        senderIsOwner: false,
      });
    }
    const duplicate = await command.handler({
      agentId: "coach-01",
      args: `connect ${pairingResponse.json().code}`,
      senderId: "U123",
      channel: "slack",
      accountId: "default",
      isAuthorizedSender: true,
      senderIsOwner: true,
    });
    assert.match(duplicate.text, /already running/i);
    assert.equal(spawnCount, 1);
    const retryResponse = responseRecorder();
    await routes.get("exact:/v1/pairing/requests")(
      request("POST", "/v1/pairing/requests", {
        devicePublicKey: Buffer.alloc(32, 4).toString("base64url"),
        deviceName: "iPhone",
        platform: "ios",
      }),
      retryResponse,
    );
    const retry = retryResponse.json();
    assert.equal(retry.requestId, pairingResponse.json().requestId);
    assert.equal(retry.status, "installing");

    const retryStore = new BootstrapPairingStore(
      join(root, "install", "coach-01"),
      "coach-01",
      () => Date.now(),
      resolveRuntimeIdentity(join(root, "install", "coach-01"), "coach-01"),
    );
    const failedRecord = await retryStore.find(retry.requestId);
    await retryStore.mark(failedRecord, "failed", {
      error: "ensurepip unavailable",
      expiresAt: new Date(Date.now() - 1_000).toISOString(),
    });
    await writeFile(
      join(
        root,
        "install",
        "coach-01",
        "bootstrap",
        "operations",
        `${host.operationId}.json`,
      ),
      JSON.stringify({
        schema: "t4l_host_install_operation.v1",
        operationId: host.operationId,
        action: "install",
        agentId: "coach-01",
        status: "failed",
        stage: "rolled-back",
      }),
    );
    const failedCompletion = responseRecorder();
    await routes.get("exact:/v1/pairing/complete")(
      request("POST", "/v1/pairing/complete", {
        requestId: retry.requestId,
        devicePublicKey: Buffer.alloc(32, 4).toString("base64url"),
        challengeSignature: Buffer.alloc(64, 7).toString("base64url"),
      }),
      failedCompletion,
    );
    assert.equal(failedCompletion.statusCode, 503);
    assert.equal(failedCompletion.json().error.retryable, true);
    assert.equal(failedCompletion.json().bootstrap.operationId, host.operationId);
    const reusedResponse = responseRecorder();
    await routes.get("exact:/v1/pairing/requests")(
      request("POST", "/v1/pairing/requests", {
        devicePublicKey: Buffer.alloc(32, 4).toString("base64url"),
        deviceName: "iPhone",
        platform: "ios",
      }),
      reusedResponse,
    );
    assert.equal(reusedResponse.json().code, pairingResponse.json().code);
    assert.equal(reusedResponse.json().status, "failed");

    const resumed = await command.handler({
      agentId: "coach-01",
      args: `connect ${pairingResponse.json().code}`,
      senderId: "U123",
      channel: "slack",
      accountId: "default",
      isAuthorizedSender: true,
      senderIsOwner: true,
    });
    assert.match(resumed.text, /retry started with the same phone pairing/i);
    assert.equal(spawnCount, 2);
    assert.equal(await retryStore.find(retry.requestId).then((item) => item.status), "installing");
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("plugin startup resumes a persisted installing request", async () => {
  const root = await mkdtemp(join(tmpdir(), "t4l-bootstrap-resume-"));
  try {
    const store = new BootstrapPairingStore(root, "coach-01");
    const created = await store.create({
      devicePublicKey: Buffer.alloc(32, 3).toString("base64url"),
      deviceName: "iPhone",
      platform: "ios",
    });
    const record = await store.find(created.requestId);
    const operationId = "op_resume123456";
    await store.confirm(
      record,
      { channel: "slack", accountId: "default", senderId: "U123" },
      operationId,
    );
    const requestPath = join(root, "bootstrap", "operations", `${operationId}.request.json`);
    await mkdir(join(root, "bootstrap", "operations"), { recursive: true });
    await writeFile(requestPath, JSON.stringify({ action: "install" }));
    const spawns = [];
    register(root, async () => {
      throw new Error("not installed");
    }, (_executable, argv) => {
      spawns.push(argv);
      return { unref() {} };
    });
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
    assert.equal(spawns.length, 1);
    assert.equal(spawns[0].at(-1), requestPath);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("duplicate lifecycle commands reuse one queued operation", async () => {
  const root = await mkdtemp(join(tmpdir(), "t4l-bootstrap-lifecycle-"));
  const previous = {
    HOME: process.env.HOME,
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
  };
  try {
    process.env.HOME = root;
    process.env.OPENCLAW_STATE_DIR = join(root, "openclaw-state");
    const identity = resolveRuntimeIdentity(root, "coach-01");
    const releaseDir = join(root, "releases", "release-01");
    const manifestSha256 = "b".repeat(64);
    await mkdir(releaseDir, { recursive: true });
    await writeFile(join(releaseDir, "release.json"), JSON.stringify({
      schema: "t4l_installed_release.v1",
      releaseId: "release-01",
      version: "0.3.0",
      manifestSha256,
    }));
    await symlink(releaseDir, join(root, "current"));
    await writeFile(join(root, "installed.json"), JSON.stringify({
      schema: "t4l_host_install_state.v1",
      agentId: "coach-01",
      profile: "default",
      serviceId: identity.serviceId,
      rootIdentity: identity.rootIdentity,
      port: 19111,
      releaseDir,
      releaseId: "release-01",
      version: "0.3.0",
      manifestSha256,
    }));
    const spawns = [];
    const { command } = register(
      root,
      async () => {
        throw new Error("not needed");
      },
      (_executable, argv) => {
        spawns.push(argv);
        return { unref() {} };
      },
      { openclawExecutable: process.execPath, pythonExecutable: process.execPath },
    );
    const owner = {
      agentId: "coach-01",
      args: "verify",
      senderId: "U123",
      channel: "slack",
      accountId: "default",
      isAuthorizedSender: true,
      senderIsOwner: true,
    };
    const [first, second] = await Promise.all([
      command.handler(owner),
      command.handler(owner),
    ]);
    assert.equal(spawns.length, 1);
    assert.deepEqual(
      [first.text, second.text].map((value) => /already running/i.test(value)).sort(),
      [false, true],
    );
    assert.match(first.text, /op_[A-Za-z0-9_-]+/);
    assert.match(second.text, /op_[A-Za-z0-9_-]+/);
    assert.equal(first.text.match(/op_[A-Za-z0-9_-]+/)?.[0], second.text.match(/op_[A-Za-z0-9_-]+/)?.[0]);
    const conflicting = await command.handler({ ...owner, args: "update" });
    assert.match(conflicting.text, /could not start/i);
    assert.equal(spawns.length, 1);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await rm(root, { recursive: true, force: true });
  }
});
