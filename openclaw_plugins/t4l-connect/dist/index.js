import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, lstat, readFile, readdir, readlink, realpath, stat } from "node:fs/promises";
import { createServer } from "node:net";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BootstrapPairingStore,
  acquireLock,
  atomicJson,
  bootstrapDiscovery,
  resolveAgentId,
  resolveStateRoot,
} from "./bootstrap.js";
import { readOperation } from "./installer.js";

const CODE_RE = /^[A-Za-z0-9-]{4,64}$/;
const MAX_BODY_BYTES = 32 * 1024 * 1024;
const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EXACT_ROUTES = [
  "/.well-known/t4l-agent",
  "/manifest",
  "/v1/session",
  "/v1/pairing/requests",
  "/v1/pairing/complete",
  "/v1/setup/apply",
  "/v1/chat/messages",
  "/v1/chat/onboarding",
  "/v1/results/pending",
  "/v1/requests/pending",
  "/v1/app/snapshot",
  "/v1/profile",
  "/v1/context/day",
  "/v1/context/daily-snapshot",
  "/v2/manifest",
  "/v2/context/latest",
  "/v2/context/bundle",
  "/v2/results/pending",
];
const PREFIX_ROUTES = [
  "/v1/operations/",
  "/v1/devices/",
  "/v1/results/",
  "/v1/requests/",
  "/v1/blobs/meal-images/",
  "/v2/results/",
];

function text(message) {
  return { text: message };
}

function isLoopbackBaseUrl(value) {
  try {
    const url = new URL(value);
    const host = url.hostname.replace(/^\[|\]$/g, "");
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      (host === "localhost" || host === "::1" || /^127(?:\.\d{1,3}){3}$/.test(host)) &&
      (url.pathname === "/" || url.pathname === "") &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash
    );
  } catch {
    return false;
  }
}

function commandArgs(ctx) {
  if (typeof ctx?.args === "string") return ctx.args.trim();
  if (Array.isArray(ctx?.args)) return ctx.args.join(" ").trim();
  return "";
}

function identityValue(ctx, key, lower = false) {
  const value = ctx?.[key];
  if (typeof value !== "string") return "";
  const normalized = value.trim();
  return lower ? normalized.toLowerCase() : normalized;
}

function verifiedOwner(ctx) {
  const channel = identityValue(ctx, "channel", true);
  let senderId = identityValue(ctx, "senderId");
  let accountId = identityValue(ctx, "accountId");
  const scopes = Array.isArray(ctx?.gatewayClientScopes)
    ? ctx.gatewayClientScopes.filter((item) => typeof item === "string")
    : [];
  if (
    channel === "webchat" &&
    (!senderId || !accountId) &&
    ctx?.isAuthorizedSender === true &&
    ctx?.senderIsOwner === true &&
    (scopes.includes("operator.admin") || scopes.includes("operator.pairing"))
  ) {
    accountId = "gateway";
    senderId = "operator-admin";
  }
  const owner = { senderId, channel, accountId };
  if (
    !owner.senderId ||
    !owner.channel ||
    !owner.accountId ||
    owner.channel.includes(":") ||
    owner.accountId.includes(":") ||
    owner.senderId.includes(":") ||
    /[\r\n\0]/.test(`${owner.channel}${owner.accountId}${owner.senderId}`)
  ) {
    return null;
  }
  return owner;
}

function jsonResponse(res, status, payload, headers = {}) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  for (const [key, value] of Object.entries(headers)) res.setHeader(key, value);
  res.end(`${JSON.stringify(payload)}\n`);
  return true;
}

function errorResponse(res, status, code, message) {
  return jsonResponse(res, status, { error: { code, message } });
}

async function readBody(req, maximum = MAX_BODY_BYTES) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximum) throw new Error("request body is too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function externalScheme(req) {
  const forwarded = String(req.headers?.["x-forwarded-proto"] || "")
    .split(",", 1)[0]
    .trim()
    .toLowerCase();
  if (req.socket?.encrypted === true) return "https";
  const peer = String(req.socket?.remoteAddress || "").replace(/^::ffff:/, "");
  if (forwarded === "https" && (peer === "127.0.0.1" || peer === "::1")) return "https";
  return "http";
}

function secureTransport(req) {
  if (externalScheme(req) === "https") return true;
  const peer = String(req.socket?.remoteAddress || "").replace(/^::ffff:/, "");
  const host = String(req.headers?.host || "").split(":", 1)[0].replace(/^\[|\]$/g, "");
  return (
    (peer === "127.0.0.1" || peer === "::1") &&
    (host === "localhost" || host === "127.0.0.1" || host === "::1")
  );
}

function safeProxyHeaders(req) {
  const headers = {};
  for (const [name, raw] of Object.entries(req.headers || {})) {
    const key = name.toLowerCase();
    if (key === "authorization" || key === "content-type" || key === "accept" || key === "last-event-id" || key.startsWith("x-t4l-")) {
      headers[key] = Array.isArray(raw) ? raw.join(",") : String(raw);
    }
  }
  const rawHost = String(req.headers?.host || "").trim();
  if (!rawHost || /[\0-\x20\x7f/@\\]/.test(rawHost)) {
    throw new Error("external Gateway authority is invalid");
  }
  const external = new URL(`http://${rawHost}`);
  if (external.username || external.password || external.pathname !== "/") {
    throw new Error("external Gateway authority is invalid");
  }
  headers["x-forwarded-host"] = external.host;
  headers["x-forwarded-proto"] = externalScheme(req);
  return headers;
}

export function stablePort(agentId, stateRoot, configured) {
  if (Number.isInteger(configured) && configured >= 1024 && configured <= 65535) return configured;
  const digest = createHash("sha256").update(`${stateRoot}\0${agentId}`).digest();
  return 20000 + (digest.readUInt16BE(0) % 40000);
}

export function resolveRuntimeIdentity(root, agentId) {
  const serviceHomeDir = process.env.HOME;
  const homeDir = process.env.OPENCLAW_HOME || serviceHomeDir;
  const profile = process.env.OPENCLAW_PROFILE || "default";
  const stateDir =
    process.env.OPENCLAW_STATE_DIR ||
    (homeDir && isAbsolute(homeDir)
      ? join(homeDir, profile !== "default" ? `.openclaw-${profile}` : ".openclaw")
      : "");
  const configPath = process.env.OPENCLAW_CONFIG_PATH || join(stateDir, "openclaw.json");
  if (
    !/^[a-z][a-z0-9_-]{0,63}$/.test(profile) ||
    !stateDir ||
    !isAbsolute(stateDir) ||
    !configPath ||
    !isAbsolute(configPath) ||
    !homeDir ||
    !isAbsolute(homeDir) ||
    resolve(homeDir) === "/" ||
    !serviceHomeDir ||
    !isAbsolute(serviceHomeDir) ||
    resolve(serviceHomeDir) === "/"
  ) {
    throw new Error("OpenClaw profile, home, state, and config paths must be safe and absolute");
  }
  const normalizedRoot = resolve(root);
  const normalizedState = resolve(stateDir);
  const normalizedConfig = resolve(configPath);
  const rootIdentity = createHash("sha256")
    .update(
      [
        "t4l-bootstrap-root.v2",
        profile,
        agentId,
        normalizedRoot,
        normalizedState,
        normalizedConfig,
      ].join("\0"),
    )
    .digest("hex");
  const serviceId = `${agentId.slice(0, 40)}-${rootIdentity.slice(0, 12)}`;
  return {
    schema: "t4l_bootstrap_runtime_identity.v1",
    agentId,
    profile,
    root: normalizedRoot,
    rootIdentity,
    serviceId,
    homeDir: resolve(homeDir),
    serviceHomeDir: resolve(serviceHomeDir),
    stateDir: normalizedState,
    configPath: normalizedConfig,
  };
}

async function portAvailable(port) {
  return new Promise((resolvePromise) => {
    const server = createServer();
    server.unref();
    server.once("error", () => resolvePromise(false));
    server.listen({ host: "127.0.0.1", port, exclusive: true }, () => {
      server.close(() => resolvePromise(true));
    });
  });
}

async function selectConnectorPort(agentId, root, configured) {
  const initial = stablePort(agentId, root, configured);
  if (Number.isInteger(configured)) {
    if (!(await portAvailable(initial))) {
      throw new Error(`configured T4L connector port ${initial} is already in use`);
    }
    return initial;
  }
  for (let offset = 0; offset < 128; offset += 1) {
    const candidate = 20000 + ((initial - 20000 + offset) % 40000);
    if (await portAvailable(candidate)) return candidate;
  }
  throw new Error("no isolated T4L connector port is available");
}

async function resolveExecutable(value, name) {
  if (typeof value !== "string" || !value || /[\0-\x1f\x7f]/.test(value)) {
    throw new Error(`${name} executable is invalid`);
  }
  const candidates = isAbsolute(value)
    ? [value]
    : value.includes("/")
      ? []
      : String(process.env.PATH || "")
          .split(delimiter)
          .filter((entry) => isAbsolute(entry))
          .map((entry) => join(entry, value));
  for (const candidate of candidates) {
    try {
      const resolved = await realpath(candidate);
      const info = await stat(resolved);
      await access(resolved, fsConstants.X_OK);
      if (info.isFile()) return resolved;
    } catch {}
  }
  throw new Error(`${name} executable could not be resolved to an absolute file`);
}

async function readInstalledState(root, agentId, identity) {
  try {
    const markerPath = join(root, "installed.json");
    const markerInfo = await lstat(markerPath);
    if (markerInfo.isSymbolicLink() || !markerInfo.isFile()) return null;
    const installed = JSON.parse(await readFile(markerPath, "utf8"));
    const releaseDir = resolve(String(installed.releaseDir || ""));
    if (
      installed.schema !== "t4l_host_install_state.v1" ||
      installed.agentId !== agentId ||
      installed.profile !== identity.profile ||
      installed.serviceId !== identity.serviceId ||
      !Number.isInteger(installed.port) ||
      installed.port < 1024 ||
      installed.port > 65535 ||
      typeof installed.releaseId !== "string" ||
      typeof installed.version !== "string" ||
      !/^[a-f0-9]{64}$/.test(String(installed.manifestSha256 || "")) ||
      !releaseDir.startsWith(`${resolve(root, "releases")}/`) ||
      resolve(await readlink(join(root, "current"))) !== releaseDir
    ) {
      return null;
    }
    const release = JSON.parse(await readFile(join(releaseDir, "release.json"), "utf8"));
    if (
      release?.schema !== "t4l_installed_release.v1" ||
      release.releaseId !== installed.releaseId ||
      release.version !== installed.version ||
      release.manifestSha256 !== installed.manifestSha256
    ) {
      return null;
    }
    return { ...installed, releaseDir };
  } catch {
    return null;
  }
}

async function connectorBaseUrl(config, root, port, agentId, identity) {
  if (typeof config.connectorBaseUrl === "string" && isLoopbackBaseUrl(config.connectorBaseUrl)) {
    return config.connectorBaseUrl.replace(/\/$/, "");
  }
  try {
    const installed = await readInstalledState(root, agentId, identity);
    if (installed) return `http://127.0.0.1:${installed.port}`;
  } catch {}
  return `http://127.0.0.1:${port}`;
}

async function connectorReady(fetchImpl, base, agentId, installed = null) {
  try {
    const response = await fetchImpl(`${base}/.well-known/t4l-agent`, {
      signal: AbortSignal.timeout(1_500),
    });
    const payload = await response.json();
    const target = payload?.installation?.targetRelease;
    return (
      response.ok &&
      payload?.agentId === agentId &&
      (!installed ||
        (target?.releaseId === installed.releaseId &&
          target?.version === installed.version &&
          target?.manifestSha256 === installed.manifestSha256))
    );
  } catch {
    return false;
  }
}

async function proxyRequest(fetchImpl, base, req, res) {
  const url = new URL(req.url || "/", "http://gateway.invalid");
  const body = ["GET", "HEAD"].includes(String(req.method).toUpperCase())
    ? undefined
    : await readBody(req);
  const upstream = await fetchImpl(`${base}${url.pathname}${url.search}`, {
    method: req.method,
    headers: safeProxyHeaders(req),
    body: body?.length ? body : undefined,
    redirect: "manual",
    signal: AbortSignal.timeout(130_000),
  });
  res.statusCode = upstream.status;
  for (const name of ["content-type", "cache-control", "etag", "last-modified", "retry-after"]) {
    const value = upstream.headers.get(name);
    if (value) res.setHeader(name, value);
  }
  if (!upstream.body) {
    res.end();
    return true;
  }
  for await (const chunk of upstream.body) res.write(Buffer.from(chunk));
  res.end();
  return true;
}

async function hostRequest({ config, root, agentId, owner, record = null, operationId, port, action = "install" }) {
  const identity = resolveRuntimeIdentity(root, agentId);
  const releasePolicyPath =
    typeof config.releasePolicyPath === "string" && isAbsolute(config.releasePolicyPath)
      ? resolve(config.releasePolicyPath)
      : join(PLUGIN_ROOT, "release-policy.json");
  const openclawExecutable = await resolveExecutable(
    typeof config.openclawExecutable === "string" ? config.openclawExecutable : "openclaw",
    "OpenClaw",
  );
  const pythonExecutable = await resolveExecutable(
    typeof config.pythonExecutable === "string" ? config.pythonExecutable : "python3",
    "Python",
  );
  const nodeExecutable = await resolveExecutable(process.execPath, "Node");
  return {
    schema: "t4l_host_install_request.v1",
    action,
    operationId,
    agentId,
    serviceId: identity.serviceId,
    rootIdentity: identity.rootIdentity,
    agentName: typeof config.agentName === "string" ? config.agentName : "T4L Coach",
    profile: identity.profile,
    root,
    homeDir: identity.homeDir,
    serviceHomeDir: identity.serviceHomeDir,
    stateDir: identity.stateDir,
    configPath: identity.configPath,
    pluginDir: PLUGIN_ROOT,
    releasePolicyPath,
    ...(record
      ? { pairingFile: join(root, "bootstrap", "pairings", `${record.requestId}.json`) }
      : {}),
    ownerIdentity: `${owner.channel}:${owner.accountId}:${owner.senderId}`,
    openclawExecutable,
    nodeExecutable,
    pythonExecutable,
    serviceMode: typeof config.serviceMode === "string" ? config.serviceMode : "auto",
    port,
  };
}

function spawnInstaller(spawnImpl, requestPath, action = "install") {
  const cli = join(PLUGIN_ROOT, "bin", "t4l-bootstrap.mjs");
  const child = spawnImpl(process.execPath, [cli, action, requestPath], {
    cwd: PLUGIN_ROOT,
    detached: true,
    stdio: "ignore",
    shell: false,
    env: { ...process.env },
  });
  child.unref?.();
}

async function resumeInstallations(store, root, spawnImpl, registeredAt) {
  for (const record of await store.installingRecords()) {
    if (new Date(record.confirmedAt).getTime() > registeredAt) continue;
    const operation = await readOperation(root, record.operationId);
    if (operation && ["failed", "rolled_back"].includes(operation.status)) {
      await store.mark(record, "failed", {
        error: String(operation.error || "installation failed").slice(0, 300),
      });
      continue;
    }
    if (operation?.status === "completed") {
      const installed = await readFile(join(root, "installed.json"))
        .then(() => true)
        .catch(() => false);
      if (installed) continue;
    }
    const requestPath = join(
      root,
      "bootstrap",
      "operations",
      `${record.operationId}.request.json`,
    );
    try {
      await readFile(requestPath);
      spawnInstaller(spawnImpl, requestPath, "install");
    } catch {
      await store.mark(record, "failed", { error: "installer request is missing" });
    }
  }
}

async function resumeLifecycleOperations(root, spawnImpl) {
  const directory = join(root, "bootstrap", "operations");
  let names;
  try {
    names = await readdir(directory);
  } catch {
    return;
  }
  let resumed = false;
  for (const name of names.sort()) {
    const match = /^(op_[A-Za-z0-9_-]{8,128})\.request\.json$/.exec(name);
    if (!match) continue;
    try {
      const requestPath = join(directory, name);
      const request = JSON.parse(await readFile(requestPath, "utf8"));
      if (!["update", "verify", "uninstall"].includes(request.action)) continue;
      const operation = await readOperation(root, match[1]);
      if (operation && ["completed", "failed", "rolled_back"].includes(operation.status)) {
        continue;
      }
      if (resumed) {
        await atomicJson(join(directory, `${match[1]}.json`), {
          schema: "t4l_host_install_operation.v1",
          operationId: match[1],
          action: request.action,
          agentId: request.agentId,
          status: "failed",
          stage: "queue-conflict",
          error: "another T4L lifecycle operation was already queued",
          updatedAt: new Date().toISOString(),
        });
        continue;
      }
      resumed = true;
      spawnInstaller(spawnImpl, requestPath, request.action);
    } catch {
      // Corrupt request files fail closed and are not executed.
    }
  }
}

async function activeLifecycleOperation(root, agentId, action) {
  const directory = join(root, "bootstrap", "operations");
  let names = [];
  try {
    names = await readdir(directory);
  } catch {
    return null;
  }
  for (const name of names.sort().reverse()) {
    const match = /^(op_[A-Za-z0-9_-]{8,128})\.request\.json$/.exec(name);
    if (!match) continue;
    try {
      const request = JSON.parse(await readFile(join(directory, name), "utf8"));
      if (request.agentId !== agentId) continue;
      const operation = await readOperation(root, match[1]);
      if (!operation || !["completed", "failed", "rolled_back"].includes(operation.status)) {
        if (request.action === action) {
          return { operationId: match[1], requestPath: join(directory, name) };
        }
        return {
          operationId: match[1],
          requestPath: join(directory, name),
          conflictAction: request.action,
        };
      }
    } catch {
      // Invalid records are ignored and never executed.
    }
  }
  return null;
}

async function queueLifecycleOperation({ config, root, agentId, owner, port, action }) {
  let release = null;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      release = await acquireLock(join(root, "bootstrap", "lifecycle-queue.lock"));
      break;
    } catch (error) {
      if (
        !String(error?.message || error).includes("another T4L bootstrap operation") ||
        attempt === 199
      ) {
        throw error;
      }
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
    }
  }
  if (!release) throw new Error("T4L lifecycle queue lock could not be acquired");
  try {
    const active = await activeLifecycleOperation(root, agentId, action);
    if (active?.conflictAction) {
      const error = new Error(`T4L ${active.conflictAction} is already running`);
      error.code = "lifecycle_in_progress";
      throw error;
    }
    if (active) return { ...active, reused: true };
    const operationId = `op_${randomBytes(12).toString("base64url")}`;
    const request = await hostRequest({
      config,
      root,
      agentId,
      owner,
      operationId,
      port,
      action,
    });
    const directory = join(root, "bootstrap", "operations");
    const requestPath = join(directory, `${operationId}.request.json`);
    await atomicJson(requestPath, request);
    await atomicJson(join(directory, `${operationId}.json`), {
      schema: "t4l_host_install_operation.v1",
      operationId,
      action,
      agentId,
      status: "queued",
      stage: "queued",
      updatedAt: new Date().toISOString(),
    });
    return { operationId, requestPath, reused: false };
  } finally {
    await release();
  }
}

export function createT4LConnectPlugin(
  fetchImpl = globalThis.fetch,
  { spawnImpl = spawn, now = () => Date.now() } = {},
) {
  return {
    id: "t4l-connect",
    name: "T4L Connect",
    description: "Owner-gated T4L bootstrap and phone pairing.",
    register(api) {
      const config = { ...(api.pluginConfig ?? {}) };
      let agentId;
      let root;
      let runtimeIdentity;
      let store;
      let configError = null;
      try {
        agentId = resolveAgentId(api, config);
        root = resolveStateRoot(config, agentId);
        runtimeIdentity = resolveRuntimeIdentity(root, agentId);
        store = new BootstrapPairingStore(root, agentId, now, runtimeIdentity);
      } catch (error) {
        configError = String(error?.message || error);
      }
      let port = agentId && root ? stablePort(agentId, root, config.connectorPort) : null;
      const pairingCreates = [];
      let connectorReadyUntil = 0;
      let connectorReadyKey = "";
      if (store && root) {
        const registeredAt = now();
        queueMicrotask(() => {
          Promise.all([
            resumeInstallations(store, root, spawnImpl, registeredAt),
            resumeLifecycleOperations(root, spawnImpl),
          ]).catch((error) => {
            api?.logger?.error?.(`T4L bootstrap recovery failed: ${String(error?.message || error)}`);
          });
        });
      }

      api.registerCommand({
        name: "t4l",
        description: "Install or connect this verified coach to T4L Trainer.",
        acceptsArgs: true,
        requireAuth: true,
        requiredScopes: ["operator.pairing"],
        handler: async (ctx) => {
          if (configError || !agentId || !root || !store || !port) return text(configError || "T4L bootstrap configuration is invalid.");
          if (ctx?.agentId !== agentId) return text("This command belongs to a different T4L agent.");
          const args = commandArgs(ctx);
          const match = /^connect\s+([A-Za-z0-9-]{4,64})$/i.exec(args);
          const lifecycle = /^(update|verify|uninstall)$/i.exec(args);
          if ((!match || !CODE_RE.test(match[1])) && !lifecycle) {
            return text("Use /t4l connect CODE, /t4l update, /t4l verify, or /t4l uninstall.");
          }
          if (ctx?.isAuthorizedSender !== true || ctx?.senderIsOwner !== true) {
            return text("OpenClaw did not verify this sender as an owner.");
          }
          const owner = verifiedOwner(ctx);
          if (!owner) return text("OpenClaw did not provide a complete verified owner identity.");
          const pending = match ? await store.match(match[1]) : null;
          if (lifecycle) {
            const installed = await readInstalledState(root, agentId, runtimeIdentity);
            if (!installed) {
              return text("T4L is not installed for this agent.");
            }
            port = installed.port;
            const action = lifecycle[1].toLowerCase();
            try {
              const queued = await queueLifecycleOperation({
                config, root, agentId, owner, port, action,
              });
              if (!queued.reused) spawnInstaller(spawnImpl, queued.requestPath, action);
              return text(
                queued.reused
                  ? `T4L ${action} is already running as ${queued.operationId}.`
                  : `T4L ${action} started as ${queued.operationId}.`,
              );
            } catch {
              return text(`T4L ${action} could not start. Check the Gateway logs.`);
            }
          }
          if (pending?.status === "installing") {
            return text("T4L installation is already running for this phone.");
          }
          if (pending?.status === "locked") {
            return text("This pairing request is locked. Start again in the app.");
          }
          if (pending && pending.status !== "pending") {
            return text("This pairing request is no longer available. Start again in the app.");
          }
          const base = await connectorBaseUrl(
            config,
            root,
            port,
            agentId,
            runtimeIdentity,
          );
          const installedState = await readInstalledState(
            root,
            agentId,
            runtimeIdentity,
          );
          const explicitlyInstalled = isLoopbackBaseUrl(config.connectorBaseUrl) || installedState !== null;
          if (explicitlyInstalled || await connectorReady(fetchImpl, base, agentId, installedState)) {
            const runtimeToken = process.env.T4L_CONNECTOR_RUNTIME_TOKEN;
            if (!runtimeToken) return text("T4L runtime credential is missing on this gateway.");
            try {
              const response = await fetchImpl(`${base}/v1/pairing/channel-confirmation`, {
                method: "POST",
                headers: { "content-type": "application/json", "x-t4l-runtime-token": runtimeToken },
                body: JSON.stringify({
                  code: match[1],
                  channel: owner.channel,
                  verifiedAccountId: owner.accountId,
                  verifiedSenderId: owner.senderId,
                }),
                signal: AbortSignal.timeout(10_000),
              });
              const payload = await response.json().catch(() => ({}));
              if (response.ok && payload?.status === "confirmed") return text("Phone pairing confirmed. Finish the connection in the app.");
              return text(payload?.error?.message || "Phone pairing was not confirmed.");
            } catch {
              return text("The local T4L connector could not be reached.");
            }
          }
          if (!pending) {
            await store.failActive();
            return text("This pairing code is invalid or expired.");
          }
          const operationId = `op_${randomBytes(12).toString("base64url")}`;
          let confirmed = null;
          try {
            port = await selectConnectorPort(agentId, root, config.connectorPort);
            confirmed = await store.confirm(pending, owner, operationId);
            const request = await hostRequest({ config, root, agentId, owner, record: confirmed, operationId, port });
            const requestPath = join(root, "bootstrap", "operations", `${operationId}.request.json`);
            await atomicJson(requestPath, request);
            spawnInstaller(spawnImpl, requestPath, "install");
          } catch (error) {
            if (confirmed) {
              await store.mark(confirmed, "failed", {
                error: String(error?.message || error).slice(0, 300),
              });
            } else {
              const current = await store.find(pending.requestId);
              if (current?.status === "installing") {
                return text("T4L installation is already running for this phone.");
              }
            }
            return text("T4L installation could not start. Check the Gateway logs.");
          }
          return text("T4L installation started. Keep the app open; pairing will finish automatically.");
        },
      });

      if (typeof api.registerHttpRoute !== "function") return;
      const handler = async (req, res) => {
        if (configError || !agentId || !root || !store || !port) return errorResponse(res, 503, "bootstrap_not_configured", configError || "T4L bootstrap is not configured.");
        const url = new URL(req.url || "/", "http://gateway.invalid");
        if (!secureTransport(req)) {
          return errorResponse(
            res,
            403,
            "https_required",
            "T4L connector traffic requires trusted HTTPS or direct loopback.",
          );
        }
        const installed = await readInstalledState(
          root,
          agentId,
          runtimeIdentity,
        );
        const base = await connectorBaseUrl(
          config,
          root,
          port,
          agentId,
          runtimeIdentity,
        );
        if (installed) {
          const readinessKey = `${installed.port}:${installed.releaseId}:${installed.manifestSha256}`;
          if (
            connectorReadyKey !== readinessKey ||
            connectorReadyUntil <= now()
          ) {
            if (!(await connectorReady(fetchImpl, base, agentId, installed))) {
              return errorResponse(res, 502, "connector_not_ready", "The installed T4L connector identity is not ready.");
            }
            connectorReadyKey = readinessKey;
            connectorReadyUntil = now() + 5_000;
          }
          try {
            return await proxyRequest(fetchImpl, base, req, res);
          } catch {
            return errorResponse(res, 502, "connector_proxy_failed", "The local T4L connector could not be reached.");
          }
        }
        if (url.pathname === "/.well-known/t4l-agent" && req.method === "GET") return jsonResponse(res, 200, bootstrapDiscovery(agentId));
        if (url.pathname === "/v1/pairing/requests" && req.method === "POST") {
          try {
            const cutoff = now() - 60_000;
            while (pairingCreates.length && pairingCreates[0] <= cutoff) pairingCreates.shift();
            if (pairingCreates.length >= 5) {
              return errorResponse(res, 429, "pairing_rate_limited", "Too many pairing requests. Try again shortly.");
            }
            pairingCreates.push(now());
            const body = JSON.parse((await readBody(req, 16 * 1024)).toString("utf8"));
            return jsonResponse(res, 201, await store.create(body));
          } catch (error) {
            if (error?.code === "pairing_in_progress") {
              return jsonResponse(
                res,
                409,
                {
                  error: {
                    code: "pairing_in_progress",
                    message: "Another phone pairing is already in progress.",
                    retryAfterSeconds: error.retryAfterSeconds,
                  },
                },
                { "retry-after": String(error.retryAfterSeconds || 3) },
              );
            }
            return errorResponse(res, 400, "invalid_pairing_request", String(error?.message || error).slice(0, 300));
          }
        }
        if (url.pathname === "/v1/pairing/complete" && req.method === "POST") {
          try {
            const body = JSON.parse((await readBody(req, 16 * 1024)).toString("utf8"));
            const record = await store.find(body?.requestId);
            if (!record || record.devicePublicKey !== body?.devicePublicKey) return errorResponse(res, 404, "pairing_not_found", "Pairing request not found.");
            if (["expired", "superseded", "locked", "failed"].includes(record.status)) return errorResponse(res, 409, `pairing_${record.status}`, "Pairing is no longer available.");
            const signature = typeof body?.challengeSignature === "string" ? Buffer.from(body.challengeSignature, "base64url") : null;
            const proofDeadline = new Date(
              record.status === "installing"
                ? record.completionExpiresAt
                : record.expiresAt,
            ).getTime();
            if (!signature || signature.length !== 64 || proofDeadline <= now()) {
              return errorResponse(res, 409, "pairing_expired_or_invalid", "Pairing is no longer available.");
            }
            const operation = record.operationId ? await readOperation(root, record.operationId) : null;
            if (operation && ["failed", "rolled_back"].includes(operation.status)) {
              return errorResponse(res, 503, "bootstrap_install_failed", "T4L installation failed and was rolled back.");
            }
            return jsonResponse(res, 202, {
              ...store.summary(record),
              status: "pending",
              bootstrap: {
                status: operation?.status || record.status,
                operationId: record.operationId,
                retryAfterSeconds: 3,
              },
            }, { "retry-after": "3" });
          } catch {
            return errorResponse(res, 400, "invalid_pairing_request", "Pairing request is invalid.");
          }
        }
        return errorResponse(res, 503, "connector_installing", "T4L is not installed yet.");
      };
      for (const path of EXACT_ROUTES) api.registerHttpRoute({ path, auth: "plugin", match: "exact", handler });
      for (const path of PREFIX_ROUTES) api.registerHttpRoute({ path, auth: "plugin", match: "prefix", handler });
    },
  };
}

export default createT4LConnectPlugin();
