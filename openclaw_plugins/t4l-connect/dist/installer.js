import {
  createHash,
  createPublicKey,
  randomBytes,
  verify as verifySignature,
} from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  readlink,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

import { acquireLock, atomicJson, readJson } from "./bootstrap.js";

export const RELEASE_SCHEMA = "t4l_release_manifest.v1";
const POLICY_SCHEMA = "t4l_release_policy.v1";
const OPERATION_SCHEMA = "t4l_host_install_operation.v1";
const REQUIRED_ARTIFACTS = new Map([
  ["t4l-agent-wheel", "python-wheel"],
  ["t4l-server-wheel", "python-wheel"],
  ["t4l-python-wheelhouse", "python-wheelhouse-tar"],
  ["t4l-instructions", "instruction-bundle-tar"],
]);
const SHA256_RE = /^[a-f0-9]{64}$/;
const SAFE_ID_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const SAFE_RELEASE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/;
const ENV_NAME_RE = /^[A-Z_][A-Z0-9_]{0,127}$/;
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_ARTIFACT_BYTES = 250 * 1024 * 1024;
const OPERATION_ID_RE = /^op_[A-Za-z0-9_-]{8,128}$/;
const CONTROL_RE = /[\0-\x1f\x7f]/;

function safeHostText(value, name, max = 4096) {
  const result = exactString(value, name, max);
  if (CONTROL_RE.test(result)) throw new Error(`${name} contains control characters`);
  return result;
}

export function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  throw new Error("release manifest contains an unsupported JSON value");
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertHttpsUrl(value, name) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an HTTPS URL`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  ) {
    throw new Error(`${name} must be an HTTPS URL without credentials or a fragment`);
  }
  return parsed.toString();
}

function exactString(value, name, max = 256) {
  if (typeof value !== "string" || !value.trim() || value.length > max) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function rawEd25519PublicKey(value) {
  if (typeof value !== "string") throw new Error("release signing key is missing");
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== 32) throw new Error("release signing key must be a raw Ed25519 public key");
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "spki" });
}

function numericVersion(value) {
  const match = String(value).match(/(\d{4})\.(\d+)\.(\d+)(?:-(\d+))?/);
  return match
    ? {
        base: match.slice(1, 4).map(Number),
        revision: match[4] === undefined ? null : Number(match[4]),
      }
    : null;
}

function versionAtLeast(actual, minimum) {
  const left = numericVersion(actual);
  const right = numericVersion(minimum);
  if (!left || !right) return false;
  for (let index = 0; index < 3; index += 1) {
    if (left.base[index] > right.base[index]) return true;
    if (left.base[index] < right.base[index]) return false;
  }
  if (right.revision === null || left.revision === null) return true;
  return left.revision >= right.revision;
}

export function validateReleasePolicy(document) {
  if (!document || document.schema !== POLICY_SCHEMA) throw new Error("release policy schema is invalid");
  const releaseId = exactString(document.releaseId, "releaseId", 96);
  const version = exactString(document.version, "version", 64);
  const manifestUrl = assertHttpsUrl(document.manifestUrl, "manifestUrl");
  const signingKeyId = exactString(document.signingKeyId, "signingKeyId", 128);
  const signingPublicKey = exactString(document.signingPublicKey, "signingPublicKey", 128);
  if (!SAFE_RELEASE_RE.test(releaseId)) {
    throw new Error("release policy identifier is invalid");
  }
  if (signingPublicKey.startsWith("REPLACE_")) {
    throw new Error("release policy is a release-build placeholder and cannot install");
  }
  rawEd25519PublicKey(signingPublicKey);
  return { releaseId, version, manifestUrl, signingKeyId, signingPublicKey };
}

export function verifyReleaseManifest(bytes, policy, openClawVersion) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_MANIFEST_BYTES) {
    throw new Error("release manifest size is invalid");
  }
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("release manifest is not valid JSON");
  }
  if (!manifest || manifest.schema !== RELEASE_SCHEMA) throw new Error("release manifest schema is invalid");
  if (manifest.releaseId !== policy.releaseId || manifest.version !== policy.version) {
    throw new Error("release manifest identity does not match policy");
  }
  const minimum = exactString(manifest.minOpenClawVersion, "minOpenClawVersion", 64);
  const runtimeVersion = numericVersion(openClawVersion);
  if (
    !versionAtLeast(openClawVersion, minimum) ||
    !runtimeVersion ||
    runtimeVersion.base[0] >= 2027
  ) {
    throw new Error(`OpenClaw ${minimum} through the compatible 2026.x API range is required`);
  }
  const signature = manifest.signature;
  if (
    !signature ||
    signature.algorithm !== "Ed25519" ||
    signature.keyId !== policy.signingKeyId ||
    typeof signature.value !== "string"
  ) {
    throw new Error("release signature metadata does not match policy");
  }
  const unsigned = { ...manifest };
  delete unsigned.signature;
  const signatureBytes = Buffer.from(signature.value, "base64url");
  if (
    signatureBytes.length !== 64 ||
    !verifySignature(
      null,
      Buffer.from(canonicalJson(unsigned), "utf8"),
      rawEd25519PublicKey(policy.signingPublicKey),
      signatureBytes,
    )
  ) {
    throw new Error("release manifest signature is invalid");
  }
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length !== REQUIRED_ARTIFACTS.size) {
    throw new Error("release manifest must contain the exact required artifact set");
  }
  const seen = new Set();
  const artifacts = manifest.artifacts.map((entry) => {
    const name = exactString(entry?.name, "artifact.name", 96);
    const kind = exactString(entry?.kind, "artifact.kind", 64);
    const filename = exactString(entry?.filename, "artifact.filename", 180);
    const url = assertHttpsUrl(entry?.url, `artifact ${name} URL`);
    const digest = exactString(entry?.sha256, `artifact ${name} sha256`, 64).toLowerCase();
    const size = entry?.size;
    if (
      seen.has(name) ||
      REQUIRED_ARTIFACTS.get(name) !== kind ||
      basename(filename) !== filename ||
      !SHA256_RE.test(digest) ||
      !Number.isSafeInteger(size) ||
      size <= 0 ||
      size > MAX_ARTIFACT_BYTES
    ) {
      throw new Error(`release artifact is invalid: ${name}`);
    }
    seen.add(name);
    return { name, kind, filename, url, sha256: digest, size };
  });
  if ([...REQUIRED_ARTIFACTS.keys()].some((name) => !seen.has(name))) {
    throw new Error("release manifest is missing a required artifact");
  }
  return { ...manifest, artifacts };
}

export async function runProcess(argv, options = {}) {
  if (!Array.isArray(argv) || argv.some((item) => typeof item !== "string" || !item)) {
    throw new Error("invalid process arguments");
  }
  return new Promise((resolvePromise) => {
    const child = spawn(argv[0], argv.slice(1), {
      cwd: options.cwd,
      env: { ...process.env, ...(options.env || {}) },
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (value) => {
      if (stdout.length < 1_000_000) stdout += value;
    });
    child.stderr.on("data", (value) => {
      if (stderr.length < 1_000_000) stderr += value;
    });
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolvePromise(result);
    };
    child.on("error", (error) => finish({ code: 127, stdout, stderr: error.message }));
    child.on("close", (code) => finish({ code: code ?? 1, stdout, stderr }));
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 2_000).unref();
      finish({ code: 124, stdout, stderr: `${stderr}\nprocess timed out` });
    }, options.timeoutMs || 120_000);
    timeout.unref();
    if (options.input) child.stdin.end(options.input);
    else child.stdin.end();
  });
}

export async function atomicText(path, content, mode = 0o600) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink() || !info.isFile()) throw new Error(`refusing unsafe output path: ${path}`);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  await writeFile(temporary, content, { mode, flag: "wx" });
  await rename(temporary, path);
  await chmod(path, mode);
}

function xml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

export function renderSystemdUnit(spec) {
  const servicePath = safeHostText(spec.environment?.PATH, "service PATH", 4096);
  for (const value of [spec.envFile, spec.root, spec.stateDir, spec.homeDir, spec.configPath, servicePath, ...spec.command]) {
    if (CONTROL_RE.test(String(value))) throw new Error("systemd service value contains control characters");
  }
  const args = spec.command.map((item) => `"${String(item).replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`).join(" ");
  const quote = (value) => `"${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
  return `[Unit]\nDescription=T4L connector for ${spec.agentId}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUMask=0077\nEnvironment=${quote(`PATH=${servicePath}`)}\nEnvironmentFile=${quote(spec.envFile)}\nExecStart=${args}\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nReadWritePaths=${quote(spec.root)} ${quote(spec.stateDir)} ${quote(spec.homeDir)} ${quote(dirname(spec.configPath))}\n\n[Install]\nWantedBy=default.target\n`;
}

export function renderLaunchdPlist(spec) {
  const argumentsXml = spec.command.map((item) => `      <string>${xml(item)}</string>`).join("\n");
  const envXml = Object.entries(spec.environment)
    .map(([key, value]) => `      <key>${xml(key)}</key>\n      <string>${xml(value)}</string>`)
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n  <key>Label</key><string>${xml(spec.label)}</string>\n  <key>ProgramArguments</key>\n  <array>\n${argumentsXml}\n  </array>\n  <key>EnvironmentVariables</key>\n  <dict>\n${envXml}\n  </dict>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>StandardOutPath</key><string>${xml(spec.logFile)}</string>\n  <key>StandardErrorPath</key><string>${xml(spec.logFile)}</string>\n</dict>\n</plist>\n`;
}

function serviceMode(request, platform) {
  const selected = request.serviceMode || "auto";
  if (!["auto", "systemd", "launchd", "none"].includes(selected)) throw new Error("invalid service mode");
  if (selected !== "auto") return selected;
  if (platform === "linux") return "systemd";
  if (platform === "darwin") return "launchd";
  throw new Error("automatic service installation supports Linux and macOS only");
}

function derivedRequestIdentity(request) {
  const rootIdentity = sha256(
    [
      "t4l-bootstrap-root.v2",
      request.profile,
      request.agentId,
      resolve(request.root),
      resolve(request.stateDir),
      resolve(request.configPath),
    ].join("\0"),
  );
  return {
    rootIdentity,
    serviceId: `${request.agentId.slice(0, 40)}-${rootIdentity.slice(0, 12)}`,
  };
}

function serviceEnvironment(request) {
  const nodeDir = dirname(request.nodeExecutable);
  const path = [nodeDir, "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    .filter((entry, index, values) => values.indexOf(entry) === index)
    .join(":");
  return { PATH: path };
}

function validateRequest(request) {
  if (!request || request.schema !== "t4l_host_install_request.v1") throw new Error("host install request schema is invalid");
  const action = exactString(request.action, "action", 20);
  if (!["install", "update", "verify", "rollback", "uninstall"].includes(action)) throw new Error("unsupported host install action");
  request.nodeExecutable ||= process.execPath;
  for (const key of ["agentId", "profile"]) {
    if (!SAFE_ID_RE.test(safeHostText(request[key], key, 64))) throw new Error(`${key} is not filesystem-safe`);
  }
  for (const key of [
    "root",
    "homeDir",
    "serviceHomeDir",
    "stateDir",
    "configPath",
    "pluginDir",
    "releasePolicyPath",
    "openclawExecutable",
    "nodeExecutable",
    "pythonExecutable",
  ]) {
    if (!isAbsolute(safeHostText(request[key], key, 4096))) throw new Error(`${key} must be absolute`);
  }
  const root = resolve(request.root);
  const stateDir = resolve(request.stateDir);
  if (root === "/" || root === resolve(homedir()) || root === stateDir || root.split("/").filter(Boolean).length < 3) {
    throw new Error("install root is dangerously broad");
  }
  const operationId = safeHostText(request.operationId || "", "operationId", 140);
  if (!OPERATION_ID_RE.test(operationId)) throw new Error("operationId is invalid");
  if (request.rollbackOperationId && !OPERATION_ID_RE.test(safeHostText(request.rollbackOperationId, "rollbackOperationId", 140))) {
    throw new Error("rollbackOperationId is invalid");
  }
  safeHostText(request.agentName || "T4L Coach", "agentName", 100);
  const owner = safeHostText(request.ownerIdentity, "ownerIdentity", 800).split(":", 3);
  if (owner.length !== 3 || owner.some((item) => !item)) throw new Error("ownerIdentity is invalid");
  if (request.pairingFile) {
    const pair = resolve(safeHostText(request.pairingFile, "pairingFile", 4096));
    const expectedRoot = resolve(root, "bootstrap", "pairings");
    if (!pair.startsWith(`${expectedRoot}/`) || !/^pair_[A-Za-z0-9_-]{12,64}\.json$/.test(basename(pair))) {
      throw new Error("pairingFile escapes this agent's bootstrap state");
    }
  }
  if (!Number.isInteger(request.port) || request.port < 1024 || request.port > 65535) throw new Error("connector port is invalid");
  if (request.provider || request.model || request.reasoning || request.providerApiKey) {
    throw new Error("provider, model, reasoning, and provider credentials are forbidden");
  }
  const derived = derivedRequestIdentity(request);
  request.rootIdentity ||= derived.rootIdentity;
  request.serviceId ||= derived.serviceId;
  if (
    request.rootIdentity !== derived.rootIdentity ||
    request.serviceId !== derived.serviceId ||
    !SAFE_ID_RE.test(safeHostText(request.serviceId, "serviceId", 64))
  ) {
    throw new Error("host request runtime identity is invalid");
  }
  return request;
}

export class HostInstaller {
  constructor({
    fetchImpl = globalThis.fetch,
    run = runProcess,
    platform = process.platform,
    arch = platform === process.platform ? process.arch : "x64",
    uid = typeof process.getuid === "function" ? process.getuid() : 0,
    now = () => new Date(),
    sleep = delay,
    installedStateWriter = atomicJson,
    hostMutationHook = async () => {},
  } = {}) {
    this.fetch = fetchImpl;
    this.run = run;
    this.platform = platform;
    this.arch = arch;
    this.uid = uid;
    this.now = now;
    this.sleep = sleep;
    this.installedStateWriter = installedStateWriter;
    this.hostMutationHook = hostMutationHook;
  }

  async execute(rawRequest) {
    const request = validateRequest(rawRequest);
    const root = resolve(request.root);
    let releaseLock = null;
    for (let attempt = 0; attempt < 120; attempt += 1) {
      try {
        releaseLock = await acquireLock(join(root, "bootstrap", "installer.lock"));
        break;
      } catch (error) {
        if (
          !String(error?.message || error).includes("another T4L bootstrap operation") ||
          attempt === 119
        ) {
          throw error;
        }
        await this.sleep(500);
      }
    }
    if (!releaseLock) {
      await atomicJson(
        join(root, "bootstrap", "operations", `${request.operationId}.json`),
        {
          schema: OPERATION_SCHEMA,
          operationId: request.operationId,
          action: request.action,
          agentId: request.agentId,
          status: "failed",
          stage: "lock-timeout",
          error: "T4L installer lock could not be acquired",
          updatedAt: this.now().toISOString(),
        },
      );
      throw new Error("T4L installer lock could not be acquired");
    }
    try {
      await this.#ensureRootIdentity(request);
      if (["install", "update"].includes(request.action)) return await this.#install(request);
      const operationPath = join(
        request.root,
        "bootstrap",
        "operations",
        `${request.operationId}.json`,
      );
      await atomicJson(operationPath, {
        schema: OPERATION_SCHEMA,
        operationId: request.operationId,
        action: request.action,
        agentId: request.agentId,
        status: "running",
        stage: request.action,
        updatedAt: this.now().toISOString(),
      });
      try {
        const result =
          request.action === "verify"
            ? await this.#verifyLifecycle(request)
            : request.action === "rollback"
              ? await this.#rollback(request)
              : await this.#uninstall(request);
        try {
          await atomicJson(operationPath, {
            schema: OPERATION_SCHEMA,
            operationId: request.operationId,
            action: request.action,
            agentId: request.agentId,
            status: result.ok ? "completed" : "failed",
            stage: result.code,
            updatedAt: this.now().toISOString(),
          });
        } catch (error) {
          if (request.action !== "uninstall" || !result.ok) throw error;
        }
        if (request.action === "uninstall" && result.ok) {
          await rm(join(request.root, "quarantine", request.operationId), {
            recursive: true,
            force: true,
          }).catch(() => {});
        }
        return result;
      } catch (error) {
        await atomicJson(operationPath, {
          schema: OPERATION_SCHEMA,
          operationId: request.operationId,
          action: request.action,
          agentId: request.agentId,
          status: "failed",
          stage: request.action,
          error: String(error?.message || error).slice(0, 500),
          updatedAt: this.now().toISOString(),
        });
        throw error;
      }
    } finally {
      await releaseLock();
    }
  }

  async #ensureRootIdentity(request) {
    const path = join(request.root, "bootstrap", "identity.json");
    try {
      const identity = await readJson(path);
      if (
        identity?.schema !== "t4l_bootstrap_root_identity.v2" ||
        identity?.agentId !== request.agentId ||
        identity?.profile !== request.profile ||
        identity?.stateDir !== request.stateDir ||
        identity?.configPath !== request.configPath ||
        identity?.serviceId !== request.serviceId ||
        identity?.rootIdentity !== request.rootIdentity
      ) {
        throw new Error("T4L install root belongs to another agent");
      }
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      await atomicJson(path, {
        schema: "t4l_bootstrap_root_identity.v2",
        agentId: request.agentId,
        profile: request.profile,
        stateDir: request.stateDir,
        configPath: request.configPath,
        serviceId: request.serviceId,
        rootIdentity: request.rootIdentity,
        createdAt: this.now().toISOString(),
      });
    }
  }

  async #install(request) {
    const operationId = request.operationId;
    const operationPath = join(request.root, "bootstrap", "operations", `${operationId}.json`);
    const updateOperation = async (status, stage, details = {}) => {
      const value = {
        schema: OPERATION_SCHEMA,
        operationId,
        action: request.action,
        agentId: request.agentId,
        status,
        stage,
        updatedAt: this.now().toISOString(),
        ...details,
      };
      await atomicJson(operationPath, value);
      return value;
    };
    let snapshot = null;
    let stagedReleaseDir = null;
    let runtimeMutationAttempted = false;
    let previousOperation = null;
    try {
      previousOperation = await readJson(operationPath);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    if (previousOperation?.status === "completed") {
      const committed = await this.#installedState(request);
      const recorded = previousOperation.installedRelease;
      if (
        committed &&
        recorded?.releaseId === committed.releaseId &&
        recorded?.version === committed.version &&
        recorded?.manifestSha256 === committed.manifestSha256
      ) {
        return {
          ok: true,
          code: "installed",
          operationId,
          idempotent: true,
          resumed: true,
          checks: { state: true, release: true },
          installedRelease: recorded,
        };
      }
    }
    if (
      previousOperation?.status === "running" &&
      previousOperation?.stage === "committing"
    ) {
      const committed = await this.#verifyInstalled(request);
      if (committed.ok) {
        await updateOperation("completed", "ready", {
          installedRelease: committed.installedRelease,
          resumed: true,
        });
        return { ...committed, operationId, idempotent: true, resumed: true };
      }
    }
    if (
      previousOperation?.status === "running" ||
      previousOperation?.status === "completed"
    ) {
      try {
        const previousSnapshot = await readJson(
          join(request.root, "snapshots", operationId, "snapshot.json"),
        );
        await this.#restoreSnapshot(request, previousSnapshot);
        snapshot = previousSnapshot;
        if (
          request.action === "update" &&
          !request.dryRun &&
          ["runtime-update", "committing"].includes(previousOperation.stage)
        ) {
          runtimeMutationAttempted = true;
          await this.#runtimeAction(request, "update");
          await this.#runtimeAction(request, "verify");
        }
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
    }
    await updateOperation("running", "manifest", { resumed: snapshot !== null });
    try {
      const policy = validateReleasePolicy(await readJson(request.releasePolicyPath));
      await this.#assertSupportedHost(request);
      const versionResult = await this.run(
        [request.openclawExecutable || "openclaw", "--profile", request.profile, "--version"],
        { env: this.#runtimeEnv(request) },
      );
      if (versionResult.code !== 0) throw new Error("OpenClaw executable could not be verified");
      const manifestBytes = await this.#download(policy.manifestUrl, MAX_MANIFEST_BYTES);
      const manifest = verifyReleaseManifest(manifestBytes, policy, versionResult.stdout);
      const manifestSha256 = sha256(manifestBytes);
      const existing = await this.#installedState(request);
      if (
        existing?.releaseId === manifest.releaseId &&
        existing?.version === manifest.version &&
        existing?.manifestSha256 === manifestSha256 &&
        existing?.signingKeyId === policy.signingKeyId
      ) {
        const verified = await this.#verifyInstalled(request);
        if (verified.ok) {
          if (request.action === "update" && !request.dryRun) {
            await updateOperation("running", "runtime-update", {
              installedRelease: verified.installedRelease,
              idempotentHost: true,
            });
            runtimeMutationAttempted = true;
            await this.#runtimeAction(request, "update");
            await this.#runtimeAction(request, "verify");
          }
          await updateOperation("completed", "idempotent", { installedRelease: verified.installedRelease });
          return { ...verified, operationId, idempotent: true };
        }
      }
      snapshot ||= await this.#snapshot(request, operationId);
      await updateOperation("running", "download", { releaseId: manifest.releaseId });
      const artifactPaths = await this.#downloadArtifacts(request, manifest);
      await updateOperation("running", "install");
      const releaseDir = join(
        request.root,
        "releases",
        `${manifest.releaseId}-${manifestSha256.slice(0, 16)}-${operationId.slice(3)}`,
      );
      stagedReleaseDir = releaseDir;
      await rm(releaseDir, { recursive: true, force: true });
      await mkdir(releaseDir, { recursive: true, mode: 0o700 });
      const venvDir = join(releaseDir, "venv");
      const instructionsDir = join(releaseDir, "instructions");
      const wheelhouseDir = join(releaseDir, "wheelhouse");
      if (!request.dryRun) {
        await this.#mustRun([request.pythonExecutable || "python3", "-m", "venv", venvDir]);
        await mkdir(wheelhouseDir, { recursive: true, mode: 0o700 });
        await this.#mustRun([
          request.pythonExecutable || "python3",
          join(request.pluginDir, "bin", "extract_instructions.py"),
          artifactPaths.get("t4l-python-wheelhouse"),
          wheelhouseDir,
        ]);
        const python = join(venvDir, "bin", "python");
        await this.#mustRun([
          python,
          "-m",
          "pip",
          "install",
          "--no-index",
          "--find-links",
          wheelhouseDir,
          "--disable-pip-version-check",
          artifactPaths.get("t4l-server-wheel"),
          artifactPaths.get("t4l-agent-wheel"),
        ]);
        await mkdir(instructionsDir, { recursive: true, mode: 0o700 });
        await this.#mustRun([
          request.pythonExecutable || "python3",
          join(request.pluginDir, "bin", "extract_instructions.py"),
          artifactPaths.get("t4l-instructions"),
          instructionsDir,
        ]);
      } else {
        await mkdir(join(venvDir, "bin"), { recursive: true, mode: 0o700 });
        await mkdir(instructionsDir, { recursive: true, mode: 0o700 });
        await mkdir(wheelhouseDir, { recursive: true, mode: 0o700 });
      }
      await atomicJson(join(releaseDir, "release.json"), {
        schema: "t4l_installed_release.v1",
        releaseId: manifest.releaseId,
        version: manifest.version,
        manifestUrl: policy.manifestUrl,
        manifestSha256,
        signingKeyId: policy.signingKeyId,
        installedAt: this.now().toISOString(),
      });
      await this.#activateRelease(request, releaseDir);
      const secrets = await this.#ensureSecrets(request);
      await this.#installService(request, secrets);
      await updateOperation("running", "service");
      if (!request.dryRun) {
        await this.#startService(request);
        await this.#waitForConnector(request, {
          releaseId: manifest.releaseId,
          version: manifest.version,
          manifestSha256,
        });
        if (request.pairingFile) {
          await updateOperation("running", "pairing-adoption");
          await this.#adoptPairing(request, secrets.runtimeToken);
        }
        if (request.action === "update") {
          await updateOperation("running", "runtime-update");
          runtimeMutationAttempted = true;
          await this.#runtimeAction(request, "update");
          await this.#runtimeAction(request, "verify");
        }
      }
      const installedRelease = {
        releaseId: manifest.releaseId,
        version: manifest.version,
        manifestSha256,
        signingKeyId: policy.signingKeyId,
      };
      const installedState = {
        schema: "t4l_host_install_state.v1",
        agentId: request.agentId,
        profile: request.profile,
        serviceId: request.serviceId,
        rootIdentity: request.rootIdentity,
        port: request.port,
        serviceMode: serviceMode(request, this.platform),
        releaseDir,
        ...installedRelease,
      };
      await updateOperation("running", "committing", { installedRelease });
      // This marker switches the Gateway proxy only after the connector and
      // pairing adoption are durable. Nothing after it may roll the host back.
      await this.installedStateWriter(
        join(request.root, "installed.json"),
        installedState,
      );
      await updateOperation("completed", "ready", { installedRelease }).catch(
        () => {},
      );
      return { ok: true, code: "installed", operationId, checks: { manifest: true, artifacts: true, service: true, adoption: !request.pairingFile || !request.dryRun }, installedRelease };
    } catch (error) {
      let rollbackOk = false;
      if (snapshot) {
        try {
          await this.#restoreSnapshot(request, snapshot);
          if (runtimeMutationAttempted) {
            await this.#runtimeAction(request, "update");
            await this.#runtimeAction(request, "verify");
          }
          rollbackOk = true;
        } catch {
          rollbackOk = false;
        }
      }
      if (rollbackOk && stagedReleaseDir) {
        await rm(stagedReleaseDir, { recursive: true, force: true }).catch(() => {});
      }
      if (request.pairingFile) {
        await this.#markPairingFailed(request, error).catch(() => {});
      }
      await updateOperation("failed", "rolled-back", {
        error: String(error?.message || error).slice(0, 500),
        rollback: rollbackOk,
      });
      throw new Error(`${error?.message || error}${snapshot ? rollbackOk ? "; previous state restored" : "; rollback failed" : ""}`);
    }
  }

  async #downloadArtifacts(request, manifest) {
    const cache = join(request.root, "cache");
    await mkdir(cache, { recursive: true, mode: 0o700 });
    const result = new Map();
    for (const artifact of manifest.artifacts) {
      const path = join(cache, `${artifact.sha256}-${artifact.filename}`);
      let valid = false;
      try {
        const info = await lstat(path);
        if (info.isSymbolicLink() || !info.isFile()) throw new Error("unsafe cache entry");
        valid = info.size === artifact.size && sha256(await readFile(path)) === artifact.sha256;
      } catch {
        valid = false;
      }
      if (!valid) {
        const bytes = await this.#download(artifact.url, artifact.size);
        if (bytes.length !== artifact.size || sha256(bytes) !== artifact.sha256) throw new Error(`artifact digest or size mismatch: ${artifact.name}`);
        await atomicText(path, bytes, 0o600);
      }
      result.set(artifact.name, path);
    }
    return result;
  }

  async #assertSupportedHost(request) {
    const supported =
      (this.platform === "linux" && this.arch === "x64") ||
      (this.platform === "darwin" && this.arch === "arm64");
    if (!supported) {
      throw new Error(
        `T4L release v1 does not support ${this.platform}/${this.arch}; supported targets are linux/x64 and darwin/arm64`,
      );
    }
    if (request.dryRun) return;
    const result = await this.run([request.pythonExecutable, "--version"]);
    const match = `${result.stdout || ""} ${result.stderr || ""}`.match(
      /Python\s+3\.(11|12|13)(?:\.|\s|$)/,
    );
    if (result.code !== 0 || !match) {
      throw new Error("T4L release v1 requires CPython 3.11, 3.12, or 3.13");
    }
  }

  async #download(url, maximum) {
    const response = await this.fetch(url, { redirect: "follow", signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`download failed with HTTP ${response.status}`);
    assertHttpsUrl(response.url || url, "final download URL");
    const declared = Number(response.headers?.get?.("content-length") || 0);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > maximum) {
      throw new Error("download exceeds pinned size limit");
    }
    if (!response.body) throw new Error("download response has no body");
    const chunks = [];
    let received = 0;
    for await (const chunk of response.body) {
      const bytes = Buffer.from(chunk);
      received += bytes.length;
      if (received > maximum) {
        throw new Error("download exceeds pinned size limit");
      }
      chunks.push(bytes);
    }
    if (declared > 0 && received !== declared) {
      throw new Error("download size does not match its content-length");
    }
    return Buffer.concat(chunks, received);
  }

  async #snapshot(request, operationId) {
    const snapshotDir = join(request.root, "snapshots", operationId);
    try {
      await lstat(snapshotDir);
      throw new Error("host rollback snapshot already exists");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await mkdir(snapshotDir, { recursive: true, mode: 0o700 });
    const current = join(request.root, "current");
    let currentTarget = null;
    try {
      currentTarget = await readlink(current);
    } catch {}
    const files = [
      this.#servicePath(request),
      join(request.root, "secrets.env"),
      join(request.root, "installed.json"),
    ];
    const copied = [];
    for (const path of files) {
      try {
        const info = await lstat(path);
        if (info.isSymbolicLink() || !info.isFile()) {
          throw new Error(`refusing unsafe snapshot path: ${path}`);
        }
        const target = join(snapshotDir, `${copied.length}.bak`);
        await copyFile(path, target);
        copied.push({ path, backup: target, mode: info.mode & 0o777, existed: true });
      } catch (error) {
        if (error?.code === "ENOENT") copied.push({ path, existed: false });
        else throw error;
      }
    }
    const metadata = {
      schema: "t4l_host_snapshot.v1",
      operationId,
      agentId: request.agentId,
      serviceId: request.serviceId,
      rootIdentity: request.rootIdentity,
      currentTarget,
      copied,
      gatewayEnv: await this.#snapshotGatewayEnv(request),
    };
    await atomicJson(join(snapshotDir, "snapshot.json"), metadata);
    await this.#pruneSnapshots(request, operationId);
    return metadata;
  }

  async #restoreSnapshot(request, snapshot) {
    if (
      snapshot?.schema !== "t4l_host_snapshot.v1" ||
      snapshot?.agentId !== request.agentId ||
      snapshot?.serviceId !== request.serviceId ||
      snapshot?.rootIdentity !== request.rootIdentity ||
      !OPERATION_ID_RE.test(String(snapshot.operationId)) ||
      !Array.isArray(snapshot.copied)
    ) {
      throw new Error("host rollback snapshot is invalid");
    }
    const allowed = new Set([
      resolve(this.#servicePath(request)),
      resolve(request.root, "secrets.env"),
      resolve(request.root, "installed.json"),
    ]);
    const backupRoot = resolve(
      request.root,
      "snapshots",
      snapshot.operationId,
    );
    for (const item of snapshot.copied) {
      if (
        !allowed.has(resolve(String(item.path || ""))) ||
        (item.existed !== false &&
          !resolve(String(item.backup || "")).startsWith(`${backupRoot}/`))
      ) {
        throw new Error("host rollback snapshot path is invalid");
      }
    }
    if (
      snapshot.currentTarget &&
      !resolve(String(snapshot.currentTarget)).startsWith(
        `${resolve(request.root, "releases")}/`,
      )
    ) {
      throw new Error("host rollback release path is invalid");
    }
    await this.#stopService(request).catch(() => {});
    for (const item of snapshot.copied) {
      if (item.existed === false) {
        await unlink(item.path).catch((error) => {
          if (error?.code !== "ENOENT") throw error;
        });
      } else {
        await atomicText(item.path, await readFile(item.backup), item.mode);
      }
    }
    if (snapshot.gatewayEnv) {
      await this.#restoreGatewayEnv(request, snapshot.gatewayEnv);
    }
    const current = join(request.root, "current");
    await unlink(current).catch(() => {});
    if (snapshot.currentTarget) {
      const temporary = `${current}.rollback-${process.pid}`;
      await symlink(snapshot.currentTarget, temporary);
      await rename(temporary, current);
      if (serviceMode(request, this.platform) !== "none") {
        await this.#startService(request);
        const previous = await this.#installedState(request);
        if (previous) {
          await this.#waitForConnector(request, {
            releaseId: previous.releaseId,
            version: previous.version,
            manifestSha256: previous.manifestSha256,
          });
        }
      }
    }
  }

  async #activateRelease(request, releaseDir) {
    const current = join(request.root, "current");
    const temporary = `${current}.next-${process.pid}`;
    await unlink(temporary).catch(() => {});
    await symlink(releaseDir, temporary);
    await rename(temporary, current);
  }

  async #ensureSecrets(request) {
    const path = join(request.root, "secrets.env");
    try {
      const info = await lstat(path);
      if (info.isSymbolicLink() || !info.isFile()) throw new Error("unsafe secrets file");
      const values = this.#parseEnv(await readFile(path, "utf8"));
      if (values.T4L_CONNECTOR_RUNTIME_TOKEN && values.T4L_SERVER_API_KEY) {
        return { runtimeToken: values.T4L_CONNECTOR_RUNTIME_TOKEN, serverToken: values.T4L_SERVER_API_KEY, path };
      }
    } catch {}
    const runtimeToken = randomBytes(32).toString("base64url");
    const serverToken = randomBytes(32).toString("base64url");
    await atomicText(
      path,
      `T4L_CONNECTOR_RUNTIME_TOKEN=${runtimeToken}\nT4L_SERVER_API_KEY=${serverToken}\nMCP_T4L_API_KEY=${serverToken}\n`,
      0o600,
    );
    const gatewayEnv = join(request.stateDir, ".env");
    let existing = "";
    try {
      existing = await readFile(gatewayEnv, "utf8");
    } catch {}
    const kept = existing
      .split(/\r?\n/)
      .filter((line) => !line.startsWith("T4L_CONNECTOR_RUNTIME_TOKEN=") && !line.startsWith("MCP_T4L_API_KEY="))
      .filter(Boolean);
    kept.push(`T4L_CONNECTOR_RUNTIME_TOKEN=${runtimeToken}`, `MCP_T4L_API_KEY=${serverToken}`);
    await mkdir(dirname(gatewayEnv), { recursive: true, mode: 0o700 });
    await atomicText(gatewayEnv, `${kept.join("\n")}\n`, 0o600);
    return { runtimeToken, serverToken, path };
  }

  #parseEnv(text) {
    const result = {};
    for (const line of text.split(/\r?\n/)) {
      const index = line.indexOf("=");
      if (index <= 0) continue;
      const key = line.slice(0, index);
      if (ENV_NAME_RE.test(key)) result[key] = line.slice(index + 1);
    }
    return result;
  }

  #command(request) {
    const current = join(request.root, "current");
    return [
      join(current, "venv", "bin", "t4l-agent"),
      "run",
      "--agent-id", request.agentId,
      "--agent-name", request.agentName || "T4L Coach",
      "--agent-runtime", "openclaw",
      "--agent-profile", request.profile,
      "--agent-home-dir", request.homeDir,
      "--agent-state-dir", request.stateDir,
      "--agent-config-path", request.configPath,
      "--runtime-executable", request.openclawExecutable,
      "--runtime-adapter-command", join(current, "venv", "bin", "t4l-agent"),
      "--bootstrap-plugin-preinstalled",
      "--data-dir", join(request.root, "data"),
      "--instruction-bundle-dir", join(current, "instructions"),
      "--openclaw-plugin-dir", request.pluginDir,
      "--release-state-file", join(current, "release.json"),
      "--connector-owner-id", request.ownerIdentity,
      "--port", String(request.port),
    ];
  }

  async #installService(request, secrets) {
    const mode = serviceMode(request, this.platform);
    const servicePath = this.#servicePath(request);
    await mkdir(dirname(servicePath), { recursive: true, mode: 0o700 });
    if (mode === "none") {
      await atomicJson(join(request.root, "service-command.json"), {
        schema: "t4l_service_command.v1",
        command: this.#command(request),
        environmentFile: secrets.path,
        environment: serviceEnvironment(request),
      });
      return;
    }
    if (mode === "systemd") {
      await atomicText(
        servicePath,
        renderSystemdUnit({
          agentId: request.agentId,
          serviceId: request.serviceId,
          root: request.root,
          stateDir: request.stateDir,
          homeDir: request.homeDir,
          configPath: request.configPath,
          envFile: secrets.path,
          environment: serviceEnvironment(request),
          command: this.#command(request),
        }),
        0o600,
      );
      return;
    }
    const environment = {
      ...serviceEnvironment(request),
      T4L_CONNECTOR_RUNTIME_TOKEN: secrets.runtimeToken,
      T4L_SERVER_API_KEY: secrets.serverToken,
      MCP_T4L_API_KEY: secrets.serverToken,
    };
    await mkdir(join(request.root, "logs"), { recursive: true, mode: 0o700 });
    await atomicText(
      servicePath,
      renderLaunchdPlist({
        label: `ai.t4l.agent.${request.serviceId}`,
        command: this.#command(request),
        environment,
        logFile: join(request.root, "logs", "service.log"),
      }),
      0o600,
    );
  }

  #servicePath(request) {
    const mode = serviceMode(request, this.platform);
    if (mode === "systemd") return join(request.serviceHomeDir, ".config", "systemd", "user", `t4l-agent-${request.serviceId}.service`);
    if (mode === "launchd") return join(request.serviceHomeDir, "Library", "LaunchAgents", `ai.t4l.agent.${request.serviceId}.plist`);
    return join(request.root, "service-command.json");
  }

  async #startService(request) {
    const mode = serviceMode(request, this.platform);
    if (mode === "systemd") {
      await this.#mustRun(["systemctl", "--user", "daemon-reload"]);
      await this.#mustRun(["systemctl", "--user", "enable", `t4l-agent-${request.serviceId}.service`]);
      await this.#mustRun(["systemctl", "--user", "restart", `t4l-agent-${request.serviceId}.service`]);
    } else if (mode === "launchd") {
      const domain = `gui/${this.uid}`;
      const path = this.#servicePath(request);
      await this.run(["launchctl", "bootout", domain, path]);
      await this.#mustRun(["launchctl", "bootstrap", domain, path]);
      await this.#mustRun(["launchctl", "kickstart", "-k", `${domain}/ai.t4l.agent.${request.serviceId}`]);
    } else {
      throw new Error("serviceMode none only supports dry-run command generation");
    }
  }

  async #stopService(request) {
    const mode = serviceMode(request, this.platform);
    if (mode === "systemd") {
      await this.run(["systemctl", "--user", "disable", "--now", `t4l-agent-${request.serviceId}.service`]);
      await this.run(["systemctl", "--user", "daemon-reload"]);
    } else if (mode === "launchd") {
      await this.run(["launchctl", "bootout", `gui/${this.uid}`, this.#servicePath(request)]);
    }
  }

  async #waitForConnector(request, expectedRelease) {
    const url = `http://127.0.0.1:${request.port}/.well-known/t4l-agent`;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      try {
        const response = await this.fetch(url, { signal: AbortSignal.timeout(2_000) });
        const payload = await response.json();
        const target = payload?.installation?.targetRelease;
        if (
          response.ok &&
          payload?.agentId === request.agentId &&
          target?.releaseId === expectedRelease.releaseId &&
          target?.version === expectedRelease.version &&
          target?.manifestSha256 === expectedRelease.manifestSha256
        ) {
          return;
        }
      } catch {}
      await this.sleep(500);
    }
    throw new Error("T4L connector did not become healthy");
  }

  async #adoptPairing(request, runtimeToken) {
    const record = await readJson(request.pairingFile);
    if (
      record?.agentId !== request.agentId ||
      record?.status !== "installing" ||
      record?.operationId !== request.operationId ||
      new Date(record.completionExpiresAt).getTime() <= this.now().getTime()
    ) {
      throw new Error("bootstrap pairing is invalid or its completion window expired");
    }
    const response = await this.fetch(`http://127.0.0.1:${request.port}/v1/pairing/bootstrap-adoption`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-t4l-runtime-token": runtimeToken },
      body: JSON.stringify({
        schema: "t4l_bootstrap_pairing_adoption.v1",
        requestId: record.requestId,
        agentId: record.agentId,
        devicePublicKey: record.devicePublicKey,
        deviceName: record.deviceName,
        platform: record.platform,
        challenge: record.challenge,
        code: record.code,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        confirmedAt: record.confirmedAt,
        completionExpiresAt: record.completionExpiresAt,
        channel: record.channel,
        verifiedAccountId: record.verifiedAccountId,
        verifiedSenderId: record.verifiedSenderId,
      }),
      signal: AbortSignal.timeout(10_000),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload?.schema !== "t4l_bootstrap_pairing_adoption_result.v1" || payload?.requestId !== record.requestId || payload?.status !== "confirmed") {
      throw new Error(payload?.error?.message || "connector rejected bootstrap pairing adoption");
    }
  }

  async #markPairingFailed(request, error) {
    const record = await readJson(request.pairingFile);
    if (
      record?.agentId !== request.agentId ||
      record?.operationId !== request.operationId ||
      record?.status !== "installing"
    ) {
      return;
    }
    await atomicJson(request.pairingFile, {
      ...record,
      status: "failed",
      error: String(error?.message || error).slice(0, 300),
      updatedAt: this.now().toISOString(),
    });
  }

  #runtimeEnv(request) {
    return {
      ...serviceEnvironment(request),
      HOME: request.homeDir,
      OPENCLAW_HOME: request.homeDir,
      OPENCLAW_PROFILE: request.profile,
      OPENCLAW_STATE_DIR: request.stateDir,
      OPENCLAW_CONFIG_PATH: request.configPath,
    };
  }

  async #mustRun(argv, options = {}) {
    const result = await this.run(argv, options);
    if (result.code !== 0) throw new Error(`command failed: ${basename(argv[0])} ${argv.slice(1, 3).join(" ")}`);
    return result;
  }

  async #installedState(request) {
    try {
      const value = await readJson(join(request.root, "installed.json"));
      const releaseDir = resolve(String(value?.releaseDir || ""));
      if (
        value?.schema !== "t4l_host_install_state.v1" ||
        value.agentId !== request.agentId ||
        value.profile !== request.profile ||
        value.serviceId !== request.serviceId ||
        value.rootIdentity !== request.rootIdentity ||
        value.port !== request.port ||
        !SAFE_RELEASE_RE.test(String(value.releaseId || "")) ||
        typeof value.version !== "string" ||
        !SHA256_RE.test(String(value.manifestSha256 || "")) ||
        !releaseDir.startsWith(`${resolve(request.root, "releases")}/`) ||
        resolve(await readlink(join(request.root, "current"))) !== releaseDir
      ) {
        return null;
      }
      const release = await readJson(join(releaseDir, "release.json"));
      if (
        release?.schema !== "t4l_installed_release.v1" ||
        release.releaseId !== value.releaseId ||
        release.version !== value.version ||
        release.manifestSha256 !== value.manifestSha256
      ) {
        return null;
      }
      return { ...value, releaseDir };
    } catch {
      return null;
    }
  }

  async #verifyInstalled(request) {
    const state = await this.#installedState(request);
    if (!state) return { ok: false, code: "not_installed", checks: { state: false } };
    const checks = { state: true, release: false, service: false, connector: false };
    try {
      const release = await readJson(join(state.releaseDir, "release.json"));
      checks.release = release.releaseId === state.releaseId && release.manifestSha256 === state.manifestSha256;
    } catch {}
    try {
      const path = this.#servicePath(request);
      const info = await lstat(path);
      if (info.isFile() && !info.isSymbolicLink()) {
        const actual = await readFile(path, "utf8");
        const expected = await this.#expectedService(request);
        checks.service =
          typeof expected === "string"
            ? actual === expected
            : JSON.stringify(JSON.parse(actual)) === JSON.stringify(expected);
      }
    } catch {}
    try {
      const response = await this.fetch(`http://127.0.0.1:${request.port}/.well-known/t4l-agent`, { signal: AbortSignal.timeout(2_000) });
      const payload = await response.json();
      const target = payload?.installation?.targetRelease;
      checks.connector =
        response.ok &&
        payload?.agentId === request.agentId &&
        target?.releaseId === state.releaseId &&
        target?.version === state.version &&
        target?.manifestSha256 === state.manifestSha256;
    } catch {}
    return {
      ok: Object.values(checks).every(Boolean),
      code: Object.values(checks).every(Boolean) ? "verified" : "verification_failed",
      checks,
      installedRelease: {
        releaseId: state.releaseId,
        version: state.version,
        manifestSha256: state.manifestSha256,
        signingKeyId: state.signingKeyId,
      },
    };
  }

  async #rollback(request) {
    const snapshots = join(request.root, "snapshots");
    const id = safeHostText(request.rollbackOperationId, "rollbackOperationId", 140);
    const snapshot = await readJson(join(snapshots, id, "snapshot.json"));
    if (
      snapshot.agentId !== request.agentId ||
      snapshot.serviceId !== request.serviceId ||
      snapshot.rootIdentity !== request.rootIdentity
    ) {
      throw new Error("rollback snapshot belongs to another agent runtime");
    }
    await this.#restoreSnapshot(request, snapshot);
    return { ok: true, code: "rolled_back", checks: { restored: true } };
  }

  async #verifyLifecycle(request) {
    if (!request.dryRun) await this.#runtimeAction(request, "verify");
    return this.#verifyInstalled(request);
  }

  async #expectedService(request) {
    const mode = serviceMode(request, this.platform);
    const values = this.#parseEnv(
      await readFile(join(request.root, "secrets.env"), "utf8"),
    );
    const runtimeToken = values.T4L_CONNECTOR_RUNTIME_TOKEN;
    const serverToken = values.T4L_SERVER_API_KEY;
    if (!runtimeToken || !serverToken) {
      throw new Error("connector service credentials are incomplete");
    }
    if (mode === "none") {
      return {
        schema: "t4l_service_command.v1",
        command: this.#command(request),
        environmentFile: join(request.root, "secrets.env"),
        environment: serviceEnvironment(request),
      };
    }
    if (mode === "systemd") {
      return renderSystemdUnit({
        agentId: request.agentId,
        serviceId: request.serviceId,
        root: request.root,
        stateDir: request.stateDir,
        homeDir: request.homeDir,
        configPath: request.configPath,
        envFile: join(request.root, "secrets.env"),
        environment: serviceEnvironment(request),
        command: this.#command(request),
      });
    }
    return renderLaunchdPlist({
      label: `ai.t4l.agent.${request.serviceId}`,
      command: this.#command(request),
      environment: {
        ...serviceEnvironment(request),
        T4L_CONNECTOR_RUNTIME_TOKEN: runtimeToken,
        T4L_SERVER_API_KEY: serverToken,
        MCP_T4L_API_KEY: serverToken,
      },
      logFile: join(request.root, "logs", "service.log"),
    });
  }

  async #uninstall(request) {
    const operationId = request.operationId;
    const quarantine = join(request.root, "quarantine", operationId);
    let snapshot;
    try {
      snapshot = await readJson(
        join(request.root, "snapshots", operationId, "snapshot.json"),
      );
      await this.#restoreUninstallQuarantine(request, quarantine);
      await this.#restoreSnapshot(request, snapshot);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      snapshot = await this.#snapshot(request, operationId);
    }
    const moved = [];
    let runtimeMutationAttempted = false;
    try {
      runtimeMutationAttempted = true;
      await this.#uninstallRuntime(request);
      await this.hostMutationHook("runtime-uninstalled", request);
      await this.#stopService(request);
      await mkdir(quarantine, { recursive: true, mode: 0o700 });
      for (const name of ["releases", ...(request.removeData === true ? ["data"] : [])]) {
        const source = join(request.root, name);
        const target = join(quarantine, name);
        try {
          const info = await lstat(source);
          if (info.isSymbolicLink() || !info.isDirectory()) throw new Error(`unsafe uninstall target: ${name}`);
          await rename(source, target);
          moved.push({ source, target });
        } catch (error) {
          if (error?.code !== "ENOENT") throw error;
        }
      }
      await rm(this.#servicePath(request), { force: true });
      await rm(join(request.root, "current"), { force: true });
      await rm(join(request.root, "secrets.env"), { force: true });
      await this.#removeGatewaySecrets(request);
      // Removing this marker switches the Gateway back to bootstrap mode. It
      // is the final host commit after the runtime transaction succeeded.
      await rm(join(request.root, "installed.json"), { force: true });
      return { ok: true, code: "uninstalled", operationId, dataPreserved: request.removeData !== true };
    } catch (error) {
      for (const item of moved.reverse()) {
        try {
          await rename(item.target, item.source);
        } catch {}
      }
      try {
        await this.#restoreSnapshot(request, snapshot);
        if (runtimeMutationAttempted) {
          await this.#runtimeAction(request, "update");
          await this.#runtimeAction(request, "verify");
        }
      } catch (rollbackError) {
        throw new Error(
          `${error?.message || error}; uninstall rollback failed: ${rollbackError?.message || rollbackError}`,
        );
      }
      throw error;
    }
  }

  async #restoreUninstallQuarantine(request, quarantine) {
    for (const name of ["releases", "data"]) {
      const source = join(request.root, name);
      const target = join(quarantine, name);
      let targetInfo;
      try {
        targetInfo = await lstat(target);
      } catch (error) {
        if (error?.code === "ENOENT") continue;
        throw error;
      }
      if (targetInfo.isSymbolicLink() || !targetInfo.isDirectory()) {
        throw new Error(`unsafe uninstall quarantine entry: ${name}`);
      }
      try {
        await lstat(source);
        throw new Error(`uninstall recovery found two ${name} directories`);
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
      await rename(target, source);
    }
    await rm(quarantine, { recursive: true, force: true });
  }

  async #uninstallRuntime(request) {
    await this.#runtimeAction(request, "uninstall");
  }

  async #runtimeAction(request, action) {
    if (!new Set(["update", "verify", "uninstall"]).has(action)) {
      throw new Error("unsupported connector runtime action");
    }
    const values = this.#parseEnv(
      await readFile(join(request.root, "secrets.env"), "utf8"),
    );
    const runtimeToken = values.T4L_CONNECTOR_RUNTIME_TOKEN;
    if (!runtimeToken) throw new Error("connector runtime credential is missing");
    const headers = {
      "content-type": "application/json",
      "x-t4l-runtime-token": runtimeToken,
    };
    const response = await this.fetch(
      `http://127.0.0.1:${request.port}/v1/setup/runtime-action`,
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          schema: "t4l_runtime_setup_action.v1",
          action,
        }),
        signal: AbortSignal.timeout(10_000),
      },
    );
    let operation = await response.json().catch(() => ({}));
    if (!response.ok || !OPERATION_ID_RE.test(String(operation?.operationId || ""))) {
      throw new Error(operation?.error?.message || "runtime uninstall could not start");
    }
    for (let attempt = 0; attempt < 120; attempt += 1) {
      if (operation?.terminal === true) {
        const successful = action === "uninstall" ? "uninstalled" : "ready";
        if (operation.status === successful) return operation;
        throw new Error(
          operation?.error?.message ||
            `runtime ${action} ended as ${String(operation?.status || "failed")}`,
        );
      }
      await this.sleep(500);
      const status = await this.fetch(
        `http://127.0.0.1:${request.port}/v1/setup/runtime-operations/${operation.operationId}`,
        {
          headers: { "x-t4l-runtime-token": runtimeToken },
          signal: AbortSignal.timeout(10_000),
        },
      );
      operation = await status.json().catch(() => ({}));
      if (!status.ok) {
        throw new Error(operation?.error?.message || "runtime uninstall status failed");
      }
    }
    throw new Error(`runtime ${action} did not finish within one minute`);
  }

  async #removeGatewaySecrets(request) {
    const path = join(request.stateDir, ".env");
    let existing;
    try {
      const info = await lstat(path);
      if (info.isSymbolicLink() || !info.isFile()) {
        throw new Error("unsafe OpenClaw environment file");
      }
      existing = await readFile(path, "utf8");
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
    const kept = existing
      .split(/\r?\n/)
      .filter(
        (line) =>
          !line.startsWith("T4L_CONNECTOR_RUNTIME_TOKEN=") &&
          !line.startsWith("MCP_T4L_API_KEY="),
      )
      .filter(Boolean);
    await atomicText(path, kept.length ? `${kept.join("\n")}\n` : "", 0o600);
  }

  async #snapshotGatewayEnv(request) {
    const path = join(request.stateDir, ".env");
    try {
      const info = await lstat(path);
      if (info.isSymbolicLink() || !info.isFile()) {
        throw new Error("unsafe OpenClaw environment file");
      }
      const ownedLines = (await readFile(path, "utf8"))
        .split(/\r?\n/)
        .filter(
          (line) =>
            line.startsWith("T4L_CONNECTOR_RUNTIME_TOKEN=") ||
            line.startsWith("MCP_T4L_API_KEY="),
        );
      return { path, existed: true, ownedLines };
    } catch (error) {
      if (error?.code === "ENOENT") return { path, existed: false, ownedLines: [] };
      throw error;
    }
  }

  async #restoreGatewayEnv(request, snapshot) {
    const path = safeHostText(snapshot.path, "snapshot gateway env path", 4096);
    if (resolve(path) !== resolve(request.stateDir, ".env")) {
      throw new Error("snapshot Gateway environment path is invalid");
    }
    let current = "";
    try {
      const info = await lstat(path);
      if (info.isSymbolicLink() || !info.isFile()) {
        throw new Error("unsafe OpenClaw environment file");
      }
      current = await readFile(path, "utf8");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    const kept = current
      .split(/\r?\n/)
      .filter(
        (line) =>
          line &&
          !line.startsWith("T4L_CONNECTOR_RUNTIME_TOKEN=") &&
          !line.startsWith("MCP_T4L_API_KEY="),
      );
    const owned = Array.isArray(snapshot.ownedLines)
      ? snapshot.ownedLines.filter(
          (line) =>
            typeof line === "string" &&
            (line.startsWith("T4L_CONNECTOR_RUNTIME_TOKEN=") ||
              line.startsWith("MCP_T4L_API_KEY=")) &&
            !CONTROL_RE.test(line),
        )
      : [];
    const lines = [...kept, ...owned];
    if (!snapshot.existed && lines.length === 0) {
      await unlink(path).catch((error) => {
        if (error?.code !== "ENOENT") throw error;
      });
      return;
    }
    await atomicText(path, lines.length ? `${lines.join("\n")}\n` : "", 0o600);
  }

  async #pruneSnapshots(request, keepOperationId) {
    const root = join(request.root, "snapshots");
    let names;
    try {
      names = await readdir(root);
    } catch {
      return;
    }
    const candidates = [];
    for (const name of names) {
      if (name === keepOperationId || !OPERATION_ID_RE.test(name)) continue;
      const path = join(root, name);
      try {
        const info = await lstat(path);
        if (info.isDirectory() && !info.isSymbolicLink()) {
          candidates.push({ path, modified: info.mtimeMs });
        }
      } catch {}
    }
    candidates.sort((left, right) => right.modified - left.modified);
    for (const entry of candidates.slice(9)) {
      await rm(entry.path, { recursive: true, force: true });
    }
  }
}

export async function readOperation(root, operationId) {
  if (!/^op_[A-Za-z0-9_-]{8,128}$/.test(String(operationId))) return null;
  try {
    return await readJson(join(root, "bootstrap", "operations", `${operationId}.json`));
  } catch {
    return null;
  }
}
