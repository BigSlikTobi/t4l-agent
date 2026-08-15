import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { mkdir, open, readFile, readdir, rename, stat, unlink, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";

export const BOOTSTRAP_SCHEMA = "t4l_agent_bootstrap.v1";
export const PAIRING_TTL_MS = 10 * 60 * 1000;
export const PAIRING_COMPLETION_TTL_MS = 30 * 60 * 1000;
export const MAX_PAIRING_FAILURES = 5;
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const ID_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const CODE_RE = /^[A-Z2-9]{4}-[A-Z2-9]{4}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function decodeB64url(value) {
  if (typeof value !== "string" || !BASE64URL_RE.test(value)) {
    return null;
  }
  try {
    return Buffer.from(value, "base64url");
  } catch {
    return null;
  }
}

function safeString(value, max) {
  return typeof value === "string" && value.trim() && value.length <= max
    ? value.trim()
    : null;
}

function normalizeCode(value) {
  if (typeof value !== "string") return null;
  const compact = value.toUpperCase().replaceAll("-", "");
  if (compact.length !== 8 || [...compact].some((item) => !CODE_ALPHABET.includes(item))) {
    return null;
  }
  return `${compact.slice(0, 4)}-${compact.slice(4)}`;
}

function hashCode(value, salt) {
  return createHash("sha256")
    .update("t4l-bootstrap-code-v1\0")
    .update(salt)
    .update(value)
    .digest("hex");
}

function equalText(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function pairingSummary(record) {
  const proofExpiresAt =
    record.status === "installing" && record.completionExpiresAt
      ? record.completionExpiresAt
      : record.expiresAt;
  return {
    requestId: record.requestId,
    pairingRequestId: record.requestId,
    agentId: record.agentId,
    deviceId: record.deviceId,
    challenge: record.challenge,
    expiresAt: proofExpiresAt,
    codeExpiresAt: record.expiresAt,
    ...(record.confirmedAt ? { confirmedAt: record.confirmedAt } : {}),
    ...(record.completionExpiresAt
      ? { completionExpiresAt: record.completionExpiresAt }
      : {}),
    status: record.status,
    failedAttempts: record.failedAttempts,
  };
}

function deviceId(publicKey) {
  return `dev_${createHash("sha256").update(publicKey, "utf8").digest("hex").slice(0, 24)}`;
}

async function atomicJson(path, value, mode = 0o600) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    mode,
    flag: "wx",
  });
  await rename(temporary, path);
}

async function readJson(path) {
  const info = await stat(path);
  if (!info.isFile()) throw new Error("state entry is not a file");
  return JSON.parse(await readFile(path, "utf8"));
}

function randomCode() {
  const bytes = randomBytes(8);
  let compact = "";
  for (const byte of bytes) compact += CODE_ALPHABET[byte % CODE_ALPHABET.length];
  return `${compact.slice(0, 4)}-${compact.slice(4)}`;
}

export function resolveAgentId(api, config) {
  const explicit = safeString(config?.agentId, 64);
  if (explicit && ID_RE.test(explicit)) return explicit;
  const fromEnv = safeString(process.env.T4L_AGENT_ID, 64);
  if (fromEnv && ID_RE.test(fromEnv)) return fromEnv;
  const listed = api?.config?.agents?.list;
  if (Array.isArray(listed)) {
    const valid = listed.filter((item) => {
      const id = safeString(item?.id, 64);
      return id && ID_RE.test(id);
    });
    const ids = valid.map((item) => safeString(item.id, 64));
    if (ids.length === 1) return ids[0];
    const defaults = valid
      .filter((item) => item?.default === true)
      .map((item) => safeString(item.id, 64));
    if (defaults.length === 1) return defaults[0];
    if (ids.length > 1) {
      throw new Error(
        "T4L found multiple OpenClaw agents. Set plugin config agentId once.",
      );
    }
  }
  return "main";
}

export function resolveStateRoot(config, agentId) {
  const home = process.env.OPENCLAW_HOME || process.env.HOME;
  const profile = process.env.OPENCLAW_PROFILE;
  const defaultState =
    home && isAbsolute(home) && resolve(home) !== "/"
      ? join(home, profile && profile !== "default" ? `.openclaw-${profile}` : ".openclaw")
      : "";
  const stateDir = process.env.OPENCLAW_STATE_DIR || defaultState;
  const configured = safeString(config?.installRoot, 4096);
  const root = configured || (stateDir ? join(stateDir, "t4l", agentId) : "");
  if (!root || !isAbsolute(root)) {
    throw new Error("T4L bootstrap needs an absolute isolated install root.");
  }
  return resolve(root);
}

export class BootstrapPairingStore {
  constructor(root, agentId, now = () => Date.now(), runtimeIdentity = null) {
    if (!isAbsolute(root) || !ID_RE.test(agentId)) throw new Error("invalid pairing store identity");
    this.root = resolve(root);
    this.agentId = agentId;
    this.now = now;
    this.runtimeIdentity = runtimeIdentity || {
      schema: "t4l_bootstrap_runtime_identity.v1",
      agentId,
      rootIdentity: createHash("sha256")
        .update(`legacy-test\0${this.root}\0${agentId}`)
        .digest("hex"),
    };
    if (
      this.runtimeIdentity.schema !== "t4l_bootstrap_runtime_identity.v1" ||
      this.runtimeIdentity.agentId !== agentId ||
      !/^[a-f0-9]{64}$/.test(String(this.runtimeIdentity.rootIdentity || ""))
    ) {
      throw new Error("invalid OpenClaw runtime identity");
    }
    this.pairingDir = join(this.root, "bootstrap", "pairings");
    this.mutationTail = Promise.resolve();
  }

  async create(payload) {
    return this.#withMutationLock(() => this.#createUnlocked(payload));
  }

  async #createUnlocked(payload) {
    const publicKey = safeString(payload?.devicePublicKey, 128);
    const publicKeyBytes = decodeB64url(publicKey);
    const deviceName = safeString(payload?.deviceName, 100);
    const platform = safeString(payload?.platform, 40)?.toLowerCase();
    if (!publicKeyBytes || publicKeyBytes.length !== 32) throw new Error("devicePublicKey must be a raw Ed25519 public key");
    if (!deviceName || !platform) throw new Error("deviceName and platform are required");
    await mkdir(this.pairingDir, { recursive: true, mode: 0o700 });
    await this.#prune();
    const active = (await this.#records()).filter((record) =>
      ["pending", "installing"].includes(record.status),
    );
    const samePhone = active.find(
      (record) => record.devicePublicKey === publicKey,
    );
    if (samePhone) {
      return { ...pairingSummary(samePhone), code: samePhone.code, reused: true };
    }
    const otherPhone = active.find((record) => record.devicePublicKey !== publicKey);
    if (otherPhone) {
      const error = new Error("another phone pairing is already in progress");
      error.code = "pairing_in_progress";
      error.retryAfterSeconds = Math.max(
        1,
        Math.ceil(
          (new Date(otherPhone.completionExpiresAt || otherPhone.expiresAt).getTime() -
            this.now()) /
            1000,
        ),
      );
      throw error;
    }
    const created = new Date(this.now());
    const expires = new Date(created.getTime() + PAIRING_TTL_MS);
    const code = randomCode();
    const salt = randomBytes(16);
    const requestId = `pair_${b64url(randomBytes(18))}`;
    const record = {
      schema: "t4l_bootstrap_pairing.v1",
      requestId,
      agentId: this.agentId,
      deviceId: deviceId(publicKey),
      devicePublicKey: publicKey,
      deviceName,
      platform,
      challenge: b64url(randomBytes(32)),
      codeSalt: b64url(salt),
      codeHash: hashCode(code.replaceAll("-", ""), salt),
      code,
      status: "pending",
      failedAttempts: 0,
      createdAt: created.toISOString(),
      expiresAt: expires.toISOString(),
      updatedAt: created.toISOString(),
    };
    await atomicJson(this.#path(requestId), record);
    return { ...pairingSummary(record), code };
  }

  async find(requestId) {
    if (!/^pair_[A-Za-z0-9_-]{12,64}$/.test(String(requestId))) return null;
    try {
      const record = await readJson(this.#path(requestId));
      return record?.agentId === this.agentId ? record : null;
    } catch {
      return null;
    }
  }

  async installingRecords() {
    return (await this.#records()).filter(
      (record) =>
        record.status === "installing" &&
        new Date(record.completionExpiresAt).getTime() > this.now() &&
        /^op_[A-Za-z0-9_-]{8,128}$/.test(String(record.operationId)),
    );
  }

  async match(code) {
    return this.#withMutationLock(() => this.#matchUnlocked(code));
  }

  async #matchUnlocked(code) {
    const normalized = normalizeCode(code);
    if (!normalized) return null;
    const now = this.now();
    const records = await this.#records();
    for (const record of records.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))) {
      const salt = decodeB64url(record.codeSalt);
      if (!salt) continue;
      const digest = hashCode(normalized.replaceAll("-", ""), salt);
      if (equalText(digest, record.codeHash)) {
        if (new Date(record.expiresAt).getTime() <= now) {
          if (record.status === "pending") {
            await this.#update(record, { status: "expired" });
          }
          return null;
        }
        return record;
      }
    }
    return null;
  }

  async fail(record) {
    return this.#withMutationLock(async () => {
      const current = await this.find(record.requestId);
      return current ? this.#failUnlocked(current) : record;
    });
  }

  async #failUnlocked(record) {
    if (record.status !== "pending") return record;
    const failures = Math.min(MAX_PAIRING_FAILURES, Number(record.failedAttempts || 0) + 1);
    return this.#update(record, {
      failedAttempts: failures,
      status: failures >= MAX_PAIRING_FAILURES ? "locked" : record.status,
    });
  }

  async failActive() {
    return this.#withMutationLock(async () => {
      const active = (await this.#records()).filter(
        (record) => record.status === "pending" && new Date(record.expiresAt).getTime() > this.now(),
      );
      for (const record of active) await this.#failUnlocked(record);
      return active.length;
    });
  }

  async confirm(record, owner, operationId) {
    return this.#withMutationLock(async () => {
      const current = await this.find(record.requestId);
      if (
        !current ||
        current.status !== "pending" ||
        new Date(current.expiresAt).getTime() <= this.now()
      ) {
        throw new Error("pairing request is no longer pending");
      }
      const confirmed = new Date(this.now());
      return this.#update(current, {
        status: "installing",
        confirmedAt: confirmed.toISOString(),
        completionExpiresAt: new Date(
          confirmed.getTime() + PAIRING_COMPLETION_TTL_MS,
        ).toISOString(),
        channel: owner.channel,
        verifiedAccountId: owner.accountId,
        verifiedSenderId: owner.senderId,
        operationId,
      });
    });
  }

  async mark(record, status, details = {}) {
    return this.#withMutationLock(async () => {
      const current = await this.find(record.requestId);
      return current
        ? this.#update(current, { status, ...details })
        : record;
    });
  }

  summary(record) {
    return pairingSummary(record);
  }

  adoptionPayload(record) {
    return {
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
    };
  }

  async #records() {
    try {
      const names = await readdir(this.pairingDir);
      const records = [];
      for (const name of names) {
        if (!name.endsWith(".json")) continue;
        try {
          const record = await readJson(join(this.pairingDir, name));
          if (record?.schema === "t4l_bootstrap_pairing.v1" && record.agentId === this.agentId) records.push(record);
        } catch {
          // Corrupt records fail closed and are never used for pairing.
        }
      }
      return records;
    } catch {
      return [];
    }
  }

  async #prune() {
    const now = this.now();
    const records = await this.#records();
    for (const record of records) {
      const expires = new Date(record.expiresAt).getTime();
      const completionExpires = new Date(
        record.completionExpiresAt || record.expiresAt,
      ).getTime();
      if (record.status === "pending" && expires <= now) {
        await this.#update(record, { status: "expired" });
      } else if (record.status === "installing" && completionExpires <= now) {
        await this.#update(record, { status: "expired" });
      } else if (
        !["pending", "installing"].includes(record.status) &&
        Number.isFinite(completionExpires) &&
        completionExpires + 24 * 60 * 60 * 1000 < now
      ) {
        await unlink(this.#path(record.requestId)).catch(() => {});
      }
    }
    const active = (await this.#records())
      .filter(
        (record) =>
          ["pending", "installing"].includes(record.status) &&
          new Date(
            record.status === "installing"
              ? record.completionExpiresAt
              : record.expiresAt,
          ).getTime() > now,
      )
      .sort((left, right) => String(right.createdAt).localeCompare(String(left.createdAt)));
    for (const duplicate of active.slice(1)) {
      await this.#update(duplicate, { status: "superseded" });
    }
  }

  async #update(record, patch) {
    const updated = {
      ...record,
      ...patch,
      updatedAt: new Date(this.now()).toISOString(),
    };
    await atomicJson(this.#path(record.requestId), updated);
    return updated;
  }

  #path(requestId) {
    return join(this.pairingDir, `${requestId}.json`);
  }

  async #withMutationLock(callback) {
    let releaseQueue;
    const predecessor = this.mutationTail;
    this.mutationTail = new Promise((resolvePromise) => {
      releaseQueue = resolvePromise;
    });
    await predecessor;
    let release = null;
    try {
      for (let attempt = 0; attempt < 200; attempt += 1) {
        try {
          release = await acquireLock(
            join(this.root, "bootstrap", "pairing-store.lock"),
          );
          break;
        } catch (error) {
          if (
            !String(error?.message || error).includes(
              "another T4L bootstrap operation",
            ) ||
            attempt === 199
          ) {
            throw error;
          }
          await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
        }
      }
      if (!release) throw new Error("T4L pairing store lock could not be acquired");
      await this.#ensureIdentity();
      return await callback();
    } finally {
      if (release) await release();
      releaseQueue();
    }
  }

  async #ensureIdentity() {
    const path = join(this.root, "bootstrap", "identity.json");
    try {
      const identity = await readJson(path);
      if (
        identity?.schema !== "t4l_bootstrap_root_identity.v2" ||
        identity?.agentId !== this.agentId ||
        identity?.rootIdentity !== this.runtimeIdentity.rootIdentity
      ) {
        throw new Error("T4L install root belongs to another agent");
      }
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      await atomicJson(path, {
        ...this.runtimeIdentity,
        schema: "t4l_bootstrap_root_identity.v2",
        createdAt: new Date(this.now()).toISOString(),
      });
    }
  }
}

export function bootstrapDiscovery(agentId, operation = null) {
  return {
    schema: BOOTSTRAP_SCHEMA,
    agentId,
    runtime: "openclaw",
    pairingSupported: true,
    connectorInstalled: false,
    capabilities: [
      "code-pairing",
      "device-proof-of-possession",
      "scoped-device-tokens",
      "setup-operations",
      "bootstrap-pairing-adoption",
      "nutrition-guidance-block-v1",
    ],
    features: {
      codePairing: true,
      deviceProofOfPossession: true,
      scopedTokens: ["chat", "status", "sync"],
      setupOperations: true,
      httpsRequired: true,
    },
    bootstrap: {
      status: operation?.status || "ready",
      package: "@t4l/openclaw-t4l-connect",
      version: "0.2.0",
      installCommand: "/t4l connect CODE",
      retryAfterSeconds: 3,
      ...(operation?.operationId ? { operationId: operation.operationId } : {}),
    },
  };
}

export async function acquireLock(path) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const token = b64url(randomBytes(18));
    try {
      const handle = await open(path, "wx", 0o600);
      await handle.writeFile(`${JSON.stringify({ pid: process.pid, token, createdAt: new Date().toISOString() })}\n`);
      return async () => {
        await handle.close();
        try {
          const current = JSON.parse(await readFile(path, "utf8"));
          if (current?.token === token) await unlink(path);
        } catch {}
      };
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      let ownerPid = null;
      try {
        const value = (await readFile(path, "utf8")).trim();
        ownerPid = value.startsWith("{") ? Number(JSON.parse(value).pid) : Number(value);
      } catch {}
      let alive = Number.isSafeInteger(ownerPid) && ownerPid > 1;
      if (alive) {
        try {
          process.kill(ownerPid, 0);
        } catch (probeError) {
          alive = probeError?.code !== "ESRCH";
        }
      }
      if (alive || attempt > 0) {
        throw new Error("another T4L bootstrap operation is running");
      }
      await unlink(path).catch((unlinkError) => {
        if (unlinkError?.code !== "ENOENT") throw unlinkError;
      });
    }
  }
  throw new Error("another T4L bootstrap operation is running");
}

export { atomicJson, normalizeCode, readJson };
