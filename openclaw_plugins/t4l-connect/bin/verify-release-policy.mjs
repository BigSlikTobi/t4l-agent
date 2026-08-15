#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policy = JSON.parse(await readFile(join(root, "release-policy.json"), "utf8"));
const placeholder = JSON.stringify(policy).includes("REPLACE_");

if (placeholder && process.env.T4L_ALLOW_PLACEHOLDER_PACKAGE !== "development-only") {
  throw new Error(
    "release-policy.json is a fail-closed placeholder; stage a signed production policy before packing",
  );
}
if (!placeholder) {
  const key = Buffer.from(String(policy.signingPublicKey || ""), "base64url");
  if (key.length !== 32 || !String(policy.manifestUrl || "").startsWith("https://")) {
    throw new Error("release-policy.json does not contain a valid pinned release key and HTTPS manifest");
  }
}
