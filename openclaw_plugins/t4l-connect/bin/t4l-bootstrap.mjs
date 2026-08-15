#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { HostInstaller } from "../dist/installer.js";

async function main() {
  const [action, requestPath] = process.argv.slice(2);
  if (!action || !requestPath || !["install", "update", "verify", "rollback", "uninstall"].includes(action)) {
    process.stderr.write("Usage: t4l-openclaw-bootstrap <install|update|verify|rollback|uninstall> /absolute/request.json\n");
    return 2;
  }
  const path = resolve(requestPath);
  const request = JSON.parse(await readFile(path, "utf8"));
  if (request.action !== action) throw new Error("CLI action does not match signed operation request");
  const result = await new HostInstaller().execute(request);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  return result.ok ? 0 : 1;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(`${String(error?.message || error).replaceAll("\n", " ").slice(0, 500)}\n`);
    process.exitCode = 1;
  });
