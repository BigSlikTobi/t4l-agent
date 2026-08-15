import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createT4LConnectPlugin } from "../dist/index.js";

let registrationId = 0;

function register(fetchImpl) {
  let command;
  registrationId += 1;
  createT4LConnectPlugin(fetchImpl).register({
    pluginConfig: {
      agentId: "agent-01",
      installRoot: join(
        tmpdir(),
        `t4l-openclaw-plugin-unit-${process.pid}-${registrationId}`,
      ),
      connectorBaseUrl: "http://127.0.0.1:8787",
    },
    registerCommand(value) {
      command = value;
    },
  });
  return command;
}

test("registers an authenticated pre-model command", () => {
  const command = register(async () => {
    throw new Error("not called");
  });
  assert.equal(command.name, "t4l");
  assert.equal(command.requireAuth, true);
  assert.deepEqual(command.requiredScopes, ["operator.pairing"]);
  assert.equal("ownerOnly" in command, false);
});

test("posts only verified owner identity and the T4L code", async () => {
  const previous = process.env.T4L_CONNECTOR_RUNTIME_TOKEN;
  process.env.T4L_CONNECTOR_RUNTIME_TOKEN = "runtime-secret";
  let request;
  const command = register(async (url, init) => {
    request = { url, init };
    return {
      ok: true,
      async json() {
        return { status: "confirmed" };
      },
    };
  });
  try {
    const result = await command.handler({
      agentId: "agent-01",
      args: "connect ABCD-1234",
      senderId: "owner-id",
      channel: "slack",
      accountId: "workspace-01",
      isAuthorizedSender: true,
      senderIsOwner: true,
      gatewayClientScopes: ["operator.pairing"],
    });
    assert.match(result.text, /confirmed/i);
    assert.equal(
      request.url,
      "http://127.0.0.1:8787/v1/pairing/channel-confirmation",
    );
    assert.deepEqual(JSON.parse(request.init.body), {
      code: "ABCD-1234",
      channel: "slack",
      verifiedAccountId: "workspace-01",
      verifiedSenderId: "owner-id",
    });
    assert.equal(request.init.headers["x-t4l-runtime-token"], "runtime-secret");
    assert.equal(request.init.body.includes("isAdmin"), false);
  } finally {
    if (previous === undefined) {
      delete process.env.T4L_CONNECTOR_RUNTIME_TOKEN;
    } else {
      process.env.T4L_CONNECTOR_RUNTIME_TOKEN = previous;
    }
  }
});

test("supports an authenticated OpenClaw web chat command context", async () => {
  const previous = process.env.T4L_CONNECTOR_RUNTIME_TOKEN;
  process.env.T4L_CONNECTOR_RUNTIME_TOKEN = "runtime-secret";
  let body;
  const command = register(async (_url, init) => {
    body = JSON.parse(init.body);
    return {
      ok: true,
      async json() {
        return { status: "confirmed" };
      },
    };
  });
  try {
    const result = await command.handler({
      agentId: "agent-01",
      args: "connect WEB1-2345",
      senderId: "web-owner-id",
      channel: "webchat",
      accountId: "local-webchat",
      isAuthorizedSender: true,
      senderIsOwner: true,
      gatewayClientScopes: ["operator.pairing"],
    });
    assert.match(result.text, /confirmed/i);
    assert.deepEqual(body, {
      code: "WEB1-2345",
      channel: "webchat",
      verifiedAccountId: "local-webchat",
      verifiedSenderId: "web-owner-id",
    });
  } finally {
    if (previous === undefined) {
      delete process.env.T4L_CONNECTOR_RUNTIME_TOKEN;
    } else {
      process.env.T4L_CONNECTOR_RUNTIME_TOKEN = previous;
    }
  }
});

test("supports the actual Gateway admin webchat context without route IDs", async () => {
  const previous = process.env.T4L_CONNECTOR_RUNTIME_TOKEN;
  process.env.T4L_CONNECTOR_RUNTIME_TOKEN = "runtime-secret";
  let body;
  const command = register(async (_url, init) => {
    body = JSON.parse(init.body);
    return { ok: true, async json() { return { status: "confirmed" }; } };
  });
  try {
    const result = await command.handler({
      agentId: "agent-01",
      args: "connect WEB1-2345",
      channel: "webchat",
      isAuthorizedSender: true,
      senderIsOwner: true,
      gatewayClientScopes: ["operator.admin", "operator.pairing"],
    });
    assert.match(result.text, /confirmed/i);
    assert.deepEqual(body, {
      code: "WEB1-2345",
      channel: "webchat",
      verifiedAccountId: "gateway",
      verifiedSenderId: "operator-admin",
    });
    const rejected = await command.handler({
      agentId: "agent-01",
      args: "connect WEB1-2345",
      channel: "webchat",
      isAuthorizedSender: true,
      senderIsOwner: true,
      gatewayClientScopes: [],
    });
    assert.match(rejected.text, /complete verified owner identity/i);
  } finally {
    if (previous === undefined) delete process.env.T4L_CONNECTOR_RUNTIME_TOKEN;
    else process.env.T4L_CONNECTOR_RUNTIME_TOKEN = previous;
  }
});

test("rejects a command routed to the wrong isolated agent", async () => {
  let called = false;
  const command = register(async () => {
    called = true;
  });
  const result = await command.handler({
    agentId: "agent-02",
    args: "connect ABCD-1234",
    senderId: "owner-id",
    channel: "slack",
    accountId: "workspace-01",
    isAuthorizedSender: true,
    senderIsOwner: true,
    gatewayClientScopes: ["operator.pairing"],
  });
  assert.match(result.text, /different T4L agent/i);
  assert.equal(called, false);
});

test("rejects a sender OpenClaw did not verify as owner", async () => {
  let called = false;
  const command = register(async () => {
    called = true;
  });
  const result = await command.handler({
    agentId: "agent-01",
    args: "connect ABCD-1234",
    senderId: "owner-id",
    channel: "slack",
    accountId: "workspace-01",
    isAuthorizedSender: true,
    senderIsOwner: false,
  });
  assert.match(result.text, /did not verify.*owner/i);
  assert.equal(called, false);
});

test("rejects an owner context OpenClaw did not authorize", async () => {
  let called = false;
  const command = register(async () => {
    called = true;
  });
  const result = await command.handler({
    agentId: "agent-01",
    args: "connect ABCD-1234",
    senderId: "owner-id",
    channel: "slack",
    accountId: "workspace-01",
    isAuthorizedSender: false,
    senderIsOwner: true,
  });
  assert.match(result.text, /did not verify.*owner/i);
  assert.equal(called, false);
});

test("rejects incomplete verified owner identity", async () => {
  let called = false;
  const command = register(async () => {
    called = true;
  });
  const missingSender = await command.handler({
    agentId: "agent-01",
    args: "connect ABCD-1234",
    channel: "slack",
    accountId: "workspace-01",
    isAuthorizedSender: true,
    senderIsOwner: true,
    gatewayClientScopes: ["operator.pairing"],
  });
  const missingChannel = await command.handler({
    agentId: "agent-01",
    args: "connect ABCD-1234",
    senderId: "owner-id",
    accountId: "workspace-01",
    isAuthorizedSender: true,
    senderIsOwner: true,
    gatewayClientScopes: ["operator.pairing"],
  });
  const missingAccount = await command.handler({
    agentId: "agent-01",
    args: "connect ABCD-1234",
    senderId: "owner-id",
    channel: "slack",
    isAuthorizedSender: true,
    senderIsOwner: true,
    gatewayClientScopes: ["operator.pairing"],
  });
  assert.match(missingSender.text, /complete verified owner identity/i);
  assert.match(missingChannel.text, /complete verified owner identity/i);
  assert.match(missingAccount.text, /complete verified owner identity/i);
  assert.equal(called, false);
});

test("propagates a connector authorization error without exposing credentials", async () => {
  const previous = process.env.T4L_CONNECTOR_RUNTIME_TOKEN;
  process.env.T4L_CONNECTOR_RUNTIME_TOKEN = "runtime-secret";
  const command = register(async () => ({
    ok: false,
    async json() {
      return {
        error: {
          code: "owner_not_allowed",
          message: "This sender is not on the connector owner allowlist.",
        },
      };
    },
  }));
  try {
    const result = await command.handler({
      agentId: "agent-01",
      args: "connect ABCD-1234",
      senderId: "not-owner",
      channel: "slack",
      accountId: "workspace-01",
      isAuthorizedSender: true,
      senderIsOwner: true,
      gatewayClientScopes: ["operator.pairing"],
    });
    assert.equal(
      result.text,
      "This sender is not on the connector owner allowlist.",
    );
    assert.equal(result.text.includes("runtime-secret"), false);
  } finally {
    if (previous === undefined) {
      delete process.env.T4L_CONNECTOR_RUNTIME_TOKEN;
    } else {
      process.env.T4L_CONNECTOR_RUNTIME_TOKEN = previous;
    }
  }
});
