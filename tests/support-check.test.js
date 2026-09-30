import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import WebSocket, { WebSocketServer } from "ws";
import { probeRemoteSupport } from "../app/lib/mesh-support-check.js";

const nodeId = "node//" + "Ab$c@D".repeat(12);
const challenge = "a".repeat(64);
function packet(command, content = Buffer.alloc(0)) {
  const header = Buffer.alloc(4); header.writeUInt16BE(command); header.writeUInt16BE(content.length + 4, 2);
  return Buffer.concat([header, content]);
}
async function fixture(mode, run) {
  const http = createServer(); const wss = new WebSocketServer({ server: http });
  await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
  let commandCount = 0, relayCount = 0;
  const target = `ws://127.0.0.1:${http.address().port}`;
  class TestSocket extends WebSocket {
    constructor(url, options) {
      const incoming = new URL(url);
      assert.equal(incoming.protocol, "wss:"); assert.equal(options.rejectUnauthorized, true);
      super(target + incoming.pathname + incoming.search, options);
    }
  }
  wss.on("connection", (socket, request) => {
    const url = new URL(request.url, target);
    if (url.pathname.endsWith("control.ashx")) {
      assert.ok(request.headers["x-meshauth"]);
      socket.on("message", (raw) => {
        const data = JSON.parse(String(raw));
        if (data.action === "authcookie") socket.send(JSON.stringify({ action: "authcookie", cookie: "test-cookie", rcookie: "test-agent-cookie" }));
        if (data.action === "msg") { assert.equal(data.usage, 2); assert.equal(data.nodeid, nodeId); }
        if (data.action === "runcommands") {
          commandCount++;
          assert.deepEqual(data.nodeids, [nodeId]); assert.equal(data.type, 2); assert.equal(data.runAsUser, 0);
          assert.ok(data.cmds.includes(`support-${challenge}.txt`));
          socket.send(JSON.stringify({ action: "runcommands", responseid: data.responseid, result: mode === "deny-command" ? "Access denied" : "OK" }));
        }
      });
    } else {
      relayCount++;
      assert.equal(url.searchParams.get("nodeid"), nodeId); // '$' and '@' survive URL encoding
      assert.equal(url.searchParams.get("p"), "2");
      socket.send("c");
      socket.once("message", () => {
        if (mode === "pair-only") return;
        const size = Buffer.alloc(4); size.writeUInt16BE(1280); size.writeUInt16BE(720, 2);
        // Send a padded irrelevant packet, then the desktop dimensions.
        socket.send(Buffer.concat([packet(14), Buffer.alloc(4)]));
        socket.send(packet(7, size));
        if (mode === "size-only") return;
        const image = Buffer.concat([Buffer.alloc(4), Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 1, 2, 3])]);
        const tile = packet(3, image);
        if (mode === "fragmented") { socket.send(tile.subarray(0, 6)); socket.send(tile.subarray(6)); }
        else if (mode === "jumbo") {
          const jumbo = Buffer.alloc(8); jumbo.writeUInt16BE(27); jumbo.writeUInt16BE(8, 2); jumbo.writeUInt32BE(tile.length, 4);
          socket.send(Buffer.concat([jumbo, tile]));
        } else socket.send(tile);
      });
    }
  });
  try { await run({ Socket: TestSocket, stats: () => ({ commandCount, relayCount }) }); }
  finally { for (const socket of wss.clients) socket.terminate(); await new Promise((resolve) => wss.close(resolve)); await new Promise((resolve) => http.close(resolve)); }
}
const options = { controlUrl: "wss://support.test/control.ashx", user: "operator", pass: "test-only", timeoutMs: 500 };
for (const mode of ["normal", "fragmented", "jumbo"]) {
  test(`desktop frame + fixed command round-trip (${mode})`, async () => fixture(mode, async ({ Socket, stats }) => {
    assert.deepEqual(await probeRemoteSupport(nodeId, challenge, { ...options, Socket }), { desktop_verified: true, command_dispatched: true });
    assert.equal(stats().commandCount, 1);
  }));
}
for (const mode of ["pair-only", "size-only"]) {
  test(`fails closed when only ${mode} is available`, async () => fixture(mode, async ({ Socket, stats }) => {
    await assert.rejects(probeRemoteSupport(nodeId, challenge, { ...options, Socket }), /timeout/);
    assert.equal(stats().commandCount, 0);
  }));
}
test("remote command denial fails verification", async () => fixture("deny-command", async ({ Socket }) => {
  await assert.rejects(probeRemoteSupport(nodeId, challenge, { ...options, Socket }), /command_rejected/);
}));
test("unsafe targets and plain-text control URLs are rejected", async () => {
  await assert.rejects(probeRemoteSupport(nodeId, challenge, { ...options, controlUrl: "ws://support.test/control.ashx" }), /not_configured/);
  await assert.rejects(probeRemoteSupport("foreign';cmd", challenge, options), /invalid_support_identity/);
});
