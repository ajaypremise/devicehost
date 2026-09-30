import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import { POST } from "../app/api/setup/verify-support/route.js";

test("missing device token rejected before database access", async () => {
  const response = await POST(new Request("https://devicehost.test/api/setup/verify-support", { method: "POST" }));
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("cache-control"), "no-store");
});
test("device authentication and pending/stale support fail closed", async () => {
  const oldFetch = globalThis.fetch;
  const oldURL = process.env.SUPABASE_URL, oldKey = process.env.SUPABASE_SECRET_KEY;
  process.env.SUPABASE_URL = "https://database.test"; process.env.SUPABASE_SECRET_KEY = "server-only-test-key";
  const token = "test-device-token";
  try {
    for (const [rows, expected] of [
      [[], 401],
      [[{ id: "device-1", last_seen_at: new Date().toISOString() }], 409],
      [[{ id: "device-1", meshcentral_node_id: "node//" + "x".repeat(64), last_seen_at: "invalid-date" }], 409],
      [[{ id: "device-1", meshcentral_node_id: "node//" + "x".repeat(64), last_seen_at: new Date(Date.now() - 180000).toISOString() }], 409],
    ]) {
      globalThis.fetch = async (url, options) => {
        assert.ok(String(url).includes(crypto.createHash("sha256").update(token).digest("hex")));
        assert.equal(options.headers.apikey, "server-only-test-key");
        assert.ok(!String(url).includes("caller-target"));
        return Response.json(rows);
      };
      const response = await POST(new Request("https://devicehost.test/api/setup/verify-support", {
        method: "POST", headers: { "x-device-token": token }, body: '{"nodeid":"caller-target"}',
      }));
      assert.equal(response.status, expected);
      assert.equal(response.headers.get("cache-control"), "no-store");
    }
  } finally {
    globalThis.fetch = oldFetch;
    if (oldURL === undefined) delete process.env.SUPABASE_URL; else process.env.SUPABASE_URL = oldURL;
    if (oldKey === undefined) delete process.env.SUPABASE_SECRET_KEY; else process.env.SUPABASE_SECRET_KEY = oldKey;
  }
});
