import test from "node:test";
import assert from "node:assert/strict";
import { buildRemoteUnlockScript } from "../app/api/admin/device/[id]/remote-action/route.js";

test("remote unlock sends only a short-lived one-time request", () => {
  const nonce = "a".repeat(32);
  const script = buildRemoteUnlockScript(nonce);
  assert.match(script, /RemoteUnlock/);
  assert.match(script, /AddMinutes\(2\)/);
  assert.match(script, /RequestNonce/);
  assert.match(script, /RequestExpires/);
  assert.match(script, /No saved Windows password is available/);
  assert.ok(!/password\s*=|Secret\s*-Value/i.test(script), "dashboard command must not contain or replace the password");
  assert.throws(() => buildRemoteUnlockScript("not-a-nonce"), /Invalid unlock nonce/);
});
