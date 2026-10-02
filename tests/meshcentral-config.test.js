import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("approved support visibly identifies every interactive session without storing credentials",async()=>{
  const config=JSON.parse(await readFile(new URL("../meshcentral/config.template.json",import.meta.url),"utf8"));
  const domain=config.domains[""];
  assert.equal(domain.allowSavingDeviceCredentials,false);
  assert.equal(domain.userConsentFlags.desktopnotify,true);
  assert.equal(domain.userConsentFlags.terminalnotify,true);
  assert.equal(domain.userConsentFlags.filenotify,true);
  assert.equal(domain.userConsentFlags.desktopprivacybar,true);
  assert.match(domain.notificationMessages.desktop,/started a remote desktop session/i);
});
