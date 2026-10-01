import test from "node:test";
import assert from "node:assert/strict";
import { isRemoteAccessAlert, recentRemoteAccessAlerts, remoteAccessTool } from "../app/lib/security-alerts.js";

test("remote-access alerts include new and legacy blocked events only",()=>{
  assert.equal(isRemoteAccessAlert({event_type:"remote_access_blocked"}),true);
  assert.equal(isRemoteAccessAlert({event_type:"remote_tool_blocked"}),true);
  assert.equal(isRemoteAccessAlert({event_type:"protection_repaired"}),false);
});

test("dashboard keeps recent critical remote alerts newest first",()=>{
  const now=Date.parse("2026-10-02T00:00:00Z");
  const events=[
    {id:"old",event_type:"remote_access_blocked",severity:"critical",created_at:"2026-09-30T00:00:00Z"},
    {id:"warning",event_type:"remote_access_blocked",severity:"warning",created_at:"2026-10-01T23:59:00Z"},
    {id:"one",event_type:"remote_tool_blocked",severity:"critical",created_at:"2026-10-01T23:30:00Z"},
    {id:"two",event_type:"remote_access_blocked",severity:"critical",created_at:"2026-10-01T23:45:00Z",details:{tool:"UltraViewer"}},
  ];
  assert.deepEqual(recentRemoteAccessAlerts(events,now).map(event=>event.id),["two","one"]);
  assert.equal(remoteAccessTool(events[3]),"UltraViewer");
  assert.equal(remoteAccessTool({details:{message:"Application: AnyDesk"}}),"AnyDesk");
});
