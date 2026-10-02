import test from 'node:test';
import assert from 'node:assert/strict';
import {deviceOnline,remoteSupportConnected} from '../app/lib/device-presence.js';

const now=Date.parse('2026-10-02T05:00:00.000Z');
test('stale heartbeat is offline and cannot look remotely connected',()=>{
  const stale={last_seen_at:'2026-10-02T03:30:00.000Z',remote_access_provider:'meshcentral',meshcentral_connected:true};
  assert.equal(deviceOnline(stale.last_seen_at,now),false);
  assert.equal(remoteSupportConnected(stale,now),false);
});
test('fresh heartbeat may report its live remote connection',()=>{
  const fresh={last_seen_at:'2026-10-02T04:55:00.000Z',remote_access_provider:'meshcentral',meshcentral_connected:true};
  assert.equal(deviceOnline(fresh.last_seen_at,now),true);
  assert.equal(remoteSupportConnected(fresh,now),true);
});
