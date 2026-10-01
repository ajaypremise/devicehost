import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDeviceAction, adminAuthorized, activateDevice } from '../app/lib/device-actions.js';
import { POST } from '../app/api/admin/devices/action/route.js';
const id='12345678-1234-1234-1234-123456789abc';
test('bulk actions require bounded valid IDs and explicit deletion confirmation',()=>{
  assert.deepEqual(parseDeviceAction({action:'delete',ids:[id,id],confirm:'delete_records'}),{action:'delete',ids:[id]});
  for(const body of [{action:'delete',ids:[id]},{action:'activate',ids:['anything']},{action:'uninstall',ids:[id]},{action:'activate',ids:Array(101).fill(id)}]) assert.throws(()=>parseDeviceAction(body));
});
test('admin action requires dashboard authentication and rejects cross-origin requests',async()=>{
  process.env.DASHBOARD_USER='test';process.env.DASHBOARD_PASSWORD='secret';
  const authorization='Basic '+Buffer.from('test:secret').toString('base64');
  assert.equal(adminAuthorized(new Request('https://dashboard.test/api/admin/devices/action',{headers:{authorization,origin:'https://dashboard.test'}})),true);
  assert.equal(adminAuthorized(new Request('https://dashboard.test/api/admin/devices/action',{headers:{authorization,origin:'https://evil.test'}})),false);
  const response=await POST(new Request('https://dashboard.test/api/admin/devices/action',{method:'POST',body:'{}'}));
  assert.equal(response.status,401);
});
const device={id,agent_version:'0.5.7-test',protection_status:'pending',migration_status:'awaiting_activation:'+new Date(Date.now()+3600000).toISOString(),last_seen_at:new Date().toISOString(),meshcentral_node_id:'node//'+ 'a'.repeat(64)};
test('activation targets enrolled PC and requires fresh desktop proof before sending fixed command',async()=>{
  let proof,command;
  const result=await activateDevice(device,{probe:async(node,nonce)=>{proof={node,nonce};},send:async(c)=>{command=c;}});
  assert.equal(result.status,'activation_requested');assert.equal(proof.node,device.meshcentral_node_id);
  assert.match(proof.nonce,/^[a-f0-9]{64}$/);assert.deepEqual(command.nodeids,[device.meshcentral_node_id]);
  assert.ok(command.cmds.includes(proof.nonce));assert.ok(command.cmds.includes('activation.request'));assert.ok(command.cmds.includes('ExecuteCommand(128)'));
});
test('offline, legacy or unverified devices cannot receive early activation',async()=>{
  for(const change of [{agent_version:'0.5.6-test'},{migration_status:'not_started'},{last_seen_at:new Date(Date.now()-180000).toISOString()}]) await assert.rejects(activateDevice({...device,...change},{probe:async()=>assert.fail('probe must not run'),send:async()=>assert.fail('command must not run')}));
  const verifying={...device,migration_status:'verifying_support:'+new Date(Date.now()+60000).toISOString()};let verifyingCommand;
  assert.equal((await activateDevice(verifying,{probe:async()=>{},send:async(c)=>{verifyingCommand=c;}})).status,'activation_requested');
  assert.match(verifyingCommand.cmds,/SupportVerified/);
  await assert.rejects(activateDevice(device,{probe:async()=>{throw new Error('failure');},send:async()=>assert.fail('command sent without proof')}));
  assert.equal((await activateDevice({...device,protection_status:'protected'})).status,'already_active');
});
test('bulk deletion stays filtered to selected IDs and reports only actual removed rows',async()=>{
  const original=global.fetch;
  process.env.SUPABASE_URL='https://db.test';process.env.SUPABASE_SECRET_KEY='server-secret';
  const requests=[];
  global.fetch=async(url,options)=>{requests.push({url,options});return Response.json([{id}]);};
  try{
    const response=await POST(new Request('https://dashboard.test/api/admin/devices/action',{method:'POST',headers:{authorization:'Basic '+Buffer.from('test:secret').toString('base64'),origin:'https://dashboard.test'},body:JSON.stringify({action:'delete',ids:[id],confirm:'delete_records'})}));
    assert.equal(response.status,200);assert.deepEqual((await response.json()).results,[{id,status:'deleted'}]);
    assert.equal(requests.length,2);assert.equal(requests[1].options.method,'DELETE');assert.ok(requests[1].url.includes(`id=in.(${id})`));
  }finally{global.fetch=original;}
});
