import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { POST as remove } from '../app/api/removal/route.js';
import { POST as action } from '../app/api/admin/devices/action/route.js';
import { POST as heartbeat } from '../app/api/heartbeat/route.js';
import { removalId,canProcessRemoval,canUninstall } from '../app/lib/removal.js';
const id='12345678-1234-1234-1234-123456789abc', nonce='a'.repeat(64), token='test-device-token';
process.env.SUPABASE_URL='https://db.test';process.env.SUPABASE_SECRET_KEY='server-secret';process.env.DASHBOARD_USER='test';process.env.DASHBOARD_PASSWORD='secret';
const device={id,agent_version:'0.5.15-test',migration_status:`removal_requested:${nonce}`};
const request=body=>new Request('https://dashboard.test/api/removal',{method:'POST',headers:{'x-device-token':token},body:JSON.stringify(body)});
async function withFetch(mock,fn){const original=global.fetch;global.fetch=mock;try{await fn();}finally{global.fetch=original;}}
test('uninstall request parsing rejects malformed IDs and older agents',()=>{
 assert.equal(removalId(`removal_requested:${nonce}:waiting_for_user`),nonce);assert.equal(removalId('removal_requested:anything'),'');
 assert.equal(canUninstall('0.5.7-test'),false);assert.equal(canUninstall('0.5.8-test'),true);assert.equal(canUninstall('0.6.0'),true);
 assert.equal(canProcessRemoval('0.5.14'),false);assert.equal(canProcessRemoval('0.5.15'),true);
});
test('removal authenticates device token and never deletes on partial or mismatched confirmation',async()=>{
 let calls=0;
 await withFetch(async(url)=>{calls++;assert.ok(url.includes(crypto.createHash('sha256').update(token).digest('hex')));return Response.json([device]);},async()=>{
  const anonymous=await remove(new Request('https://dashboard.test/api/removal',{method:'POST',body:'{}'}));assert.equal(anonymous.status,401);assert.equal(calls,0);
  for(const body of [{removal_id:'b'.repeat(64),status:'complete'},{removal_id:nonce,status:'complete',service_removed:true}]) assert.equal((await remove(request(body))).status,409);
  assert.equal(calls,2);
 });
});
test('complete uninstall deletes only matching enrolled record after all PC checks',async()=>{
 const calls=[];
 await withFetch(async(url,options)=>{calls.push({url,options});return Response.json([{...device}]);},async()=>{
  const result=await remove(request({removal_id:nonce,status:'complete',service_removed:true,helper_removed:true,credentials_removed:true,files_removed:true,support_removed:true}));
  assert.equal(result.status,200);assert.equal((await result.json()).deleted,true);
  assert.equal(calls[1].options.method,'DELETE');assert.ok(calls[1].url.includes(`id=eq.${id}`));assert.ok(calls[1].url.includes('migration_status=eq.removal_requested%3A'+nonce));
 });
});
test('offline uninstall queues durable pending status and preserves dashboard record',async()=>{
 const calls=[];
 await withFetch(async(url,options)=>{calls.push({url,options});return Response.json([{...device,migration_status:'completed',last_seen_at:'2000-01-01'}]);},async()=>{
  const result=await action(new Request('https://dashboard.test/api/admin/devices/action',{method:'POST',headers:{authorization:'Basic '+Buffer.from('test:secret').toString('base64')},body:JSON.stringify({action:'uninstall',ids:[id],confirm:'uninstall_from_pc'})}));
  assert.equal(result.status,200);assert.equal((await result.json()).results[0].status,'removal_pending');assert.equal(calls.length,2);assert.equal(calls[1].options.method,'PATCH');
  assert.match(JSON.parse(calls[1].options.body).migration_status,/^removal_requested:[a-f0-9]{64}$/);assert.ok(!calls.some(c=>c.options.method==='DELETE'));
 });
});
test('heartbeat preserves removal request and delivers it only to enrolled PC',async()=>{
 const calls=[];
 await withFetch(async(url,options)=>{calls.push({url,options});return Response.json([device]);},async()=>{
  const result=await heartbeat(new Request('https://dashboard.test/api/heartbeat',{method:'POST',headers:{'x-device-token':token},body:JSON.stringify({migration_status:'completed',agent_version:'0.5.15-test'})}));
  assert.equal(result.status,200);assert.equal((await result.json()).removal_request,nonce);assert.equal(JSON.parse(calls[1].options.body).migration_status,undefined);assert.ok(calls[1].url.includes('migration_status=eq.removal_requested%3A'));
 });
});
test('heartbeat preserves but withholds removal from the broken 0.5.14 helper so it can auto-update',async()=>{
 const calls=[];
 await withFetch(async(url,options)=>{calls.push({url,options});return Response.json([{...device,agent_version:'0.5.14'}]);},async()=>{
  const result=await heartbeat(new Request('https://dashboard.test/api/heartbeat',{method:'POST',headers:{'x-device-token':token},body:JSON.stringify({migration_status:'completed',agent_version:'0.5.14'})}));
  assert.equal(result.status,200);assert.equal((await result.json()).removal_request,undefined);assert.equal(JSON.parse(calls[1].options.body).migration_status,undefined);
 });
});
test('heartbeat retries a concurrent dashboard uninstall without overwriting it',async()=>{
 const calls=[];
 await withFetch(async(url,options)=>{calls.push({url,options});return Response.json(calls.length===1?[{...device,migration_status:'completed'}]:calls.length===2?[]:[device]);},async()=>{
  const result=await heartbeat(new Request('https://dashboard.test/api/heartbeat',{method:'POST',headers:{'x-device-token':token},body:JSON.stringify({migration_status:'awaiting_activation:later'})}));
  assert.equal(result.status,200);assert.equal((await result.json()).removal_request,nonce);assert.equal(calls.length,4);assert.equal(JSON.parse(calls[3].options.body).migration_status,undefined);
 });
});

const uninstallRequest=()=>new Request('https://dashboard.test/api/admin/devices/action',{method:'POST',headers:{authorization:'Basic '+Buffer.from('test:secret').toString('base64')},body:JSON.stringify({action:'uninstall',ids:[id],confirm:'uninstall_from_pc'})});
test('uninstall retries a heartbeat status race with a fresh conditional filter',async()=>{
 const calls=[];
 await withFetch(async(url,options)=>{
  calls.push({url,options});
  if(calls.length===1) return Response.json([{...device,migration_status:'completed'}]);
  if(calls.length===2) return Response.json([]);
  if(calls.length===3) return Response.json([{...device,migration_status:'protected'}]);
  assert.ok(url.includes('migration_status=eq.protected'));
  assert.equal(options.body,calls[1].options.body);
  return Response.json([{id}]);
 },async()=>{
  const result=await action(uninstallRequest());
  assert.equal((await result.json()).results[0].status,'removal_pending');
  assert.equal(calls.length,4);
 });
});
test('uninstall recognizes a concurrently queued removal without replacing its nonce',async()=>{
 const calls=[];
 await withFetch(async(url,options)=>{
  calls.push({url,options});
  return Response.json(calls.length===1?[{...device,migration_status:'completed'}]:calls.length===2?[]:[device]);
 },async()=>{
  const result=await action(uninstallRequest());
  assert.equal((await result.json()).results[0].status,'removal_pending');assert.equal(calls.length,3);
 });
});
test('uninstall reports database rejection separately from a status race without exposing details',async()=>{
 let calls=0;
 await withFetch(async()=>{
  calls++;
  return calls===1?Response.json([{...device,migration_status:'completed'}]):Response.json({code:'23514',message:'private row data',details:'server-secret'}, {status:400});
 },async()=>{
  const result=await action(uninstallRequest());
  const body=await result.json();assert.equal(body.results[0].status,'failed');
  assert.match(body.results[0].error,/storage \(23514\)/);assert.doesNotMatch(JSON.stringify(body),/private row|server-secret|status changed/i);assert.equal(calls,2);
 });
});
test('uninstall stops after three status conflicts and never deletes the record',async()=>{
 let calls=0;
 await withFetch(async(url,options)=>{
  calls++;assert.notEqual(options.method,'DELETE');
  return Response.json(options.method==='PATCH'?[]:[{...device,migration_status:'completed'}]);
 },async()=>{
  const result=await action(uninstallRequest());const body=await result.json();
  assert.equal(body.results[0].status,'failed');assert.match(body.results[0].error,/kept changing/);assert.equal(calls,7);
 });
});
