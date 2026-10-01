import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {setupZip,installerUrl} from '../app/lib/setup-package.js';
import {readDownloadToken} from '../app/lib/download-links.js';
import {POST} from '../app/api/admin/installer/route.js';
import {POST as publicDownload} from '../app/api/public/installer/route.js';
import {GET as sharedDownload} from '../app/api/public/download/[token]/route.js';
process.env.SUPABASE_URL='https://db.test';process.env.SUPABASE_SECRET_KEY='server-secret';process.env.DASHBOARD_USER='test';process.env.DASHBOARD_PASSWORD='secret';
const auth='Basic '+Buffer.from('test:secret').toString('base64');
const exe=Buffer.alloc(2048,0);exe.write('MZ');
function files(zip){const result={};let offset=0;while(zip.readUInt32LE(offset)===0x04034b50){const size=zip.readUInt32LE(offset+18),length=zip.readUInt16LE(offset+26),name=zip.subarray(offset+30,offset+30+length).toString();result[name]=zip.subarray(offset+30+length,offset+30+length+size);offset+=30+length+size;}assert.equal(zip.readUInt32LE(offset),0x02014b50);assert.equal(zip.readUInt32LE(zip.length-22),0x06054b50);assert.equal(zip.readUInt16LE(zip.length-12),2);return result;}
async function mocked(mock,fn){const original=global.fetch;global.fetch=mock;try{await fn();}finally{global.fetch=original;}}
const request=(headers={authorization:auth})=>new Request('https://dashboard.test/api/admin/installer',{method:'POST',headers,body:JSON.stringify({owner:'Mum',label:'Laptop',agent:'Koko'})});
test('prepared ZIP preserves installer bytes and contains only short-lived setup configuration',()=>{
 const config={owner:'Mum',label:'Laptop',code:'AAAA-BBBB-CCCC',expires_at:'future'};
 const zip=setupZip(exe,config),result=files(zip);
 assert.deepEqual(Object.keys(result),['WindowsProtect_Setup.exe','WindowsProtect_Setup.json']);assert.deepEqual(result['WindowsProtect_Setup.exe'],exe);assert.deepEqual(JSON.parse(result['WindowsProtect_Setup.json']),config);
});
test('prepared installer requires dashboard authorization before any download or database operation',async()=>{
 await mocked(()=>assert.fail('fetch must not run'),async()=>{
  assert.equal((await POST(request({}))).status,401);
  assert.equal((await POST(request({authorization:auth,origin:'https://other.test'}))).status,401);
 });
});
test('prepared download verifies release hash and creates a fresh one-time code with no permanent secret in ZIP',async()=>{
 const calls=[];
 await mocked(async(url,options)=>{
  calls.push({url,options});
  if(url===installerUrl)return new Response(exe);
  if(url.endsWith('installer-sha256.json'))return Response.json({version:'0.5.14',sha256:crypto.createHash('sha256').update(exe).digest('hex')});
  assert.equal(url,'https://db.test/rest/v1/setup_codes');assert.equal(options.method,'POST');const body=JSON.parse(options.body);assert.match(body.code_hash,/^[a-f0-9]{64}$/);assert.equal(body.label,'Laptop');return new Response(null,{status:201});
 },async()=>{
  const result=await POST(request());assert.equal(result.status,200);assert.match(result.headers.get('cache-control'),/no-store/);
  const zip=Buffer.from(await result.arrayBuffer());const config=JSON.parse(files(zip)['WindowsProtect_Setup.json']);assert.match(config.code,/^[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/);assert.equal(config.owner,'Mum');assert.equal(config.label,'Laptop');assert.equal(config.agent,'Koko');assert.ok(Date.parse(config.expires_at)>Date.now());assert.equal(zip.includes(Buffer.from('server-secret')),false);assert.equal(calls.length,3);
 });
});
test('checksum mismatch prevents issuing a setup code',async()=>{
 let calls=0;
 await mocked(async url=>{calls++;if(url===installerUrl)return new Response(exe);assert.ok(url.endsWith('installer-sha256.json'));return Response.json({version:'0.5.14',sha256:'0'.repeat(64)});},async()=>{
  const result=await POST(request());assert.equal(result.status,503);assert.match((await result.json()).error,/verification failed/);assert.equal(calls,2);
 });
});
test('public self-service download validates origin and contact fields before any external request',async()=>{
 await mocked(()=>assert.fail('fetch must not run'),async()=>{
  const crossSite=new Request('https://dashboard.test/api/public/installer',{method:'POST',headers:{origin:'https://other.test','content-type':'application/json'},body:'{}'});
  assert.equal((await publicDownload(crossSite)).status,403);
  const invalid=new Request('https://dashboard.test/api/public/installer',{method:'POST',headers:{origin:'https://dashboard.test','content-type':'application/json','x-forwarded-for':'192.0.2.20'},body:JSON.stringify({name:'Mum',phone:'12',email:'bad'})});
  assert.equal((await publicDownload(invalid)).status,400);
 });
});
test('public page creates an encrypted share link without exposing contact or installer details',async()=>{
 const calls=[];
 await mocked(async(url,options)=>{
  calls.push({url:String(url),options});
  if(String(url).includes('setup_codes?'))return Response.json([]);
  assert.fail(`unexpected fetch ${url}`);
 },async()=>{
  const body={name:'Meera Singh',phone:'+91 98765 43210',email:'Meera@Example.com',agent:'Ashu',pc_name:''};
  const request=new Request('https://dashboard.test/api/public/installer',{method:'POST',headers:{origin:'https://dashboard.test','content-type':'application/json','x-forwarded-for':'192.0.2.21'},body:JSON.stringify(body)});
  const response=await publicDownload(request);assert.equal(response.status,200);assert.match(response.headers.get('cache-control'),/no-store/);
  const result=await response.json();assert.equal(result.filename,'WindowsProtect-Meera-s-PC.zip');assert.match(result.download_url,/^https:\/\/dashboard\.test\/api\/public\/download\/[A-Za-z0-9_-]+$/);assert.ok(Date.parse(result.expires_at)>Date.now());
  assert.equal(result.download_url.includes('Meera'),false);assert.equal(result.download_url.includes('Ashu'),false);assert.equal(result.download_url.includes('98765'),false);
  const token=result.download_url.split('/').pop(),details=readDownloadToken(token);assert.equal(details.owner,'Meera Singh');assert.equal(details.label,"Meera's PC");assert.equal(details.agent,'Ashu');assert.match(details.fingerprint,/^[a-f0-9]{24}$/);assert.equal(calls.length,1);
 });
});
test('share link directly downloads a prepared package with a four-hour one-time code',async()=>{
 const createRequest=new Request('https://dashboard.test/api/public/installer',{method:'POST',headers:{origin:'https://dashboard.test','content-type':'application/json','x-forwarded-for':'192.0.2.22'},body:JSON.stringify({name:'Ravi Kumar',phone:'+91 90000 00000',email:'ravi@example.com',agent:'Koko',pc_name:'Office PC'})});
 let token;
 await mocked(async url=>{assert.ok(String(url).includes('setup_codes?'));return Response.json([]);},async()=>{token=(await (await publicDownload(createRequest)).json()).download_url.split('/').pop();});
 const calls=[];
 await mocked(async(url,options={})=>{
  calls.push({url:String(url),options});
  if(String(url).includes('setup_codes?'))return Response.json([]);
  if(url===installerUrl)return new Response(exe);
  if(String(url).endsWith('installer-sha256.json'))return Response.json({version:'0.5.14',sha256:crypto.createHash('sha256').update(exe).digest('hex')});
  assert.equal(url,'https://db.test/rest/v1/setup_codes');assert.equal(options.method,'POST');return new Response(null,{status:201});
 },async()=>{
  const response=await sharedDownload(new Request(`https://dashboard.test/api/public/download/${token}`),{params:Promise.resolve({token})});assert.equal(response.status,200);assert.match(response.headers.get('content-disposition'),/WindowsProtect-Office-PC\.zip/);
  const zip=Buffer.from(await response.arrayBuffer()),config=JSON.parse(files(zip)['WindowsProtect_Setup.json']);assert.equal(config.owner,'Ravi Kumar');assert.equal(config.label,'Office PC');assert.equal(config.agent,'Koko');assert.match(config.code,/^[A-F0-9-]{14}$/);const remaining=Date.parse(config.expires_at)-Date.now();assert.ok(remaining>239*60000&&remaining<=240*60000);assert.equal(calls.length,4);
 });
});
test('tampered share links fail before database or release access',async()=>{
 await mocked(()=>assert.fail('fetch must not run'),async()=>{const response=await sharedDownload(new Request('https://dashboard.test/api/public/download/bad'),{params:Promise.resolve({token:'bad'})});assert.equal(response.status,410);assert.match((await response.json()).error,/invalid/i);});
});
