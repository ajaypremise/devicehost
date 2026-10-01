import test from "node:test";
import assert from "node:assert/strict";
import {POST} from "../app/api/admin/device/[id]/sales-status/route.js";

const id="12345678-1234-1234-1234-123456789abc";
process.env.DASHBOARD_USER="test";process.env.DASHBOARD_PASSWORD="secret";process.env.SUPABASE_URL="https://db.test";process.env.SUPABASE_SECRET_KEY="server-secret";
const auth="Basic "+Buffer.from("test:secret").toString("base64");

function request(status,authorization=auth){return new Request(`https://dashboard.test/api/admin/device/${id}/sales-status`,{method:"POST",headers:{authorization,origin:"https://dashboard.test","content-type":"application/json"},body:JSON.stringify({status})});}

test("sales status requires dashboard authorization and a known value",async()=>{
  assert.equal((await POST(request("sale",""),{params:Promise.resolve({id})})).status,401);
  assert.equal((await POST(request("maybe"),{params:Promise.resolve({id})})).status,400);
});

test("sales status writes an auditable device event",async()=>{
  const original=global.fetch;let saved;
  global.fetch=async(url,options)=>{saved={url:String(url),options};return new Response(null,{status:201});};
  try{
    const response=await POST(request("sale"),{params:Promise.resolve({id})});
    assert.equal(response.status,200);assert.deepEqual(await response.json(),{ok:true,status:"sale"});
    assert.equal(saved.url,"https://db.test/rest/v1/security_events");
    assert.deepEqual(JSON.parse(saved.options.body),{device_id:id,event_type:"sales_status",severity:"info",title:"Marked as Sale",details:{status:"sale"}});
  }finally{global.fetch=original;}
});
