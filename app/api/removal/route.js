import crypto from "node:crypto";
import { removalId, removalReasons } from "../../lib/removal.js";
export const runtime="nodejs";
export async function POST(request){
  const reply=(body,status=200)=>Response.json(body,{status,headers:{"Cache-Control":"no-store"}});
  try{
    const token=request.headers.get("x-device-token");
    if(!token || token.length>256) return reply({error:"Unauthorized"},401);
    const base=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
    if(!base || !key) return reply({error:"Removal confirmation unavailable"},503);
    const hash=crypto.createHash("sha256").update(token).digest("hex");
    const headers={apikey:key,"Content-Type":"application/json",Prefer:"return=representation"};
    const found=await fetch(`${base}/rest/v1/devices?agent_token_hash=eq.${hash}&select=id,migration_status&limit=1`,{headers,cache:"no-store",signal:AbortSignal.timeout(4000)});
    if(!found.ok) throw new Error();
    const [device]=await found.json();
    if(!device) return reply({error:"Unauthorized"},401);
    const body=await request.json().catch(()=>({}));
    const nonce=removalId(device.migration_status);
    if(!nonce || body.removal_id!==nonce) return reply({error:"No matching uninstall request"},409);
    const filter=`id=eq.${device.id}&migration_status=eq.${encodeURIComponent(device.migration_status)}`;
    if(body.status==="pending"){
      if(!removalReasons.has(body.reason)) return reply({error:"Invalid removal status"},400);
      const result=await fetch(`${base}/rest/v1/devices?${filter}`,{method:"PATCH",headers,body:JSON.stringify({migration_status:`removal_requested:${nonce}:${body.reason}`}),cache:"no-store",signal:AbortSignal.timeout(4000)});
      if(!result.ok) throw new Error();
      if(!(await result.json()).length) return reply({error:"Removal status changed. Retry."},409);
      return reply({ok:true,pending:true});
    }
    if(body.status!=="complete" || body.service_removed!==true || body.helper_removed!==true || body.credentials_removed!==true || body.files_removed!==true || body.support_removed!==true) return reply({error:"PC must confirm all uninstall checks"},409);
    const result=await fetch(`${base}/rest/v1/devices?${filter}&select=id`,{method:"DELETE",headers,cache:"no-store",signal:AbortSignal.timeout(10000)});
    if(!result.ok) throw new Error();
    if(!(await result.json()).length) return reply({error:"Removal status changed. Retry confirmation."},409);
    return reply({ok:true,deleted:true});
  }catch{return reply({error:"Removal confirmation failed. Record retained."},503);}
}
