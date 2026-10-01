import { activateDevice, adminAuthorized, parseDeviceAction } from "../../../../lib/device-actions.js";
import crypto from "node:crypto";
import { removalId, canUninstall } from "../../../../lib/removal.js";
export const runtime = "nodejs";
export const maxDuration = 45;
export async function POST(request) {
  const reply = (body, status=200) => Response.json(body,{status,headers:{"Cache-Control":"no-store"}});
  if (!adminAuthorized(request)) return reply({error:"Unauthorized"},401);
  let selection;
  try { selection=parseDeviceAction(await request.json()); } catch(error) { return reply({error:error.message},400); }
  try {
    const base=process.env.SUPABASE_URL, key=process.env.SUPABASE_SECRET_KEY;
    if(!base || !key) throw new Error("Dashboard storage is unavailable.");
    const filter=`id=in.(${selection.ids.join(",")})`;
    const headers={apikey:key,Accept:"application/json",Prefer:"return=representation"};
    const lookup=await fetch(`${base}/rest/v1/devices?${filter}&select=id,person_name,protection_status,migration_status,agent_version,last_seen_at,meshcentral_node_id`,{headers,cache:"no-store",signal:AbortSignal.timeout(4000)});
    if(!lookup.ok) throw new Error("Unable to look up selected devices.");
    const devices=await lookup.json();
    if(devices.length!==selection.ids.length) return reply({error:"One or more selected devices no longer exist. Refresh and select again."},409);
    if(selection.action==="uninstall") {
      const results=[];
      for(let device of devices){
        if(!canUninstall(device.agent_version)){
          results.push({id:device.id,status:"failed",error:"Update this PC to 0.5.8 before requesting remote uninstall."}); continue;
        }
        if(removalId(device.migration_status)){
          results.push({id:device.id,status:"removal_pending"}); continue;
        }
        const nonce=crypto.randomBytes(32).toString("hex");
        try{
          let accepted=false;
          for(let attempt=0;attempt<3;attempt++){
            if(removalId(device.migration_status)){accepted=true;break;}
            const previous=device.migration_status==null?"is.null":`eq.${encodeURIComponent(device.migration_status)}`;
            const queued=await fetch(`${base}/rest/v1/devices?id=eq.${device.id}&migration_status=${previous}&select=id`,{method:"PATCH",headers:{...headers,"Content-Type":"application/json"},body:JSON.stringify({migration_status:`removal_requested:${nonce}`}),cache:"no-store",signal:AbortSignal.timeout(4000)});
            if(!queued.ok){
              // Return only a database error code, never raw details that may
              // contain credentials, row data, or internal connection strings.
              const failure=await queued.json().catch(()=>({}));
              const code=/^(?:[0-9A-Z]{5}|PGRST\d{3})$/.test(failure.code || "")?failure.code:`HTTP ${queued.status}`;
              if(code==="23514" || code==="22001" || code==="22P02") throw new Error(`Uninstall request rejected by dashboard storage (${code}). Database configuration needs updating; nothing was uninstalled.`);
              throw new Error(`Unable to save uninstall request (${code}). Nothing was uninstalled.`);
            }
            if((await queued.json()).length){accepted=true;break;}
            const latest=await fetch(`${base}/rest/v1/devices?id=eq.${device.id}&select=id,migration_status,agent_version`,{headers,cache:"no-store",signal:AbortSignal.timeout(4000)});
            if(!latest.ok) throw new Error("Unable to check uninstall request. Refresh the dashboard before retrying.");
            const rows=await latest.json();
            if(!rows.length) throw new Error("Device record no longer exists. Refresh the dashboard.");
            device=rows[0];
            if(!canUninstall(device.agent_version)) throw new Error("Update this PC to 0.5.8 before requesting remote uninstall.");
            // A second browser/request may already have queued this PC.
            if(removalId(device.migration_status)){accepted=true;break;}
          }
          if(!accepted) throw new Error("PC status kept changing while saving uninstall. Nothing was uninstalled; retry shortly.");
          results.push({id:device.id,status:"removal_pending"});
        }catch(error){results.push({id:device.id,status:"failed",error:error.message});}
      }
      return reply({results});
    }
    if(selection.action==="delete") {
      if(devices.some(d=>removalId(d.migration_status))) return reply({error:"Uninstall is pending. Wait for confirmed removal before deleting its record."},409);
      // One filtered DELETE; child records follow existing database FK rules.
      const deleted=await fetch(`${base}/rest/v1/devices?${filter}&select=id`,{method:"DELETE",headers,cache:"no-store",signal:AbortSignal.timeout(10000)});
      if(!deleted.ok) throw new Error("Device records could not be deleted.");
      const rows=await deleted.json();
      return reply({results:rows.map(d=>({id:d.id,status:"deleted"}))});
    }
    const result=await activateDevice(devices[0]);
    return reply({results:[result]});
  } catch(error) { return reply({error:error.message || "Device action failed."},409); }
}
