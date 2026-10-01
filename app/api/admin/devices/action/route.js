import { activateDevice, adminAuthorized, parseDeviceAction } from "../../../../lib/device-actions.js";
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
    if(selection.action==="delete") {
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
