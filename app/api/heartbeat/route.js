import crypto from "node:crypto";

import { removalId } from "../../lib/removal.js";
import { meshcentralConfigured, sendMeshCentral } from "../../lib/meshcentral.js";

export const runtime = "nodejs";

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function headers() {
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!key) throw new Error("SUPABASE_SECRET_KEY missing");
  return { apikey: key, "Content-Type": "application/json", Prefer: "return=representation" };
}

function url(path) {
  const base = process.env.SUPABASE_URL;
  if (!base) throw new Error("SUPABASE_URL missing");
  return `${base}/rest/v1/${path}`;
}

async function getDevice(token) {
  const tokenHash = hashToken(token);
  const response = await fetch(
    url(`devices?agent_token_hash=eq.${encodeURIComponent(tokenHash)}&select=id,person_name,meshcentral_node_id,migration_status,temporary_support_enabled,temporary_support_expires_at&limit=1`),
    { headers: headers(), cache: "no-store" }
  );
  if (!response.ok) throw new Error(await response.text());
  const rows = await response.json();
  return rows[0] || null;
}

export async function POST(request) {
  try {
    const token = request.headers.get("x-device-token");
    if (!token) return Response.json({ error: "Unauthorized" }, { status: 401 });

    let device = await getDevice(token);
    if (!device) return Response.json({ error: "Unauthorized" }, { status: 401 });

    const body = await request.json().catch(() => ({}));
    const patch = {
      last_seen_at: new Date().toISOString()
    };

    for (const field of [
      "computer_name","rustdesk_id","rustdesk_running","protection_status",
      "migration_status","os_version","agent_version",
      "defender_enabled","firewall_enabled","smartscreen_enabled",
      "rustdesk_version","rustdesk_service_running",
      "uptime_seconds","installed_apps_count","remote_tools_detected","security_posture",
      "remote_access_provider","meshcentral_node_id","meshcentral_connected",
      "meshcentral_agent_version"
    ]) {
      if (body[field] !== undefined) patch[field] = body[field];
    }

    // Compare the observed status so an in-flight heartbeat cannot overwrite
    // a dashboard removal request queued after its lookup.
    for(let attempt=0;attempt<3;attempt++){
      const nonce=removalId(device.migration_status);
      const nextPatch={...patch};
      const allowedUntil=device.temporary_support_enabled && Date.parse(device.temporary_support_expires_at)>Date.now()?device.temporary_support_expires_at:null;
      if(device.temporary_support_enabled && !allowedUntil){nextPatch.temporary_support_enabled=false;nextPatch.temporary_support_expires_at=null;}
      if(nonce) delete nextPatch.migration_status;
      const previous=device.migration_status==null?"is.null":`eq.${encodeURIComponent(device.migration_status)}`;
      const response=await fetch(url(`devices?id=eq.${device.id}&migration_status=${previous}`),{
        method:"PATCH",headers:headers(),body:JSON.stringify(nextPatch),cache:"no-store",signal:AbortSignal.timeout(4000)
      });
      if(!response.ok) throw new Error("Heartbeat update failed");
      if((await response.json()).length) {
        if(!device.meshcentral_node_id && body.meshcentral_node_id && device.person_name && meshcentralConfigured()){
          try{
            await sendMeshCentral({action:"changedevice",nodeid:body.meshcentral_node_id,name:device.person_name,responseid:`enrollment-name-${Date.now()}-${Math.random().toString(16).slice(2)}`},{timeoutMs:10000});
          }catch{}
        }
        return Response.json({ok:true,server_time:new Date().toISOString(),ultraviewer_allowed_until:allowedUntil,...(nonce?{removal_request:nonce}:{})});
      }
      device=await getDevice(token);
      if(!device) return Response.json({error:"Unauthorized"},{status:401});
    }
    return Response.json({error:"Device status changed. Retry heartbeat."},{status:409});

  } catch (error) {
    return Response.json({ error: "Heartbeat failed", detail: String(error) }, { status: 500 });
  }
}
