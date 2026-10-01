import { adminAuthorized } from "../../../../lib/device-actions.js";
import { meshcentralConfigured, syncMeshCentralDevice } from "../../../../lib/meshcentral.js";
import { normalizeEmail, normalizePhone } from "../../../../lib/device-contact.js";

export const runtime = "nodejs";

function headers(prefer = "return=representation") {
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!key) throw new Error("SUPABASE_SECRET_KEY missing");
  return { apikey: key, "Content-Type": "application/json", Prefer: prefer };
}

function baseUrl() {
  const base = process.env.SUPABASE_URL;
  if (!base) throw new Error("SUPABASE_URL missing");
  return base;
}

export async function PATCH(request, { params }) {
  if (!adminAuthorized(request)) return Response.json({ error: "Unauthorized" }, { status: 401 });
  try {
    const { id } = await params;
    const body = await request.json().catch(() => ({}));

    const personName = String(body.person_name || "").trim().slice(0, 120);
    const deviceName = String(body.device_name || "").trim().slice(0, 120);
    const email=body.email==null?"":normalizeEmail(body.email),phone=body.phone==null?"":normalizePhone(body.phone);

    if (!personName || !deviceName) {
      return Response.json({ error: "Owner and device name are required" }, { status: 400 });
    }
    if((String(body.email||"").trim()&&!email)||(String(body.phone||"").trim()&&!phone))return Response.json({error:"Enter a valid email and phone number."},{status:400});

    const currentResponse = await fetch(
      `${baseUrl()}/rest/v1/devices?id=eq.${encodeURIComponent(id)}&select=id,meshcentral_node_id&limit=1`,
      { headers: headers(""), cache: "no-store" }
    );
    if (!currentResponse.ok) throw new Error("Device lookup failed");
    const [current] = await currentResponse.json();
    if (!current) return Response.json({ error: "Device not found" }, { status: 404 });

    const response = await fetch(
      `${baseUrl()}/rest/v1/devices?id=eq.${encodeURIComponent(id)}`,
      {
        method: "PATCH",
        headers: headers("return=representation"),
        body: JSON.stringify({
          person_name: personName,
          device_name: deviceName
        }),
        cache: "no-store"
      }
    );

    if (!response.ok) {
      return Response.json({ error: "Update failed", detail: await response.text() }, { status: 500 });
    }

    const rows = await response.json();
    if (!rows.length) return Response.json({ error: "Device not found" }, { status: 404 });

    let supportNameSynced = !current.meshcentral_node_id;
    if (current.meshcentral_node_id && meshcentralConfigured()) {
      try {
        await syncMeshCentralDevice({nodeId:current.meshcentral_node_id,name:personName,description:deviceName,force:true});
        supportNameSynced = true;
      } catch {}
    }
    const contactSaved=await fetch(`${baseUrl()}/rest/v1/security_events`,{method:"POST",headers:headers("return=minimal"),body:JSON.stringify({device_id:id,event_type:"device_contact",severity:"info",title:"Customer contact updated",details:{email:email||null,phone:phone||null}}),cache:"no-store"});
    if(!contactSaved.ok)throw new Error("Contact update failed");

    return Response.json({
      ok: true,
      support_name_synced: supportNameSynced,
      warning: supportNameSynced ? null : "Names saved, but the support console did not confirm its update. Save again when the PC is online.",
      device: {
        id: rows[0].id,
        person_name: rows[0].person_name,
        device_name: rows[0].device_name
      }
    });
  } catch (error) {
    return Response.json({ error: "Update failed", detail: String(error) }, { status: 500 });
  }
}
