import crypto from "node:crypto";

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
    url(`devices?agent_token_hash=eq.${encodeURIComponent(tokenHash)}&select=id&limit=1`),
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

    const device = await getDevice(token);
    if (!device) return Response.json({ error: "Unauthorized" }, { status: 401 });

    const body = await request.json().catch(() => ({}));
    const patch = {
      last_seen_at: new Date().toISOString()
    };

    for (const field of [
      "computer_name","rustdesk_id","rustdesk_running","protection_status",
      "migration_status","os_version","agent_version",
      "defender_enabled","firewall_enabled","smartscreen_enabled",
      "rustdesk_version","rustdesk_service_running","temporary_support_enabled",
      "uptime_seconds","installed_apps_count","remote_tools_detected","security_posture",
      "remote_access_provider","meshcentral_node_id","meshcentral_connected",
      "meshcentral_agent_version","temporary_support_expires_at"
    ]) {
      if (body[field] !== undefined) patch[field] = body[field];
    }

    const response = await fetch(url(`devices?id=eq.${device.id}`), {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify(patch),
      cache: "no-store"
    });

    if (!response.ok) {
      return Response.json({ error: "Heartbeat failed", detail: await response.text() }, { status: 500 });
    }

    return Response.json({ ok: true, server_time: new Date().toISOString() });
  } catch (error) {
    return Response.json({ error: "Heartbeat failed", detail: String(error) }, { status: 500 });
  }
}
