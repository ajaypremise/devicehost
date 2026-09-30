import crypto from "node:crypto";

export const runtime = "nodejs";

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
function headers(prefer = "return=representation") {
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!key) throw new Error("SUPABASE_SECRET_KEY missing");
  return { apikey: key, "Content-Type": "application/json", Prefer: prefer };
}
function url(path) {
  const base = process.env.SUPABASE_URL;
  if (!base) throw new Error("SUPABASE_URL missing");
  return `${base}/rest/v1/${path}`;
}
async function findDevice(token) {
  const response = await fetch(
    url(`devices?agent_token_hash=eq.${encodeURIComponent(hashToken(token))}&select=id&limit=1`),
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
    const device = await findDevice(token);
    if (!device) return Response.json({ error: "Unauthorized" }, { status: 401 });

    const body = await request.json().catch(() => ({}));
    const apps = Array.isArray(body.apps) ? body.apps.slice(0, 1000) : [];
    const now = new Date().toISOString();

    const cleanText = (value, max) => {
      if (value == null) return null;
      return String(value).replace(/\u0000/g, "").trim().slice(0, max) || null;
    };

    const cleaned = apps
      .map((app) => ({
        device_id: device.id,
        app_name: cleanText(app.app_name, 240),
        app_version: cleanText(app.app_version, 120),
        publisher: cleanText(app.publisher, 160),
        is_remote_access: Boolean(app.is_remote_access),
        last_seen_at: now
      }))
      .filter((app) => app.app_name);

    if (cleaned.length) {
      const response = await fetch(url("software_inventory?on_conflict=device_id,app_name"), {
        method: "POST",
        headers: headers("resolution=merge-duplicates,return=minimal"),
        body: JSON.stringify(cleaned),
        cache: "no-store"
      });
      if (!response.ok) throw new Error(await response.text());
    }

    return Response.json({ ok: true, received: cleaned.length });
  } catch (error) {
    return Response.json({ error: "Inventory update failed", detail: String(error) }, { status: 500 });
  }
}
