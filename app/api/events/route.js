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

    const body = await request.json();
    const title = String(body.title || "").trim();
    const eventType = String(body.event_type || "").trim();

    if (!title || !eventType) {
      return Response.json({ error: "title and event_type are required" }, { status: 400 });
    }

    const severity = ["info", "warning", "critical"].includes(body.severity)
      ? body.severity
      : "info";

    const response = await fetch(url("security_events"), {
      method: "POST",
      headers: headers("return=minimal"),
      body: JSON.stringify({
        device_id: device.id,
        event_type: eventType,
        severity,
        title,
        details: body.details || {}
      }),
      cache: "no-store"
    });

    if (!response.ok) {
      return Response.json({ error: "Event failed", detail: await response.text() }, { status: 500 });
    }

    return Response.json({ ok: true });
  } catch (error) {
    return Response.json({ error: "Event failed", detail: String(error) }, { status: 500 });
  }
}
