import crypto from "node:crypto";

export const runtime = "nodejs";

function sbHeaders() {
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!key) throw new Error("SUPABASE_SECRET_KEY missing");
  return { apikey: key, "Content-Type": "application/json", Prefer: "return=representation" };
}

function sbUrl(path) {
  const base = process.env.SUPABASE_URL;
  if (!base) throw new Error("SUPABASE_URL missing");
  return `${base}/rest/v1/${path}`;
}

export async function POST(request) {
  try {
    const enrollmentKey = request.headers.get("x-enrollment-key");
    const expectedKey = process.env.DEVICE_ENROLLMENT_KEY;

    if (!expectedKey || !enrollmentKey || enrollmentKey !== expectedKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const personName = String(body.person_name || "").trim();
    const deviceName = String(body.device_name || "").trim();

    if (!personName || !deviceName) {
      return Response.json({ error: "person_name and device_name are required" }, { status: 400 });
    }

    const deviceToken = crypto.randomBytes(32).toString("base64url");
    const tokenHash = crypto.createHash("sha256").update(deviceToken).digest("hex");

    const payload = {
      person_name: personName,
      device_name: deviceName,
      computer_name: body.computer_name || null,
      rustdesk_id: body.rustdesk_id || null,
      rustdesk_running: Boolean(body.rustdesk_running),
      protection_status: body.protection_status || "pending",
      migration_status: body.migration_status || "not_started",
      os_version: body.os_version || null,
      agent_version: body.agent_version || null,
      agent_token_hash: tokenHash,
      last_seen_at: new Date().toISOString()
    };

    const response = await fetch(sbUrl("devices"), {
      method: "POST",
      headers: sbHeaders(),
      body: JSON.stringify(payload),
      cache: "no-store"
    });

    if (!response.ok) {
      return Response.json({ error: "Enrollment failed", detail: await response.text() }, { status: 500 });
    }

    const [device] = await response.json();
    return Response.json({
      ok: true,
      device_id: device.id,
      device_code: device.device_code,
      device_token: deviceToken
    });
  } catch (error) {
    return Response.json({ error: "Enrollment failed", detail: String(error) }, { status: 500 });
  }
}
