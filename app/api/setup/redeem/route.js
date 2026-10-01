import crypto from "node:crypto";
import { contactFromSetupLabel, createEnrollmentGrant } from "../../../lib/device-contact.js";

export const runtime = "nodejs";

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
function enrollmentHeaders() {
  const key = process.env.DEVICE_ENROLLMENT_KEY;
  if (!key) throw new Error("DEVICE_ENROLLMENT_KEY missing");
  return key;
}

export async function POST(request) {
  try {
    const body = await request.json().catch(() => ({}));
    const code = String(body.code || "").trim().toUpperCase();
    if (!code) return Response.json({ error: "Setup code required" }, { status: 400 });

    const hash = crypto.createHash("sha256").update(code).digest("hex");
    const response = await fetch(
      url(`setup_codes?code_hash=eq.${encodeURIComponent(hash)}&select=id,label,expires_at,used_at&limit=1`),
      { headers: headers(), cache: "no-store" }
    );
    if (!response.ok) throw new Error(await response.text());
    const rows = await response.json();
    const row = rows[0];

    if (!row || row.used_at || new Date(row.expires_at).getTime() <= Date.now()) {
      return Response.json({ error: "Invalid or expired setup code" }, { status: 401 });
    }

    const mark = await fetch(url(`setup_codes?id=eq.${row.id}&used_at=is.null`), {
      method: "PATCH",
      headers: headers("return=representation"),
      body: JSON.stringify({ used_at: new Date().toISOString() }),
      cache: "no-store"
    });
    if (!mark.ok) throw new Error(await mark.text());
    const updated = await mark.json();
    if (!updated.length) return Response.json({ error: "Setup code already used" }, { status: 409 });

    const contact=contactFromSetupLabel(row.label);
    return Response.json({
      ok: true,
      device_enrollment_key: contact?createEnrollmentGrant(contact):enrollmentHeaders(),
      meshcentral_url: "https://34-69-184-103.sslip.io",
      mesh_agent_url: process.env.MESHCENTRAL_AGENT_URL || null
    });
  } catch (error) {
    return Response.json({ error: "Unable to redeem setup code", detail: String(error) }, { status: 500 });
  }
}
