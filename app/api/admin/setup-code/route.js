import crypto from "node:crypto";

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

function randomCode() {
  return Array.from({ length: 3 }, () => crypto.randomBytes(2).toString("hex").toUpperCase()).join("-");
}

export async function POST(request) {
  try {
    const body = await request.json().catch(() => ({}));
    const label = String(body.label || "").trim().slice(0, 120) || null;
    const minutesRaw = Number(body.minutes || 30);
    const minutes = Number.isFinite(minutesRaw) ? Math.min(120, Math.max(5, Math.round(minutesRaw))) : 30;

    let code = "";
    let hash = "";
    let inserted = false;

    for (let i = 0; i < 5 && !inserted; i++) {
      code = randomCode();
      hash = crypto.createHash("sha256").update(code).digest("hex");
      const response = await fetch(url("setup_codes"), {
        method: "POST",
        headers: headers("return=minimal"),
        body: JSON.stringify({
          code_hash: hash,
          label,
          expires_at: new Date(Date.now() + minutes * 60 * 1000).toISOString()
        }),
        cache: "no-store"
      });
      if (response.ok) inserted = true;
      else if (response.status !== 409) throw new Error(await response.text());
    }

    if (!inserted) throw new Error("Unable to create a unique setup code.");
    return Response.json({ ok: true, code, expires_in_minutes: minutes });
  } catch (error) {
    return Response.json({ error: "Unable to create setup code", detail: String(error) }, { status: 500 });
  }
}
