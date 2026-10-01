import crypto from "node:crypto";

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

export async function issueSetupCode(label, minutes = 30) {
  let code = "";
  for (let i = 0; i < 5; i++) {
    code = randomCode();
    const codeHash = crypto.createHash("sha256").update(code).digest("hex");
    const response = await fetch(url("setup_codes"), {
      method: "POST",
      headers: headers("return=minimal"),
      body: JSON.stringify({ code_hash: codeHash, label: label || null, expires_at: new Date(Date.now() + minutes * 60000).toISOString() }),
      cache: "no-store"
    });
    if (response.ok) return code;
    if (response.status !== 409) throw new Error(await response.text());
  }
  throw new Error("Unable to create a unique setup code.");
}

export async function recentPublicRequests(fingerprint, minutes = 60) {
  const since = new Date(Date.now() - minutes * 60000).toISOString();
  const pattern = encodeURIComponent(`public:${fingerprint}:*`);
  const response = await fetch(url(`setup_codes?label=like.${pattern}&created_at=gte.${encodeURIComponent(since)}&select=id&limit=3`), {
    headers: headers(), cache: "no-store"
  });
  if (!response.ok) throw new Error(await response.text());
  return (await response.json()).length;
}

