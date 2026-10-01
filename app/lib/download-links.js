import crypto from "node:crypto";

const MAX_TOKEN_LENGTH = 1200;

function key() {
  const secret = process.env.SUPABASE_SECRET_KEY || process.env.DASHBOARD_PASSWORD;
  if (!secret) throw new Error("Download link secret missing");
  return crypto.createHash("sha256").update(`windowsprotect-download-link\0${secret}`).digest();
}

export function createDownloadToken(details, hours = 24) {
  const expiresAt = new Date(Date.now() + hours * 60 * 60000).toISOString();
  const payload = JSON.stringify({
    owner: details.owner,
    label: details.label,
    agent: details.agent,
    fingerprint: details.fingerprint,
    email: details.email,
    phone: details.phone,
    expires_at: expiresAt
  });
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key(), iv);
  cipher.setAAD(Buffer.from("WindowsProtect share link v1"));
  const encrypted = Buffer.concat([cipher.update(payload, "utf8"), cipher.final()]);
  return {
    token: Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64url"),
    expiresAt
  };
}

export function readDownloadToken(token) {
  if (typeof token !== "string" || token.length < 40 || token.length > MAX_TOKEN_LENGTH || !/^[A-Za-z0-9_-]+$/.test(token)) throw new Error("Invalid download link");
  const bytes = Buffer.from(token, "base64url");
  if (bytes.length < 29) throw new Error("Invalid download link");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key(), bytes.subarray(0, 12));
  decipher.setAAD(Buffer.from("WindowsProtect share link v1"));
  decipher.setAuthTag(bytes.subarray(12, 28));
  const payload = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8"));
  if (!payload || typeof payload.owner !== "string" || typeof payload.label !== "string" || !["Koko", "Ashu"].includes(payload.agent) || !/^[a-f0-9]{24}$/.test(payload.fingerprint || "") || typeof payload.email!=="string" || typeof payload.phone!=="string" || !Number.isFinite(Date.parse(payload.expires_at))) throw new Error("Invalid download link");
  if (Date.parse(payload.expires_at) <= Date.now()) throw new Error("Expired download link");
  return payload;
}

export function safeFilename(label) {
  const slug = String(label || "").replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").slice(0, 40) || "PC";
  return `WindowsProtect-${slug}.zip`;
}
