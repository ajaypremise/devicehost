import crypto from "node:crypto";
import { createDownloadToken, safeFilename } from "../../../lib/download-links.js";
import { recentPublicRequests } from "../../../lib/setup-codes.js";

export const runtime = "nodejs";
export const maxDuration = 45;

const buckets = globalThis.__windowsProtectPublicDownloads || new Map();
globalThis.__windowsProtectPublicDownloads = buckets;

function clean(value, max) { return String(value || "").trim().replace(/\s+/g, " ").slice(0, max); }
function validName(value) { return value.length >= 2 && /^[\p{L}\p{M}][\p{L}\p{M} .'’-]*$/u.test(value); }
function validEmail(value) { return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/u.test(value); }
function normalizePhone(value) {
  const input = clean(value, 40);
  if (!/^\+?[0-9 ().-]+$/.test(input)) return "";
  const digits = input.replace(/\D/g, "");
  return digits.length >= 7 && digits.length <= 15 ? (input.startsWith("+") ? "+" : "") + digits : "";
}
function sameOrigin(request) {
  const origin = request.headers.get("origin");
  return (!origin || origin === new URL(request.url).origin) && request.headers.get("sec-fetch-site") !== "cross-site";
}
function takeIpSlot(request) {
  const now = Date.now(), windowMs = 30 * 60000;
  if (buckets.size > 2000) for (const [key, value] of buckets) if (value.reset <= now) buckets.delete(key);
  const ip = clean((request.headers.get("x-forwarded-for") || "unknown").split(",")[0], 80);
  const value = buckets.get(ip);
  if (!value || value.reset <= now) { buckets.set(ip, { count: 1, reset: now + windowMs }); return true; }
  if (value.count >= 4) return false;
  value.count += 1; return true;
}

export async function POST(request) {
  if (!sameOrigin(request)) return Response.json({ error: "Open the download page directly and try again." }, { status: 403 });
  if (Number(request.headers.get("content-length") || 0) > 8192) return Response.json({ error: "The form is too large." }, { status: 413 });
  try {
    const body = await request.json();
    if (body.website) return Response.json({ error: "Unable to prepare this download." }, { status: 400 });
    const name = clean(body.name, 80), email = clean(body.email, 254).toLowerCase();
    const phone = normalizePhone(body.phone);
    const agent = ["Koko","Ashu"].includes(body.agent) ? body.agent : "";
    const pcName = clean(body.pc_name, 80) || `${name.split(" ")[0] || "My"}'s PC`;
    if (!validName(name)) return Response.json({ error: "Enter your full name using letters." }, { status: 400 });
    if (!validEmail(email)) return Response.json({ error: "Enter a valid email address." }, { status: 400 });
    if (!phone) return Response.json({ error: "Enter a valid phone number, including the country code when needed." }, { status: 400 });
    if (!agent) return Response.json({ error: "Choose Koko or Ashu as the support agent." }, { status: 400 });
    if (pcName.length < 2) return Response.json({ error: "Enter a name for this PC." }, { status: 400 });
    if (!takeIpSlot(request)) return Response.json({ error: "Too many downloads were requested. Please try again in 30 minutes." }, { status: 429 });

    const secret = process.env.DASHBOARD_PASSWORD;
    if (!secret) throw new Error("Download service is not configured");
    const fingerprint = crypto.createHmac("sha256", secret).update(`${email}|${phone}`).digest("hex").slice(0, 24);
    if (await recentPublicRequests(fingerprint) >= 3) return Response.json({ error: "This contact has already requested several downloads. Please use the newest one or try again later." }, { status: 429 });

    const { token, expiresAt } = createDownloadToken({ owner: name, label: pcName, agent, fingerprint });
    const downloadUrl = new URL(`/api/public/download/${token}`, request.url).toString();
    return Response.json({ download_url: downloadUrl, expires_at: expiresAt, filename: safeFilename(pcName) }, { headers: { "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer" } });
  } catch {
    return Response.json({ error: "The download could not be prepared. Please wait a moment and try again." }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
