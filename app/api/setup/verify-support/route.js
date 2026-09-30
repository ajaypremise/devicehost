import crypto from "node:crypto";
import { probeRemoteSupport } from "../../../lib/mesh-support-check.js";

export const runtime = "nodejs";
export const maxDuration = 35;

export async function POST(request) {
  const response = (body, status = 200) => Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
  try {
    const token = request.headers.get("x-device-token");
    if (!token || token.length > 256) return response({ error: "Unauthorized" }, 401);
    const key = process.env.SUPABASE_SECRET_KEY, base = process.env.SUPABASE_URL;
    if (!key || !base) return response({ error: "Support verification unavailable" }, 503);
    const hash = crypto.createHash("sha256").update(token).digest("hex");
    const lookup = await fetch(`${base}/rest/v1/devices?agent_token_hash=eq.${hash}&select=id,meshcentral_node_id,last_seen_at&limit=1`, {
      headers: { apikey: key, Accept: "application/json" }, cache: "no-store", signal: AbortSignal.timeout(4000),
    });
    if (!lookup.ok) throw new Error("Device lookup failed");
    const [device] = await lookup.json();
    if (!device) return response({ error: "Unauthorized" }, 401);
    // Read the enrolled device's node from its recent heartbeat, never a
    // caller-supplied target. No arbitrary remote-action endpoint is exposed.
    const age = Date.now() - Date.parse(device.last_seen_at);
    if (!device.meshcentral_node_id || !Number.isFinite(age) || age < -5000 || age > 120000) {
      return response({ error: "Waiting for this PC's secure support connection", retryable: true }, 409);
    }
    const challenge = crypto.randomBytes(32).toString("hex");
    const proof = await probeRemoteSupport(device.meshcentral_node_id, challenge);
    return response({ ...proof, challenge });
  } catch {
    // Do not leak control-plane URLs, cookies, credentials or screen contents.
    return response({ error: "Secure support could not be verified. Protection has not been activated.", retryable: true }, 503);
  }
}
