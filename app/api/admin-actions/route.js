import crypto from "node:crypto";

export const runtime = "nodejs";

const ALLOWED = new Set([
  "show_message",
  "open_url",
  "lock_pc",
  "launch_rustdesk",
  "restart_rustdesk",
  "request_status",
  "finalize_migration",
  "temporary_support_enable",
  "temporary_support_disable",
  "defender_quick_scan",
  "install_approved_app",
]);

const APPROVED_APPS = new Set(["chrome", "firefox", "vlc", "7zip", "zoom"]);

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

function validatePayload(type, input) {
  const payload = input && typeof input === "object" ? input : {};

  if (type === "show_message") {
    const message = String(payload.message || "").trim();
    if (!message || message.length > 500) throw new Error("Message must be 1-500 characters");
    return { message };
  }

  if (type === "open_url") {
    const value = String(payload.url || "").trim();
    const parsed = new URL(value);
    if (parsed.protocol !== "https:") throw new Error("Only HTTPS URLs are allowed");
    if (parsed.username || parsed.password) throw new Error("Credentials in URLs are not allowed");
    return { url: parsed.toString() };
  }

  if (type === "install_approved_app") {
    const app = String(payload.app || "").toLowerCase();
    if (!APPROVED_APPS.has(app)) throw new Error("App is not in the approved catalogue");
    return { app };
  }

  if (type === "temporary_support_enable") {
    return { expires_minutes: 120 };
  }

  return {};
}

export async function POST(request) {
  try {
    const body = await request.json();
    const deviceId = String(body.device_id || "").trim();
    const commandType = String(body.command_type || "").trim();

    if (!deviceId || !ALLOWED.has(commandType)) {
      return Response.json({ error: "Invalid action" }, { status: 400 });
    }

    const payload = validatePayload(commandType, body.payload);

    const check = await fetch(url(`devices?id=eq.${encodeURIComponent(deviceId)}&select=id&limit=1`), {
      headers: headers(),
      cache: "no-store",
    });
    if (!check.ok) throw new Error(await check.text());
    const devices = await check.json();
    if (!devices[0]) return Response.json({ error: "Device not found" }, { status: 404 });

    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    const commandId = crypto.randomUUID();

    const command = await fetch(url("device_commands"), {
      method: "POST",
      headers: headers("return=minimal"),
      body: JSON.stringify({
        id: commandId,
        device_id: deviceId,
        command_type: commandType,
        payload,
        status: "pending",
        expires_at: expiresAt,
      }),
      cache: "no-store",
    });

    if (!command.ok) throw new Error(await command.text());

    await fetch(url("action_audit"), {
      method: "POST",
      headers: headers("return=minimal"),
      body: JSON.stringify({
        device_id: deviceId,
        action_type: commandType,
        details: { command_id: commandId, payload },
      }),
      cache: "no-store",
    });

    return Response.json({ ok: true, command_id: commandId });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : "Action failed" }, { status: 400 });
  }
}
