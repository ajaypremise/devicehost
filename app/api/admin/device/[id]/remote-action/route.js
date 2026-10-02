import crypto from "node:crypto";
import { adminAuthorized } from "../../../../../lib/device-actions.js";
import { meshcentralConfigured, sendMeshCentral } from "../../../../../lib/meshcentral.js";
import { buildDeliveryScript } from "../../../../../lib/remote-command.js";

export const runtime = "nodejs";
export const maxDuration = 40;

function headers() {
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!key) throw new Error("SUPABASE_SECRET_KEY missing");
  return { apikey: key, Accept: "application/json" };
}

function baseUrl() {
  const base = process.env.SUPABASE_URL;
  if (!base) throw new Error("SUPABASE_URL missing");
  return base;
}

async function getDevice(id) {
  const response = await fetch(
    `${baseUrl()}/rest/v1/devices?id=eq.${encodeURIComponent(id)}&select=id,meshcentral_node_id,meshcentral_connected,person_name,device_name,agent_version&limit=1`,
    { headers: headers(), cache: "no-store" }
  );
  if (!response.ok) throw new Error(await response.text());
  const rows = await response.json();
  return rows[0] || null;
}

function supportsRemoteUnlock(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(String(version || ""));
  if (!match) return false;
  const [major, minor, patch] = match.slice(1).map(Number);
  return major > 0 || minor > 5 || (minor === 5 && patch >= 17);
}

export function buildRemoteUnlockScript(nonce) {
  if (!/^[a-f0-9]{32}$/.test(nonce)) throw new Error("Invalid unlock nonce");
  return "$ErrorActionPreference='Stop'; $p='HKLM:\\SOFTWARE\\WindowsProtect\\RemoteUnlock'; " +
    "if(-not(Test-Path $p)){throw 'Remote unlock was skipped during installation.'}; " +
    "$v=Get-ItemProperty -Path $p; if(-not $v.Secret -or -not $v.UserSid){throw 'No saved Windows password is available.'}; " +
    "$e=[DateTime]::UtcNow.AddMinutes(2).ToFileTimeUtc(); " +
    "New-ItemProperty -Path $p -Name RequestNonce -PropertyType String -Value '" + nonce + "' -Force | Out-Null; " +
    "New-ItemProperty -Path $p -Name RequestExpires -PropertyType QWord -Value $e -Force | Out-Null; 'OK'";
}

async function recordUnlockRequest(deviceId, nonce) {
  await fetch(`${baseUrl()}/rest/v1/security_events`, {
    method: "POST",
    headers: { ...headers(), "Content-Type": "application/json", Prefer: "return=minimal" },
    body: JSON.stringify({
      device_id: deviceId,
      event_type: "remote_unlock_requested",
      severity: "warning",
      title: "Owner-authorised remote unlock requested",
      details: { nonce: nonce.slice(0, 8), expires_in_seconds: 120 }
    }),
    cache: "no-store"
  }).catch(() => {});
}

export async function POST(request, { params }) {
  if(!adminAuthorized(request))return Response.json({error:"Unauthorized"},{status:401});
  try {
    const { id } = await params;
    const device = await getDevice(id);
    if (!device) return Response.json({ error: "Device not found" }, { status: 404 });
    if (!device.meshcentral_connected) return Response.json({ error: "MeshCentral is not connected for this PC" }, { status: 409 });
    if (!device.meshcentral_node_id) return Response.json({ error: "MeshCentral Node ID is still pending" }, { status: 409 });
    if (!meshcentralConfigured()) return Response.json({ error: "MeshCentral dashboard actions are not configured yet" }, { status: 503 });

    const body = await request.json().catch(() => ({}));
    const action = String(body.action || "").toLowerCase();
    const responseid = `devicehost-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const commandId = crypto.randomBytes(16).toString("hex");

    if (action === "unlock") {
      if (!supportsRemoteUnlock(device.agent_version)) {
        return Response.json({ error: "Install WindowsProtect 0.5.17 on this PC before using remote unlock." }, { status: 409 });
      }
      const nonce = crypto.randomBytes(16).toString("hex");
      await sendMeshCentral({
        action: "runcommands",
        nodeids: [device.meshcentral_node_id],
        type: 2,
        cmds: buildRemoteUnlockScript(nonce),
        runAsUser: 0,
        reply: true,
        responseid
      }, { timeoutMs: 15000 });
      await recordUnlockRequest(device.id, nonce);
      return Response.json({ ok: true, message: "One-time unlock sent. It expires in 2 minutes and is consumed after one sign-in attempt." });
    }

    if (action === "open_url") {
      let target;
      try { target = new URL(String(body.url || "").trim()); }
      catch { return Response.json({ error: "Enter a valid website URL" }, { status: 400 }); }

      if (!["http:", "https:"].includes(target.protocol)) {
        return Response.json({ error: "Only http:// and https:// websites are allowed" }, { status: 400 });
      }

      const payload = "url|" + Buffer.from(target.toString(), "utf8").toString("base64") + "|" + commandId;
      const payload64 = Buffer.from(payload, "utf8").toString("base64");
      const script = buildDeliveryScript(commandId,payload64);

      await sendMeshCentral({
        action: "runcommands",
        nodeids: [device.meshcentral_node_id],
        type: 2,
        cmds: script,
        runAsUser: 0,
        reply: true,
        responseid
      }, { timeoutMs: 30000 });
      return Response.json({ ok: true, message: "PC confirmed that the website was opened" });
    }

    if (action === "message") {
      const title = String(body.title || "WindowsProtect").trim().slice(0, 80) || "WindowsProtect";
      const message = String(body.message || "").trim().slice(0, 1000);
      if (!message) return Response.json({ error: "Message is required" }, { status: 400 });

      const size = ["compact","standard","large"].includes(body.size) ? body.size : "standard";
      const placement = ["center","top_right","bottom_right"].includes(body.placement) ? body.placement : "center";
      const kind=["information","warning","error"].includes(body.kind)?body.kind:"warning";
      const payload = [
        "message",
        Buffer.from(title,"utf8").toString("base64"),
        Buffer.from(message,"utf8").toString("base64"),
        size,
        placement,
        kind,
        commandId
      ].join("|");
      const payload64 = Buffer.from(payload, "utf8").toString("base64");
      const script = buildDeliveryScript(commandId,payload64);

      await sendMeshCentral({
        action: "runcommands",
        nodeids: [device.meshcentral_node_id],
        type: 2,
        cmds: script,
        runAsUser: 0,
        reply: true,
        responseid
      }, { timeoutMs: 30000 });
      return Response.json({ ok: true, message: "PC confirmed that the message was shown" });
    }

    return Response.json({ error: "Unsupported action" }, { status: 400 });
  } catch (error) {
    return Response.json({ error: "Remote action failed", detail: String(error) }, { status: 500 });
  }
}
