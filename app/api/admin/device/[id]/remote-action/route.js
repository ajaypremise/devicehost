import { meshcentralConfigured, sendMeshCentral } from "../../../../../lib/meshcentral";

export const runtime = "nodejs";

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
    `${baseUrl()}/rest/v1/devices?id=eq.${encodeURIComponent(id)}&select=id,meshcentral_node_id,meshcentral_connected,person_name,device_name&limit=1`,
    { headers: headers(), cache: "no-store" }
  );
  if (!response.ok) throw new Error(await response.text());
  const rows = await response.json();
  return rows[0] || null;
}

export async function POST(request, { params }) {
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

    if (action === "open_url") {
      let target;
      try { target = new URL(String(body.url || "").trim()); }
      catch { return Response.json({ error: "Enter a valid website URL" }, { status: 400 }); }

      if (!["http:", "https:"].includes(target.protocol)) {
        return Response.json({ error: "Only http:// and https:// websites are allowed" }, { status: 400 });
      }

      await sendMeshCentral({
        action: "msg",
        type: "openUrl",
        nodeid: device.meshcentral_node_id,
        url: target.toString(),
        responseid
      });
      return Response.json({ ok: true, message: "Website sent to PC" });
    }

    if (action === "message") {
      const title = String(body.title || "WindowsProtect").trim().slice(0, 80) || "WindowsProtect";
      const message = String(body.message || "").trim().slice(0, 1000);
      if (!message) return Response.json({ error: "Message is required" }, { status: 400 });

      // MeshCentral's native dialog targets the console session, which can be invisible
      // on Windows Server/RDP. Use Windows msg.exe through a fixed, non-user-editable
      // PowerShell wrapper so the message is delivered to active interactive sessions.
      const text = `${title}\r\n\r\n${message}`;
      const b64 = Buffer.from(text, "utf8").toString("base64");
      const script = `$m=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')); & "$env:SystemRoot\\System32\\msg.exe" * /TIME:120 $m; if($LASTEXITCODE -ne 0){ throw "Message delivery failed with exit code $LASTEXITCODE" }`;

      await sendMeshCentral({
        action: "runcommands",
        nodeids: [device.meshcentral_node_id],
        type: 2,
        cmds: script,
        runAsUser: 0,
        reply: true,
        responseid
      });
      return Response.json({ ok: true, message: "Message delivered to Windows session" });
    }

    return Response.json({ error: "Unsupported action" }, { status: 400 });
  } catch (error) {
    return Response.json({ error: "Remote action failed", detail: String(error) }, { status: 500 });
  }
}
