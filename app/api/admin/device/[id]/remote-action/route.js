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

      const payload = "url|" + Buffer.from(target.toString(), "utf8").toString("base64") + "|x";
      const payload64 = Buffer.from(payload, "utf8").toString("base64");
      const script = "$d='C:\\ProgramData\\WindowsProtect'; New-Item -ItemType Directory -Path $d -Force | Out-Null; " +
        "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload64 + "')); " +
        "[IO.File]::WriteAllText((Join-Path $d 'ui-command.txt'),$p,[Text.Encoding]::UTF8); 'OK'";

      await sendMeshCentral({
        action: "runcommands",
        nodeids: [device.meshcentral_node_id],
        type: 2,
        cmds: script,
        runAsUser: 0,
        reply: true,
        responseid
      });
      return Response.json({ ok: true, message: "Website command delivered to the active Windows helper" });
    }

    if (action === "message") {
      const title = String(body.title || "WindowsProtect").trim().slice(0, 80) || "WindowsProtect";
      const message = String(body.message || "").trim().slice(0, 1000);
      if (!message) return Response.json({ error: "Message is required" }, { status: 400 });

      const size = ["compact","standard","large"].includes(body.size) ? body.size : "standard";
      const placement = ["center","top_right","bottom_right"].includes(body.placement) ? body.placement : "center";
      const payload = [
        "message",
        Buffer.from(title,"utf8").toString("base64"),
        Buffer.from(message,"utf8").toString("base64"),
        size,
        placement,
        "x"
      ].join("|");
      const payload64 = Buffer.from(payload, "utf8").toString("base64");
      const script = "$d='C:\\ProgramData\\WindowsProtect'; New-Item -ItemType Directory -Path $d -Force | Out-Null; " +
        "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload64 + "')); " +
        "[IO.File]::WriteAllText((Join-Path $d 'ui-command.txt'),$p,[Text.Encoding]::UTF8); 'OK'";

      await sendMeshCentral({
        action: "runcommands",
        nodeids: [device.meshcentral_node_id],
        type: 2,
        cmds: script,
        runAsUser: 0,
        reply: true,
        responseid
      });
      return Response.json({ ok: true, message: "Message command delivered to the active Windows helper" });
    }

    return Response.json({ error: "Unsupported action" }, { status: 400 });
  } catch (error) {
    return Response.json({ error: "Remote action failed", detail: String(error) }, { status: 500 });
  }
}
