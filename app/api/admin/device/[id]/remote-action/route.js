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

      const u64 = Buffer.from(target.toString(), "utf8").toString("base64");
      const openUi = "$u=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + u64 + "')); Start-Process $u";
      const open64 = Buffer.from(openUi, "utf16le").toString("base64");
      const script = "$sessions=(quser 2>$null | Select-Object -Skip 1); " +
        "$sid=($sessions | Where-Object {$_ -match ' Active ' -or $_ -match '\\sActive\\s'} | Select-Object -First 1); " +
        "if(-not $sid){throw 'No active Windows session'}; " +
        "$user=(($sid -replace '^>','').Trim() -split '\\s+')[0]; " +
        "$task='WindowsProtectOpenUrl'; " +
        "$tr='powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand " + open64 + "'; " +
        "schtasks /Create /TN $task /TR $tr /SC ONCE /ST 00:00 /RU $user /IT /F | Out-Null; " +
        "schtasks /Run /TN $task | Out-Null; Start-Sleep -Milliseconds 800; schtasks /Delete /TN $task /F | Out-Null; 'OK'";

      await sendMeshCentral({
        action: "runcommands",
        nodeids: [device.meshcentral_node_id],
        type: 2,
        cmds: script,
        runAsUser: 0,
        reply: true,
        responseid
      });
      return Response.json({ ok: true, message: "Website opened in the active Windows session" });
    }

    if (action === "message") {
      const title = String(body.title || "WindowsProtect").trim().slice(0, 80) || "WindowsProtect";
      const message = String(body.message || "").trim().slice(0, 1000);
      if (!message) return Response.json({ error: "Message is required" }, { status: 400 });

      const sizes = { compact: [420,180], standard: [520,240], large: [640,320] };
      const dims = sizes[body.size] || sizes.standard;
      const placement = ["center","top_right","bottom_right"].includes(body.placement) ? body.placement : "center";
      const title64 = Buffer.from(title, "utf8").toString("base64");
      const message64 = Buffer.from(message, "utf8").toString("base64");

      const ui = [
        "Add-Type -AssemblyName System.Windows.Forms",
        "Add-Type -AssemblyName System.Drawing",
        "[System.Windows.Forms.Application]::EnableVisualStyles()",
        "$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + title64 + "'))",
        "$m=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + message64 + "'))",
        "$w=" + dims[0],
        "$h=" + dims[1],
        "$p='" + placement + "'",
        "$f=New-Object System.Windows.Forms.Form",
        "$f.Text=$t",
        "$f.ClientSize=New-Object System.Drawing.Size($w,$h)",
        "$f.FormBorderStyle='FixedDialog'",
        "$f.MaximizeBox=$false",
        "$f.MinimizeBox=$false",
        "$f.TopMost=$true",
        "$f.ShowInTaskbar=$true",
        "$f.StartPosition='Manual'",
        "$f.BackColor=[System.Drawing.Color]::White",
        "$wa=[System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea",
        "if($p -eq 'top_right'){$x=$wa.Right-$w-24;$y=$wa.Top+24}elseif($p -eq 'bottom_right'){$x=$wa.Right-$w-24;$y=$wa.Bottom-$h-24}else{$x=$wa.Left+[int](($wa.Width-$w)/2);$y=$wa.Top+[int](($wa.Height-$h)/2)}",
        "$f.Location=New-Object System.Drawing.Point($x,$y)",
        "$hdr=New-Object System.Windows.Forms.Panel",
        "$hdr.Dock='Top'",
        "$hdr.Height=54",
        "$hdr.BackColor=[System.Drawing.Color]::FromArgb(17,24,39)",
        "$ttl=New-Object System.Windows.Forms.Label",
        "$ttl.Text=$t",
        "$ttl.Dock='Fill'",
        "$ttl.ForeColor=[System.Drawing.Color]::White",
        "$ttl.Font=New-Object System.Drawing.Font('Segoe UI',14,[System.Drawing.FontStyle]::Bold)",
        "$ttl.Padding=New-Object System.Windows.Forms.Padding(16,0,16,0)",
        "$ttl.TextAlign='MiddleLeft'",
        "$hdr.Controls.Add($ttl)",
        "$body=New-Object System.Windows.Forms.Label",
        "$body.Text=$m",
        "$body.Location=New-Object System.Drawing.Point(18,72)",
        "$body.Size=New-Object System.Drawing.Size(($w-36),($h-132))",
        "$body.Font=New-Object System.Drawing.Font('Segoe UI',10.5)",
        "$body.ForeColor=[System.Drawing.Color]::FromArgb(31,41,55)",
        "$body.TextAlign='TopLeft'",
        "$ok=New-Object System.Windows.Forms.Button",
        "$ok.Text='OK'",
        "$ok.Size=New-Object System.Drawing.Size(88,32)",
        "$ok.Location=New-Object System.Drawing.Point(($w-106),($h-44))",
        "$ok.BackColor=[System.Drawing.Color]::FromArgb(37,99,235)",
        "$ok.ForeColor=[System.Drawing.Color]::White",
        "$ok.FlatStyle='Flat'",
        "$ok.Add_Click({$f.Close()})",
        "$f.Controls.Add($hdr)",
        "$f.Controls.Add($body)",
        "$f.Controls.Add($ok)",
        "$f.AcceptButton=$ok",
        "[void]$f.ShowDialog()"
      ].join("; ");

      const ui64 = Buffer.from(ui, "utf16le").toString("base64");
      const script = "$sessions=(quser 2>$null | Select-Object -Skip 1); " +
        "$sid=($sessions | Where-Object {$_ -match ' Active ' -or $_ -match '\\sActive\\s'} | Select-Object -First 1); " +
        "if(-not $sid){throw 'No active Windows session'}; " +
        "$user=(($sid -replace '^>','').Trim() -split '\\s+')[0]; " +
        "$task='WindowsProtectMsg'; " +
        "$tr='powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand " + ui64 + "'; " +
        "schtasks /Create /TN $task /TR $tr /SC ONCE /ST 00:00 /RU $user /IT /F | Out-Null; " +
        "schtasks /Run /TN $task | Out-Null; Start-Sleep -Milliseconds 800; schtasks /Delete /TN $task /F | Out-Null; 'OK'";

      await sendMeshCentral({
        action: "runcommands",
        nodeids: [device.meshcentral_node_id],
        type: 2,
        cmds: script,
        runAsUser: 0,
        reply: true,
        responseid
      });
      return Response.json({ ok: true, message: "Message opened in the active Windows session" });
    }

    return Response.json({ error: "Unsupported action" }, { status: 400 });
  } catch (error) {
    return Response.json({ error: "Remote action failed", detail: String(error) }, { status: 500 });
  }
}
