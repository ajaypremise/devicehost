import Link from "next/link";
import { notFound } from "next/navigation";
import DeviceNameEditor from "./DeviceNameEditor";

export const dynamic = "force-dynamic";

async function supabaseGet(resource) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error("Supabase environment variables are missing.");
  const response = await fetch(`${url}/rest/v1/${resource}`, {
    headers: { apikey: key, Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Supabase request failed (${response.status}): ${await response.text()}`);
  return response.json();
}

function timeAgo(value) {
  if (!value) return "Never";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function isOnline(lastSeen) {
  return Boolean(lastSeen) && Date.now() - new Date(lastSeen).getTime() < 10 * 60 * 1000;
}

function StateBlock({ label, value, state = "neutral", note }) {
  return (
    <article className={`stateBlock ${state}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {note ? <small>{note}</small> : null}
    </article>
  );
}

function DetailBlock({ title, children }) {
  return <article className="detailBlock"><h2>{title}</h2>{children}</article>;
}

function Row({ label, children }) {
  return <div className="detailRow"><span>{label}</span><strong>{children ?? "—"}</strong></div>;
}

export default async function DevicePage({ params }) {
  const { id } = await params;
  const [devices, events, inventory] = await Promise.all([
    supabaseGet(`devices?id=eq.${encodeURIComponent(id)}&select=*&limit=1`),
    supabaseGet(`security_events?device_id=eq.${encodeURIComponent(id)}&select=id,event_type,severity,title,details,created_at&order=created_at.desc&limit=20`),
    supabaseGet(`software_inventory?device_id=eq.${encodeURIComponent(id)}&select=id,app_name,app_version,publisher,is_remote_access,last_seen_at&order=is_remote_access.desc,app_name.asc&limit=250`),
  ]);

  const device = devices[0];
  if (!device) notFound();

  const online = isOnline(device.last_seen_at);
  const tools = Array.isArray(device.remote_tools_detected) ? device.remote_tools_detected : [];
  const mesh = device.remote_access_provider === "meshcentral";
  const remoteOn = mesh ? device.meshcentral_connected === true : device.rustdesk_service_running === true;

  return (
    <main className="shell wideShell">
      <div className="detailTop">
        <div>
          <Link href="/" className="backLink">← All devices</Link>
          <div className="eyebrow">WINDOWSPROTECT DEVICE</div>
          <h1>{device.person_name || "Unnamed device"}</h1>
          <p>{device.device_name || "Device"} · {device.computer_name || "Computer name pending"} · {device.device_code}</p>
        </div>
        <div className="detailActions">
          <span className={online ? "status online" : "status offline"}>{online ? "Online" : "Offline"}</span>
          <DeviceNameEditor deviceId={device.id} personName={device.person_name || ""} deviceName={device.device_name || ""} />
          <a className="primaryAction" href="https://34-69-184-103.sslip.io" target="_blank" rel="noreferrer">Open MeshCentral</a>
        </div>
      </div>

      <section className="stateGrid">
        <StateBlock label="Security posture" value={device.security_posture && device.security_posture !== "unknown" ? device.security_posture : "Awaiting telemetry"} state={device.security_posture === "healthy" ? "good" : device.security_posture === "critical" ? "bad" : device.security_posture === "warning" ? "warn" : "neutral"} />
        <StateBlock label="WindowsProtect" value={device.protection_status || "Pending"} state={device.protection_status === "protected" ? "good" : "warn"} note={device.agent_version ? `Agent ${device.agent_version}` : "Agent version pending"} />
        <StateBlock label="Remote support" value={remoteOn ? "Connected" : "Off"} state={remoteOn ? "good" : "bad"} note={mesh ? "MeshCentral" : (device.remote_access_provider || "Pending")} />
        <StateBlock label="Last seen" value={timeAgo(device.last_seen_at)} state={online ? "good" : "neutral"} note={device.last_seen_at ? new Date(device.last_seen_at).toLocaleString() : "No heartbeat yet"} />
      </section>

      <section className="quickActions">
        <a href="https://34-69-184-103.sslip.io" target="_blank" rel="noreferrer"><strong>Remote desktop</strong><span>Open this device in MeshCentral</span></a>
        <a href="https://34-69-184-103.sslip.io" target="_blank" rel="noreferrer"><strong>Message user</strong><span>Use MeshCentral chat / message</span></a>
        <a href="https://34-69-184-103.sslip.io" target="_blank" rel="noreferrer"><strong>Open webpage</strong><span>Use MeshCentral supported user action</span></a>
        <a href="https://34-69-184-103.sslip.io" target="_blank" rel="noreferrer"><strong>Temporary support</strong><span>Create a time-limited guest link</span></a>
      </section>

      <section className="detailGrid">
        <DetailBlock title="Security health">
          <Row label="Microsoft Defender">{device.defender_enabled === true ? "On" : device.defender_enabled === false ? "Off" : "Unknown"}</Row>
          <Row label="Windows Firewall">{device.firewall_enabled === true ? "On" : device.firewall_enabled === false ? "Off" : "Unknown"}</Row>
          <Row label="SmartScreen">{device.smartscreen_enabled === true ? "On" : device.smartscreen_enabled === false ? "Off" : "Unknown"}</Row>
          <Row label="Security posture">{device.security_posture || "unknown"}</Row>
        </DetailBlock>

        <DetailBlock title="Remote support">
          <Row label="Provider">{mesh ? "MeshCentral" : (device.remote_access_provider || "Pending")}</Row>
          <Row label="Connection">{remoteOn ? "Connected" : "Off"}</Row>
          <Row label="MeshCentral node">{device.meshcentral_node_id || "Pending"}</Row>
          <Row label="MeshCentral agent">{device.meshcentral_agent_version || "Pending"}</Row>
          <Row label="Temporary support">{device.temporary_support_expires_at ? `Until ${new Date(device.temporary_support_expires_at).toLocaleString()}` : "Off"}</Row>
        </DetailBlock>

        <DetailBlock title="Device identity">
          <Row label="Owner">{device.person_name}</Row>
          <Row label="Device label">{device.device_name}</Row>
          <Row label="Computer name">{device.computer_name}</Row>
          <Row label="Device ID">{device.device_code}</Row>
          <Row label="Migration">{device.migration_status || "not_started"}</Row>
        </DetailBlock>

        <DetailBlock title="System">
          <Row label="Windows">{device.os_version}</Row>
          <Row label="WindowsProtect agent">{device.agent_version}</Row>
          <Row label="Installed apps">{device.installed_apps_count ?? "Pending"}</Row>
          <Row label="Uptime">{device.uptime_seconds != null ? `${Math.floor(device.uptime_seconds / 3600)} hours` : "Pending"}</Row>
        </DetailBlock>
      </section>

      <section className="section">
        <div className={tools.length ? "remoteTools dangerBox detailAlert" : "remoteTools safeBox detailAlert"}>
          <strong>{tools.length ? "Unauthorized remote-access software detected" : "No unauthorized remote tools reported"}</strong>
          {tools.length ? <p>{tools.join(", ")}</p> : <p>Approved MeshCentral access is tracked separately and is not treated as an unauthorized tool.</p>}
        </div>
      </section>

      <section className="section">
        <div className="sectionHeading"><h2>Installed applications</h2><span>{inventory.length} reported</span></div>
        {inventory.length === 0 ? (
          <div className="empty compact"><p>Software inventory has not been uploaded yet.</p></div>
        ) : (
          <div className="inventoryTableWrap">
            <table className="inventoryTable">
              <thead><tr><th>Application</th><th>Version</th><th>Publisher</th><th>Remote access</th></tr></thead>
              <tbody>
                {inventory.map((app) => (
                  <tr key={app.id}>
                    <td>{app.app_name}</td>
                    <td>{app.app_version || "—"}</td>
                    <td>{app.publisher || "—"}</td>
                    <td>{app.is_remote_access ? <span className="health bad">Unauthorized</span> : <span className="health good">No</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="section">
        <div className="sectionHeading"><h2>Security events</h2><span>Latest 20 for this device</span></div>
        {events.length === 0 ? (
          <div className="empty compact"><p>No security events recorded for this device.</p></div>
        ) : (
          <div className="events">
            {events.map((event) => (
              <div className="eventRow" key={event.id}>
                <span className={`severity ${event.severity}`} />
                <div><strong>{event.title}</strong><p>{event.event_type}</p></div>
                <time>{timeAgo(event.created_at)}</time>
              </div>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}
