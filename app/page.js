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
function health(value) {
  if (value === true) return <span className="health good">On</span>;
  if (value === false) return <span className="health bad">Off</span>;
  return <span className="health unknown">Unknown</span>;
}
function postureLabel(value) {
  return value && value !== "unknown" ? value : "Awaiting telemetry";
}

export default async function Home() {
  let devices = [];
  let events = [];
  let error = "";

  try {
    [devices, events] = await Promise.all([
      supabaseGet("devices?select=*&order=created_at.desc"),
      supabaseGet("security_events?select=id,device_id,event_type,severity,title,details,created_at&order=created_at.desc&limit=20"),
    ]);
  } catch (err) {
    error = err instanceof Error ? err.message : "Unable to load dashboard.";
  }

  const online = devices.filter((d) => isOnline(d.last_seen_at)).length;
  const protectedCount = devices.filter((d) => d.protection_status === "protected").length;
  const attention = devices.filter((d) =>
    d.security_posture === "warning" || d.security_posture === "critical" ||
    (Array.isArray(d.remote_tools_detected) && d.remote_tools_detected.length > 0)
  ).length;

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <div className="eyebrow">WINDOWSPROTECT</div>
          <h1>DeviceHost</h1>
          <p>Family PC protection, security health and managed remote-support visibility.</p>
        </div>
        <div className="liveBadge"><span className="dot" />Live dashboard</div>
      </header>

      <section className="stats">
        <article><span>Total devices</span><strong>{devices.length}</strong></article>
        <article><span>Online</span><strong>{online}</strong></article>
        <article><span>Protected</span><strong>{protectedCount}</strong></article>
        <article><span>Needs attention</span><strong>{attention}</strong></article>
      </section>

      {error ? <div className="errorBox">{error}</div> : null}

      <section className="section">
        <div className="sectionHeading"><h2>Devices</h2><span>{devices.length} enrolled</span></div>
        {devices.length === 0 && !error ? (
          <div className="empty">
            <h3>No PCs enrolled yet</h3>
            <p>DeviceHost is ready. The first WindowsProtect PC will appear here after enrollment.</p>
          </div>
        ) : (
          <div className="deviceGrid">
            {devices.map((device) => {
              const onlineNow = isOnline(device.last_seen_at);
              const tools = Array.isArray(device.remote_tools_detected) ? device.remote_tools_detected : [];
              return (
                <article className="deviceCard" key={device.id}>
                  <div className="cardTop">
                    <div>
                      <h3>{device.person_name}</h3>
                      <p>{device.device_name} · {device.computer_name || "Computer name pending"}</p>
                    </div>
                    <span className={onlineNow ? "status online" : "status offline"}>
                      {onlineNow ? "Online" : "Offline"}
                    </span>
                  </div>

                  <div className="postureRow">
                    <span>Security posture</span>
                    <strong className={`posture ${device.security_posture || "unknown"}`}>
                      {postureLabel(device.security_posture)}
                    </strong>
                  </div>

                  <div className="healthGrid">
                    <div><span>Defender</span>{health(device.defender_enabled)}</div>
                    <div><span>Firewall</span>{health(device.firewall_enabled)}</div>
                    <div><span>SmartScreen</span>{health(device.smartscreen_enabled)}</div>
                    <div><span>Remote support</span>{health(
                      device.remote_access_provider === "meshcentral"
                        ? device.meshcentral_connected
                        : device.rustdesk_service_running
                    )}</div>
                  </div>

                  <dl>
                    <div><dt>Device ID</dt><dd>{device.device_code}</dd></div>
                    <div><dt>Remote access</dt><dd>{device.remote_access_provider === "meshcentral" ? "MeshCentral" : (device.remote_access_provider || "Pending")}</dd></div>
                    <div><dt>MeshCentral node</dt><dd>{device.meshcentral_node_id || "Pending"}</dd></div>
                    <div><dt>MeshCentral agent</dt><dd>{device.meshcentral_agent_version || "—"}</dd></div>
                    <div><dt>Temporary support</dt><dd>{
                      device.temporary_support_expires_at
                        ? `Until ${new Date(device.temporary_support_expires_at).toLocaleString()}`
                        : "Off"
                    }</dd></div>
                    <div><dt>Migration</dt><dd>{device.migration_status || "not_started"}</dd></div>
                    <div><dt>Windows</dt><dd>{device.os_version || "—"}</dd></div>
                    <div><dt>Agent</dt><dd>{device.agent_version || "—"}</dd></div>
                    <div><dt>Installed apps</dt><dd>{device.installed_apps_count ?? "—"}</dd></div>
                    <div><dt>Last seen</dt><dd>{timeAgo(device.last_seen_at)}</dd></div>
                  </dl>

                  <div className={tools.length ? "remoteTools dangerBox" : "remoteTools safeBox"}>
                    <strong>{tools.length ? "Remote-access software detected" : "No unauthorized remote tools reported"}</strong>
                    {tools.length ? <p>{tools.join(", ")}</p> : null}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>

      <section className="section">
        <div className="sectionHeading"><h2>Recent security events</h2><span>Latest 20</span></div>
        {events.length === 0 && !error ? (
          <div className="empty compact"><p>No security events yet.</p></div>
        ) : (
          <div className="events">
            {events.map((event) => {
              const device = devices.find((d) => d.id === event.device_id);
              return (
                <div className="eventRow" key={event.id}>
                  <span className={`severity ${event.severity}`} />
                  <div>
                    <strong>{event.title}</strong>
                    <p>{device ? `${device.person_name} · ` : ""}{event.event_type}</p>
                  </div>
                  <time>{timeAgo(event.created_at)}</time>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <section className="section">
        <div className="noticeBox">
          <strong>Remote support is separated from DeviceHost</strong>
          <p>DeviceHost monitors WindowsProtect security health. Interactive remote control is handled by the separately authenticated MeshCentral server; DeviceHost does not expose a remote shell.</p>
        </div>
      </section>
    </main>
  );
}
