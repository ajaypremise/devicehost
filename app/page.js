import Link from "next/link";

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

function remoteSupportOn(device) {
  return device.remote_access_provider === "meshcentral"
    ? device.meshcentral_connected === true
    : device.rustdesk_service_running === true;
}

function postureLabel(value) {
  return value && value !== "unknown" ? value : "Awaiting telemetry";
}

export default async function Home({ searchParams }) {
  const params = (await searchParams) || {};
  const q = String(params.q || "").trim();
  const requestedPage = Number.parseInt(String(params.page || "1"), 10) || 1;
  const pageSize = 20;

  let devices = [];
  let events = [];
  let error = "";

  try {
    [devices, events] = await Promise.all([
      supabaseGet("devices?select=*&order=created_at.desc"),
      supabaseGet("security_events?select=id,device_id,event_type,severity,title,details,created_at&order=created_at.desc&limit=12"),
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

  const needle = q.toLowerCase();
  const filtered = needle
    ? devices.filter((d) => [d.person_name, d.device_name, d.computer_name, d.device_code]
        .some((v) => String(v || "").toLowerCase().includes(needle)))
    : devices;

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(Math.max(1, requestedPage), totalPages);
  const start = (currentPage - 1) * pageSize;
  const pageDevices = filtered.slice(start, start + pageSize);

  function pageHref(page) {
    const query = new URLSearchParams();
    if (q) query.set("q", q);
    query.set("page", String(page));
    return `/?${query.toString()}`;
  }

  return (
    <main className="shell wideShell">
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
        <div className="sectionHeading deviceHeading">
          <div>
            <h2>Devices</h2>
            <span>{filtered.length}{q ? ` matching of ${devices.length}` : " enrolled"}</span>
          </div>
          <form className="deviceSearch" method="get">
            <input name="q" defaultValue={q} placeholder="Search name, PC or Device ID" />
            <button type="submit">Search</button>
            {q ? <Link href="/" className="clearSearch">Clear</Link> : null}
          </form>
        </div>

        {filtered.length === 0 && !error ? (
          <div className="empty">
            <h3>{q ? "No matching devices" : "No PCs enrolled yet"}</h3>
            <p>{q ? "Try a different name, computer name or Device ID." : "DeviceHost is ready. The first WindowsProtect PC will appear here after enrollment."}</p>
          </div>
        ) : (
          <>
            <div className="deviceTableWrap">
              <table className="deviceTable">
                <thead>
                  <tr>
                    <th>Owner / device</th>
                    <th>Computer</th>
                    <th>Status</th>
                    <th>Protection</th>
                    <th>Remote support</th>
                    <th>Last seen</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {pageDevices.map((device) => {
                    const onlineNow = isOnline(device.last_seen_at);
                    const remoteOn = remoteSupportOn(device);
                    return (
                      <tr key={device.id}>
                        <td>
                          <Link className="devicePrimary" href={`/device/${device.id}`}>
                            <strong>{device.person_name || "Unnamed"}</strong>
                            <span>{device.device_name || "Unnamed device"} · {device.device_code}</span>
                          </Link>
                        </td>
                        <td>{device.computer_name || "Pending"}</td>
                        <td><span className={onlineNow ? "status online" : "status offline"}>{onlineNow ? "Online" : "Offline"}</span></td>
                        <td><span className={`tablePosture ${device.security_posture || "unknown"}`}>{postureLabel(device.security_posture)}</span></td>
                        <td><span className={remoteOn ? "health good" : "health bad"}>{remoteOn ? "On" : "Off"}</span></td>
                        <td>{timeAgo(device.last_seen_at)}</td>
                        <td><Link className="openDevice" href={`/device/${device.id}`}>Open</Link></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {totalPages > 1 ? (
              <nav className="pagination" aria-label="Device pages">
                <Link className={currentPage === 1 ? "disabled" : ""} href={pageHref(Math.max(1, currentPage - 1))}>Previous</Link>
                <span>Page {currentPage} of {totalPages}</span>
                <Link className={currentPage === totalPages ? "disabled" : ""} href={pageHref(Math.min(totalPages, currentPage + 1))}>Next</Link>
              </nav>
            ) : null}
          </>
        )}
      </section>

      <section className="section">
        <div className="sectionHeading"><h2>Recent security events</h2><span>Latest 12</span></div>
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
