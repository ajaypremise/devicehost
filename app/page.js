export const dynamic = "force-dynamic";

async function supabaseGet(resource) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    throw new Error("Supabase environment variables are missing.");
  }

  const response = await fetch(`${url}/rest/v1/${resource}`, {
    headers: {
      apikey: key,
      Accept: "application/json",
    },
    cache: "no-store",
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Supabase request failed (${response.status}): ${detail}`);
  }

  return response.json();
}

function timeAgo(value) {
  if (!value) return "Never";
  const seconds = Math.floor((Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function isOnline(lastSeen) {
  if (!lastSeen) return false;
  return Date.now() - new Date(lastSeen).getTime() < 10 * 60 * 1000;
}

export default async function Home() {
  let devices = [];
  let events = [];
  let error = "";

  try {
    [devices, events] = await Promise.all([
      supabaseGet(
        "devices?select=id,device_code,person_name,device_name,computer_name,rustdesk_id,rustdesk_running,protection_status,migration_status,last_seen_at,created_at&order=created_at.desc"
      ),
      supabaseGet(
        "security_events?select=id,device_id,event_type,severity,title,details,created_at&order=created_at.desc&limit=10"
      ),
    ]);
  } catch (err) {
    error = err instanceof Error ? err.message : "Unable to load dashboard.";
  }

  const online = devices.filter((device) => isOnline(device.last_seen_at)).length;
  const protectedCount = devices.filter(
    (device) => device.protection_status === "protected"
  ).length;
  const critical = events.filter((event) => event.severity === "critical").length;

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <div className="eyebrow">WINDOWSPROTECT</div>
          <h1>DeviceHost</h1>
          <p>Family PC protection and remote-support status.</p>
        </div>
        <div className="liveBadge">
          <span className="dot" />
          Live dashboard
        </div>
      </header>

      <section className="stats">
        <article>
          <span>Total devices</span>
          <strong>{devices.length}</strong>
        </article>
        <article>
          <span>Online</span>
          <strong>{online}</strong>
        </article>
        <article>
          <span>Protected</span>
          <strong>{protectedCount}</strong>
        </article>
        <article>
          <span>Critical alerts</span>
          <strong>{critical}</strong>
        </article>
      </section>

      {error ? <div className="errorBox">{error}</div> : null}

      <section className="section">
        <div className="sectionHeading">
          <h2>Devices</h2>
          <span>{devices.length} enrolled</span>
        </div>

        {devices.length === 0 && !error ? (
          <div className="empty">
            <h3>No PCs enrolled yet</h3>
            <p>
              The database and dashboard are working. The WindowsProtect agent
              will register the first PC here.
            </p>
          </div>
        ) : (
          <div className="deviceGrid">
            {devices.map((device) => {
              const onlineNow = isOnline(device.last_seen_at);
              return (
                <article className="deviceCard" key={device.id}>
                  <div className="cardTop">
                    <div>
                      <h3>{device.person_name}</h3>
                      <p>{device.device_name}</p>
                    </div>
                    <span className={onlineNow ? "status online" : "status offline"}>
                      {onlineNow ? "Online" : "Offline"}
                    </span>
                  </div>

                  <dl>
                    <div>
                      <dt>Device ID</dt>
                      <dd>{device.device_code}</dd>
                    </div>
                    <div>
                      <dt>Computer</dt>
                      <dd>{device.computer_name || "—"}</dd>
                    </div>
                    <div>
                      <dt>RustDesk ID</dt>
                      <dd>{device.rustdesk_id || "Not registered"}</dd>
                    </div>
                    <div>
                      <dt>RustDesk</dt>
                      <dd>{device.rustdesk_running ? "Running" : "Not confirmed"}</dd>
                    </div>
                    <div>
                      <dt>Protection</dt>
                      <dd>{device.protection_status}</dd>
                    </div>
                    <div>
                      <dt>Last seen</dt>
                      <dd>{timeAgo(device.last_seen_at)}</dd>
                    </div>
                  </dl>
                </article>
              );
            })}
          </div>
        )}
      </section>

      <section className="section">
        <div className="sectionHeading">
          <h2>Recent security events</h2>
          <span>Latest 10</span>
        </div>

        {events.length === 0 && !error ? (
          <div className="empty compact">
            <p>No security events yet.</p>
          </div>
        ) : (
          <div className="events">
            {events.map((event) => (
              <div className="eventRow" key={event.id}>
                <span className={`severity ${event.severity}`} />
                <div>
                  <strong>{event.title}</strong>
                  <p>{event.event_type}</p>
                </div>
                <time>{timeAgo(event.created_at)}</time>
              </div>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}
