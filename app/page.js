import Link from "next/link";
import SetupCodePanel from "./SetupCodePanel";
import DeviceTable from "./DeviceTable";
import { recentRemoteAccessAlerts, remoteAccessTool } from "./lib/security-alerts.js";
import { deviceOnline, remoteSupportConnected } from "./lib/device-presence.js";

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
  return deviceOnline(lastSeen);
}

function remoteSupportOn(device) {
  return remoteSupportConnected(device);
}

function postureLabel(value) {
  return value && value !== "unknown" ? value : "Awaiting telemetry";
}

function attentionRank(device) {
  if (device.recent_remote_alert) return 5;
  if (device.security_posture === "critical") return 4;
  if (Array.isArray(device.remote_tools_detected) && device.remote_tools_detected.length > 0) return 3;
  if (device.security_posture === "warning") return 2;
  if (!isOnline(device.last_seen_at)) return 1;
  return 0;
}

export default async function Home({ searchParams }) {
  const params = (await searchParams) || {};
  const q = String(params.q || "").trim();
  const status = ["online","offline"].includes(String(params.status)) ? String(params.status) : "all";
  const posture = ["healthy","attention"].includes(String(params.posture)) ? String(params.posture) : "all";
  const remote = ["on","off"].includes(String(params.remote)) ? String(params.remote) : "all";
  const sales = ["sale","no_sale"].includes(String(params.sales)) ? String(params.sales) : "all";
  const sort = ["owner","computer","last_seen","attention"].includes(String(params.sort)) ? String(params.sort) : "attention";
  const size = [20,50,100].includes(Number(params.size)) ? Number(params.size) : 20;
  const requestedPage = Number.parseInt(String(params.page || "1"), 10) || 1;

  let devices = [];
  let events = [];
  let remoteAlerts = [];
  let error = "";

  try {
    let assignments=[],contacts=[],salesEvents=[],criticalEvents=[];
    [devices, events, assignments, contacts, salesEvents, criticalEvents] = await Promise.all([
      supabaseGet("devices?select=*&order=created_at.desc"),
      supabaseGet("security_events?select=id,device_id,event_type,severity,title,details,created_at&order=created_at.desc&limit=12"),
      supabaseGet("security_events?event_type=eq.agent_assignment&select=device_id,details,created_at&order=created_at.desc&limit=10000"),
      supabaseGet("security_events?event_type=eq.device_contact&select=device_id,details,created_at&order=created_at.desc&limit=10000"),
      supabaseGet("security_events?event_type=eq.sales_status&select=device_id,details,created_at&order=created_at.desc&limit=10000"),
      supabaseGet("security_events?event_type=in.(remote_access_blocked,remote_tool_blocked)&select=id,device_id,event_type,severity,title,details,created_at&order=created_at.desc&limit=100"),
    ]);
    const assigned=new Map();
    for(const event of assignments) if(!assigned.has(event.device_id) && ["Koko","Ashu"].includes(event.details?.agent)) assigned.set(event.device_id,event.details.agent);
    const contactByDevice=new Map();
    for(const event of contacts)if(!contactByDevice.has(event.device_id))contactByDevice.set(event.device_id,event.details||{});
    const salesByDevice=new Map();
    for(const event of salesEvents)if(!salesByDevice.has(event.device_id) && ["sale","no_sale"].includes(event.details?.status))salesByDevice.set(event.device_id,event.details.status);
    remoteAlerts=recentRemoteAccessAlerts(criticalEvents);
    const alertByDevice=new Map();
    for(const alert of remoteAlerts)if(!alertByDevice.has(alert.device_id))alertByDevice.set(alert.device_id,alert);
    devices=devices.map(device=>({...device,assigned_agent:assigned.get(device.id) || null,customer_email:contactByDevice.get(device.id)?.email||null,customer_phone:contactByDevice.get(device.id)?.phone||null,sales_status:salesByDevice.get(device.id)||"no_sale",recent_remote_alert:alertByDevice.get(device.id)||null}));
  } catch (err) {
    error = err instanceof Error ? err.message : "Unable to load dashboard.";
  }

  const online = devices.filter((d) => isOnline(d.last_seen_at)).length;
  const protectedCount = devices.filter((d) => d.protection_status === "protected").length;
  const remoteConnected = devices.filter((d) => remoteSupportOn(d)).length;
  const attention = devices.filter((d) => attentionRank(d) >= 2).length;

  const needle = q.toLowerCase();
  let filtered = devices.filter((d) => {
    const matchesSearch = !needle || [d.person_name, d.customer_email, d.customer_phone, d.device_name, d.computer_name, d.device_code, d.os_version, d.assigned_agent]
      .some((v) => String(v || "").toLowerCase().includes(needle));
    const onlineNow = isOnline(d.last_seen_at);
    const remoteOn = remoteSupportOn(d);
    const matchesStatus = status === "all" || (status === "online" ? onlineNow : !onlineNow);
    const matchesPosture = posture === "all" ||
      (posture === "healthy" ? d.security_posture === "healthy" : attentionRank(d) >= 2);
    const matchesRemote = remote === "all" || (remote === "on" ? remoteOn : !remoteOn);
    const matchesSales = sales === "all" || d.sales_status === sales;
    return matchesSearch && matchesStatus && matchesPosture && matchesRemote && matchesSales;
  });

  filtered = [...filtered].sort((a,b) => {
    if (sort === "owner") return String(a.person_name || "").localeCompare(String(b.person_name || ""));
    if (sort === "computer") return String(a.computer_name || "").localeCompare(String(b.computer_name || ""));
    if (sort === "last_seen") return new Date(b.last_seen_at || 0).getTime() - new Date(a.last_seen_at || 0).getTime();
    return attentionRank(b) - attentionRank(a) || String(a.person_name || "").localeCompare(String(b.person_name || ""));
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / size));
  const currentPage = Math.min(Math.max(1, requestedPage), totalPages);
  const start = (currentPage - 1) * size;
  const pageDevices = filtered.slice(start, start + size);

  function hrefWith(overrides = {}) {
    const values = { q, status, posture, remote, sales, sort, size, page: currentPage, ...overrides };
    const query = new URLSearchParams();
    if (values.q) query.set("q", values.q);
    for (const key of ["status","posture","remote","sales","sort"]) if (values[key] && values[key] !== "all") query.set(key, String(values[key]));
    if (values.size !== 20) query.set("size", String(values.size));
    if (values.page !== 1) query.set("page", String(values.page));
    const qs = query.toString();
    return qs ? `/?${qs}` : "/";
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
        <article><span>Remote connected</span><strong>{remoteConnected}</strong></article>
        <article><span>Needs attention</span><strong>{attention}</strong></article>
      </section>

      {error ? <div className="errorBox">{error}</div> : null}

      {remoteAlerts.length ? (
        <section className="securityAlert" role="alert" aria-live="assertive">
          <div className="securityAlertIcon">!</div>
          <div>
            <strong>{remoteAlerts.length} unauthorized remote-access attempt{remoteAlerts.length === 1 ? "" : "s"} blocked in the last 24 hours</strong>
            <p>{devices.find(device => device.id === remoteAlerts[0].device_id)?.person_name || "Device"} · {remoteAccessTool(remoteAlerts[0])} · {timeAgo(remoteAlerts[0].created_at)}</p>
          </div>
          <Link href={`/device/${remoteAlerts[0].device_id}`}>Review latest</Link>
        </section>
      ) : null}

      <section className="section">
        <div className="sectionHeading deviceHeading">
          <div>
            <h2>Devices</h2>
            <span>{filtered.length} shown · {devices.length} enrolled · {protectedCount} protected</span>
          </div>
        </div>

        <form className="filterBar" method="get">
          <input name="q" defaultValue={q} placeholder="Search name, email, phone, PC or Device ID" />
          <select name="status" defaultValue={status}>
            <option value="all">All status</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
          </select>
          <select name="posture" defaultValue={posture}>
            <option value="all">All security</option>
            <option value="healthy">Healthy</option>
            <option value="attention">Needs attention</option>
          </select>
          <select name="remote" defaultValue={remote}>
            <option value="all">All remote support</option>
            <option value="on">Remote On</option>
            <option value="off">Remote Off</option>
          </select>
          <select name="sales" defaultValue={sales}>
            <option value="all">All sales</option>
            <option value="sale">Sale</option>
            <option value="no_sale">No Sale</option>
          </select>
          <select name="sort" defaultValue={sort}>
            <option value="attention">Sort: attention first</option>
            <option value="last_seen">Sort: last seen</option>
            <option value="owner">Sort: owner A-Z</option>
            <option value="computer">Sort: computer A-Z</option>
          </select>
          <select name="size" defaultValue={String(size)}>
            <option value="20">20 / page</option>
            <option value="50">50 / page</option>
            <option value="100">100 / page</option>
          </select>
          <button type="submit">Apply</button>
          {(q || status !== "all" || posture !== "all" || remote !== "all" || sales !== "all" || sort !== "attention" || size !== 20) ? <Link href="/" className="clearSearch">Reset</Link> : null}
        </form>

        {filtered.length === 0 && !error ? (
          <div className="empty">
            <h3>No matching devices</h3>
            <p>Change or reset the search and filters.</p>
          </div>
        ) : (
          <>
            <DeviceTable devices={pageDevices.map(d => ({id:d.id ?? null,person_name:d.person_name ?? null,customer_email:d.customer_email ?? null,customer_phone:d.customer_phone ?? null,device_name:d.device_name ?? null,device_code:d.device_code ?? null,computer_name:d.computer_name ?? null,assigned_agent:d.assigned_agent ?? null,sales_status:d.sales_status ?? "no_sale",last_seen_at:d.last_seen_at ?? null,security_posture:d.security_posture ?? null,recent_remote_alert:d.recent_remote_alert ?? null,remote_access_provider:d.remote_access_provider ?? null,meshcentral_connected:d.meshcentral_connected ?? null,rustdesk_service_running:d.rustdesk_service_running ?? null,protection_status:d.protection_status ?? null,migration_status:d.migration_status ?? null,agent_version:d.agent_version ?? null}))} />

            <div className="tableFooter">
              <span>Showing {filtered.length ? start + 1 : 0}-{Math.min(start + size, filtered.length)} of {filtered.length}</span>
              {totalPages > 1 ? (
                <nav className="pagination" aria-label="Device pages">
                  <Link className={currentPage === 1 ? "disabled" : ""} href={hrefWith({page:Math.max(1,currentPage-1)})}>Previous</Link>
                  <span>Page {currentPage} of {totalPages}</span>
                  <Link className={currentPage === totalPages ? "disabled" : ""} href={hrefWith({page:Math.min(totalPages,currentPage+1)})}>Next</Link>
                </nav>
              ) : null}
            </div>
          </>
        )}
      </section>

      <SetupCodePanel />

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
          <strong>Remote support stays in MeshCentral</strong>
          <p>DeviceHost is the monitoring and security dashboard. Remote desktop, chat, user messages, opening a webpage and temporary support links are handled by the separately authenticated MeshCentral control plane.</p>
        </div>
      </section>
    </main>
  );
}
