export const remoteAccessAlertTypes = new Set(["remote_access_blocked", "remote_tool_blocked"]);

export function isRemoteAccessAlert(event) {
  return Boolean(event && remoteAccessAlertTypes.has(String(event.event_type || "")));
}

export function recentRemoteAccessAlerts(events, now = Date.now(), hours = 24) {
  const cutoff = now - hours * 60 * 60 * 1000;
  return (Array.isArray(events) ? events : [])
    .filter((event) => isRemoteAccessAlert(event) && event.severity === "critical" && Date.parse(event.created_at) >= cutoff)
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
}

export function remoteAccessTool(event) {
  const value = event?.details?.tool || event?.details?.application || event?.details?.message || "Unauthorized remote-access tool";
  return String(value).replace(/^Application:\s*/i, "").slice(0, 160);
}
