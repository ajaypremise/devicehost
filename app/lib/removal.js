export function removalId(value) {
  return /^removal_requested:([a-f0-9]{64})(?::[a-z_]+)?$/.exec(String(value || ""))?.[1] || "";
}
export function canUninstall(version) {
  const m=/^(\d+)\.(\d+)\.(\d+)(?:-|$)/.exec(String(version || ""));
  return Boolean(m) && (Number(m[1])>0 || Number(m[2])>5 || (Number(m[2])===5 && Number(m[3])>=8));
}
export const removalReasons = new Set(["waiting_for_user", "cleanup_failed", "support_removal_failed"]);
