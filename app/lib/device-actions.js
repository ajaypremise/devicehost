import crypto from "node:crypto";
import { probeRemoteSupport } from "./mesh-support-check.js";
import { sendMeshCentral } from "./meshcentral.js";

export function parseDeviceAction(body) {
  if (!["activate", "delete", "uninstall"].includes(body?.action)) throw new Error("Choose activate, delete or uninstall.");
  if (!Array.isArray(body.ids) || !body.ids.length || body.ids.length > 100 || body.ids.some(id => typeof id !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(id))) throw new Error("Select 1–100 valid devices.");
  const ids = [...new Set(body.ids)];
  if (["activate", "uninstall"].includes(body.action) && ids.length !== 1) throw new Error("Activate or uninstall one device per request.");
  if (body.action === "delete" && body.confirm !== "delete_records") throw new Error("Confirm deleting dashboard records.");
  if (body.action === "uninstall" && body.confirm !== "uninstall_from_pc") throw new Error("Confirm uninstalling protection and approved support from the selected PCs.");
  return { action: body.action, ids };
}

export function adminAuthorized(request) {
  const user = process.env.DASHBOARD_USER, pass = process.env.DASHBOARD_PASSWORD;
  if (!user || !pass) return false;
  const supplied = request.headers.get("authorization") || "";
  const expected = "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
  const a = Buffer.from(supplied), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return false;
  const origin = request.headers.get("origin");
  return (!origin || origin === new URL(request.url).origin) && request.headers.get("sec-fetch-site") !== "cross-site";
}

export async function activateDevice(device, { probe = probeRemoteSupport, send = sendMeshCentral } = {}) {
  if (String(device.migration_status || "").startsWith("removal_requested:")) throw new Error("Removal is pending for this PC.");
  if (device.protection_status === "protected") return { id: device.id, status: "already_active" };
  if (!/^0\.5\.([7-9]|[1-9][0-9]+)(?:-|$)/.test(device.agent_version || "") || !/^(?:verifying_support|awaiting_activation):/.test(String(device.migration_status || ""))) throw new Error("Update this PC to 0.5.7 and wait for its setup window before activating protection.");
  const age = Date.now() - Date.parse(device.last_seen_at);
  if (!device.meshcentral_node_id || !Number.isFinite(age) || age < -5000 || age > 120000) throw new Error("This PC must be online with a recent support heartbeat.");
  const challenge = crypto.randomBytes(32).toString("hex");
  try { await probe(device.meshcentral_node_id, challenge); } catch { throw new Error("Secure support could not be verified. Activation was not requested."); }
  // The service requires the matching local proof written by the fresh probe.
  const script = "$ErrorActionPreference='Stop'; $d='C:\\ProgramData\\WindowsProtect\\Setup'; " +
    "New-Item -Path 'HKLM:\\SOFTWARE\\WindowsProtect' -Force | Out-Null; " +
    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\WindowsProtect' -Name SupportVerified -Type DWord -Value 1; " +
    `[IO.File]::WriteAllText((Join-Path $d 'activation.request'),'${challenge}',[Text.Encoding]::ASCII); ` +
    "$s=Get-Service DeviceSupportHost; $s.ExecuteCommand(128); 'OK'";
  try { await send({ action: "runcommands", nodeids: [device.meshcentral_node_id], type: 2, cmds: script, runAsUser: 0, reply: true, responseid: `activate-${crypto.randomBytes(12).toString("hex")}` }); } catch { throw new Error("Activation delivery could not be confirmed. Check the PC status before retrying."); }
  return { id: device.id, status: "activation_requested" };
}
