import { adminAuthorized } from "../../../lib/device-actions.js";
import { issueSetupCode } from "../../../lib/setup-codes.js";

export const runtime = "nodejs";

export async function POST(request) {
  if(!adminAuthorized(request))return Response.json({error:"Unauthorized"},{status:401});
  try {
    const body = await request.json().catch(() => ({}));
    const label = String(body.label || "").trim().slice(0, 120) || null;
    const minutesRaw = Number(body.minutes || 30);
    const minutes = Number.isFinite(minutesRaw) ? Math.min(120, Math.max(5, Math.round(minutesRaw))) : 30;

    const code = await issueSetupCode(label, minutes);
    return Response.json({ ok: true, code, expires_in_minutes: minutes });
  } catch (error) {
    return Response.json({ error: "Unable to create setup code", detail: String(error) }, { status: 500 });
  }
}
