import { readDownloadToken, safeFilename } from "../../../../lib/download-links.js";
import { fetchInstaller, setupZip } from "../../../../lib/setup-package.js";
import { issueSetupCode, recentPublicRequests } from "../../../../lib/setup-codes.js";

export const runtime = "nodejs";
export const maxDuration = 45;

function error(message, status) {
  return Response.json({ error: message }, { status, headers: { "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer" } });
}

export async function GET(request, context) {
  try {
    const { token } = await context.params;
    let details;
    try { details = readDownloadToken(token); }
    catch (problem) { return error(String(problem.message).includes("Expired") ? "This download link has expired. Create a fresh link." : "This download link is invalid.", 410); }

    if (await recentPublicRequests(details.fingerprint) >= 3) return error("This link has already prepared several downloads recently. Try again later or create a fresh link.", 429);
    const installer = await fetchInstaller();
    const code = await issueSetupCode(`public:${details.fingerprint}:${details.label}`.slice(0, 120), 240);
    const codeExpiresAt = new Date(Date.now() + 240 * 60000).toISOString();
    const bytes = setupZip(installer, { code, owner: details.owner, label: details.label, agent: details.agent, expires_at: codeExpiresAt });
    return new Response(bytes, { headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="${safeFilename(details.label)}"`,
      "Cache-Control": "private, no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff"
    }});
  } catch {
    return error("The download could not be prepared. Please wait a moment and try again.", 503);
  }
}
