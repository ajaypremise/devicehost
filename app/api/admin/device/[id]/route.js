export const runtime = "nodejs";

function headers(prefer = "return=representation") {
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!key) throw new Error("SUPABASE_SECRET_KEY missing");
  return { apikey: key, "Content-Type": "application/json", Prefer: prefer };
}

function baseUrl() {
  const base = process.env.SUPABASE_URL;
  if (!base) throw new Error("SUPABASE_URL missing");
  return base;
}

export async function PATCH(request, { params }) {
  try {
    const { id } = await params;
    const body = await request.json().catch(() => ({}));

    const personName = String(body.person_name || "").trim().slice(0, 120);
    const deviceName = String(body.device_name || "").trim().slice(0, 120);

    if (!personName || !deviceName) {
      return Response.json({ error: "Owner and device name are required" }, { status: 400 });
    }

    const response = await fetch(
      `${baseUrl()}/rest/v1/devices?id=eq.${encodeURIComponent(id)}`,
      {
        method: "PATCH",
        headers: headers("return=representation"),
        body: JSON.stringify({
          person_name: personName,
          device_name: deviceName
        }),
        cache: "no-store"
      }
    );

    if (!response.ok) {
      return Response.json({ error: "Update failed", detail: await response.text() }, { status: 500 });
    }

    const rows = await response.json();
    if (!rows.length) return Response.json({ error: "Device not found" }, { status: 404 });

    return Response.json({
      ok: true,
      device: {
        id: rows[0].id,
        person_name: rows[0].person_name,
        device_name: rows[0].device_name
      }
    });
  } catch (error) {
    return Response.json({ error: "Update failed", detail: String(error) }, { status: 500 });
  }
}
