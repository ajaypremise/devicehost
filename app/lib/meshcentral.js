import WebSocket from "ws";

function b64(value) {
  return Buffer.from(String(value || "")).toString("base64");
}

export function meshcentralConfigured() {
  return Boolean(
    process.env.MESHCENTRAL_WS_URL &&
    process.env.MESHCENTRAL_LOGIN_USER &&
    process.env.MESHCENTRAL_LOGIN_PASS
  );
}

export function sendMeshCentral(command) {
  return new Promise((resolve, reject) => {
    const url = process.env.MESHCENTRAL_WS_URL;
    const user = process.env.MESHCENTRAL_LOGIN_USER;
    const pass = process.env.MESHCENTRAL_LOGIN_PASS;

    if (!url || !user || !pass) {
      reject(new Error("MeshCentral dashboard actions are not configured."));
      return;
    }

    const ws = new WebSocket(url, {
      rejectUnauthorized: true,
      headers: {
        "x-meshauth": `${b64(user)},${b64(pass)}`
      }
    });

    let settled = false;
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { ws.close(); } catch {}
      if (err) reject(err); else resolve(value);
    };

    const timer = setTimeout(() => finish(new Error("MeshCentral action timed out.")), 7000);

    ws.on("open", () => {
      try {
        ws.send(JSON.stringify(command));
      } catch (error) {
        finish(error);
      }
    });

    ws.on("message", (raw) => {
      try {
        const data = JSON.parse(String(raw));
        if (data.responseid === command.responseid) {
          if (data.result && String(data.result).toLowerCase() !== "ok") {
            finish(new Error(String(data.result)));
          } else {
            finish(null, data);
          }
        }
      } catch {}
    });

    ws.on("error", (error) => finish(error));
    ws.on("close", (code, reason) => {
      if (!settled) {
        const why = String(reason || "").trim();
        finish(new Error("MeshCentral closed the connection before confirming the action" + (why ? ": " + why : "") + " (code " + code + ")."));
      }
    });
  });
}
