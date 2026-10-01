import WebSocket from "ws";

const syncCache = globalThis.__windowsProtectMeshSyncCache || new Map();
globalThis.__windowsProtectMeshSyncCache = syncCache;

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

export function sendMeshCentral(command, { timeoutMs = 7000 } = {}) {
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

    const timer = setTimeout(() => finish(new Error("MeshCentral action timed out.")), timeoutMs);

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
          if (data.result && String(data.result).trim().toLowerCase() !== "ok") {
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

function validNodeId(nodeId){return /^node\/[^/]*\/[A-Za-z0-9@$+_=.-]{20,200}$/.test(String(nodeId||""));}

export async function syncMeshCentralDevice({nodeId,name,description="",force=false,send=sendMeshCentral}){
  if(!validNodeId(nodeId))throw new Error("Invalid support device identity.");
  const cleanName=String(name||"").trim().slice(0,120),cleanDescription=String(description||"").trim().slice(0,120);
  if(!cleanName)throw new Error("Device name is required.");
  const signature=`${cleanName}\n${cleanDescription}`,previous=syncCache.get(nodeId);
  if(!force && previous?.signature===signature && Date.now()-previous.at<300000)return false;
  syncCache.set(nodeId,{signature,at:Date.now()});
  try{
    await send({action:"changedevice",nodeid:nodeId,name:cleanName,desc:cleanDescription,responseid:`device-sync-${Date.now()}-${Math.random().toString(16).slice(2)}`},{timeoutMs:10000});
    return true;
  }catch(error){syncCache.delete(nodeId);throw error;}
}

export async function removeMeshCentralDevices(nodeIds,{send=sendMeshCentral}={}){
  const ids=[...new Set((nodeIds||[]).filter(Boolean))];
  if(ids.some(id=>!validNodeId(id)))throw new Error("Invalid support device identity.");
  if(!ids.length)return false;
  await send({action:"removedevices",nodeids:ids,responseid:`device-remove-${Date.now()}-${Math.random().toString(16).slice(2)}`},{timeoutMs:10000});
  for(const id of ids)syncCache.delete(id);
  return true;
}
