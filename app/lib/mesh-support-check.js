import crypto from "node:crypto";
import WebSocket from "ws";

// Follow MeshCentral's authcookie + tunnel + relay protocol. A running agent or
// a relay pairing ('c') is insufficient: require desktop size AND an image tile.
export function probeRemoteSupport(nodeId, challenge, {
  controlUrl = process.env.MESHCENTRAL_WS_URL,
  user = process.env.MESHCENTRAL_LOGIN_USER,
  pass = process.env.MESHCENTRAL_LOGIN_PASS,
  Socket = WebSocket,
  timeoutMs = 24000,
} = {}) {
  if (!controlUrl || !user || !pass) return Promise.reject(new Error("support_not_configured"));
  const controlAddress = new URL(controlUrl);
  if (controlAddress.protocol !== "wss:" || !controlAddress.pathname.endsWith("/control.ashx")) return Promise.reject(new Error("support_not_configured"));
  if (!/^node\/[^/]*\/[A-Za-z0-9@$+_=.-]{20,200}$/.test(nodeId) || !/^[a-f0-9]{64}$/.test(challenge)) return Promise.reject(new Error("invalid_support_identity"));

  return new Promise((resolve, reject) => {
    let control, relay, done = false, paired = false, screen = false, commandSent = false;
    let accumulator = Buffer.alloc(0);
    const responseid = `setup-check-${crypto.randomBytes(12).toString("hex")}`;
    const finish = (error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      // Discard screen data; never store screenshots, cookies, or passwords.
      accumulator = Buffer.alloc(0);
      for (const socket of [relay, control]) {
        try {
          if (socket?.readyState === WebSocket.OPEN) socket.close();
          else socket?.terminate();
        } catch {}
      }
      if (error) reject(new Error(error));
      else resolve({ desktop_verified: true, command_dispatched: true });
    };
    const timer = setTimeout(() => finish("support_verification_timeout"), timeoutMs);
    const sendCommand = () => {
      if (commandSent || done) return;
      commandSent = true;
      // Only a fixed, harmless challenge file. No caller-supplied executable,
      // path, shell text or credentials. Installer must read this fresh proof.
      const script = "$ErrorActionPreference='Stop'; $d='C:\\ProgramData\\WindowsProtect\\Setup'; " +
        "New-Item -ItemType Directory -Path $d -Force | Out-Null; " +
        `[IO.File]::WriteAllText((Join-Path $d 'support-${challenge}.txt'),'${challenge}',[Text.Encoding]::ASCII); '${challenge}'`;
      control.send(JSON.stringify({ action: "runcommands", nodeids: [nodeId], type: 2, cmds: script, runAsUser: 0, reply: true, responseid }));
    };
    const processDesktop = (raw) => {
      accumulator = Buffer.concat([accumulator, raw]);
      if (accumulator.length > 4 * 1024 * 1024) return finish("invalid_desktop_stream");
      while (accumulator.length >= 4 && !done && !commandSent) {
        let offset = 0, size = accumulator.readUInt16BE(2), command = accumulator.readUInt16BE(0);
        if (command === 27 && size === 8) {
          if (accumulator.length < 12) return;
          size = accumulator.readUInt32BE(4);
          offset = 8;
          command = accumulator.readUInt16BE(8);
        }
        if (size < 4 || size > 4 * 1024 * 1024) return finish("invalid_desktop_stream");
        if (accumulator.length < offset + size) return;
        const packet = accumulator.subarray(offset, offset + size);
        if (command === 7 && packet.length >= 8) {
          screen = packet.readUInt16BE(4) > 0 && packet.readUInt16BE(6) > 0;
          relay.send(Buffer.from([0, 8, 0, 5, 0])); // unpause
          relay.send(Buffer.from([0, 6, 0, 4])); // refresh
        }
        // Request JPEG. The tile has a 4-byte header, X/Y, then image bytes.
        if (screen && command === 3 && packet.length > 11 && packet[8] === 0xff && packet[9] === 0xd8 && packet[10] === 0xff) {
          accumulator = Buffer.alloc(0);
          sendCommand();
          return;
        }
        accumulator = accumulator.subarray(offset + size);
        // Native desktop packets can be padded to an 8-byte boundary.
        if (accumulator.length < 8 && accumulator.every((byte) => byte === 0)) accumulator = Buffer.alloc(0);
      }
    };
    try {
      control = new Socket(controlAddress, {
        rejectUnauthorized: true, maxPayload: 1024 * 1024,
        headers: { "x-meshauth": `${Buffer.from(user).toString("base64")},${Buffer.from(pass).toString("base64")}` },
      });
      control.on("open", () => control.send(JSON.stringify({ action: "authcookie" })));
      control.on("error", () => finish("support_server_unavailable"));
      control.on("close", () => finish("support_server_disconnected"));
      control.on("message", (raw) => {
        if (done) return;
        let data;
        try { data = JSON.parse(String(raw)); } catch { return; }
        if (data.responseid === responseid && commandSent) {
          if (String(data.result || "").trim().toLowerCase() === "ok" || String(data.result || "").trim() === challenge) finish();
          else if (data.result && data.type !== "runcommands") finish("support_command_rejected");
        }
        if (data.action !== "authcookie" || relay) return;
        if (!data.cookie || !data.rcookie) return finish("support_authentication_failed");
        const id = crypto.randomBytes(16).toString("hex");
        const relayAddress = new URL(controlAddress);
        relayAddress.pathname = relayAddress.pathname.replace(/control\.ashx$/, "meshrelay.ashx");
        relayAddress.search = "";
        relayAddress.searchParams.set("browser", "1");
        relayAddress.searchParams.set("p", "2");
        relayAddress.searchParams.set("nodeid", nodeId);
        relayAddress.searchParams.set("id", id);
        relayAddress.searchParams.set("auth", data.cookie);
        const agentAddress = new URL(relayAddress);
        agentAddress.searchParams.delete("browser"); agentAddress.searchParams.delete("auth");
        agentAddress.searchParams.set("rauth", data.rcookie);
        control.send(JSON.stringify({ action: "msg", type: "tunnel", nodeid: nodeId, usage: 2, value: "*" + agentAddress.pathname + agentAddress.search }));
        relay = new Socket(relayAddress, { rejectUnauthorized: true, maxPayload: 4 * 1024 * 1024 });
        relay.on("error", () => finish("support_desktop_unavailable"));
        relay.on("close", () => { if (!commandSent) finish("support_desktop_disconnected"); });
        relay.on("message", (raw, binary) => {
          if (done || commandSent) return;
          if (!paired) {
            if (!["c", "cr"].includes(String(raw))) return;
            paired = true;
            relay.send("2"); // desktop
            relay.send(Buffer.from([0, 5, 0, 10, 1, 30, 4, 0, 0, 100])); // JPEG, low quality, full scale
            relay.send(Buffer.from([0, 8, 0, 5, 0]));
            relay.send(Buffer.from([0, 6, 0, 4]));
          } else if (binary) processDesktop(Buffer.from(raw));
          else {
            try {
              const message = JSON.parse(String(raw));
              if (message.ctrlChannel == "102938" && message.type === "ping") relay.send(JSON.stringify({ ctrlChannel: "102938", type: "pong" }));
            } catch {}
          }
        });
      });
    } catch { finish("support_server_unavailable"); }
  });
}
