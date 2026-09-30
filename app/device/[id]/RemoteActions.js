"use client";

import { useState } from "react";

export default function RemoteActions({ deviceId, nodeId, connected }) {
  const [mode,setMode]=useState(null);
  const [url,setUrl]=useState("");
  const [title,setTitle]=useState("WindowsProtect");
  const [message,setMessage]=useState("");
  const [size,setSize]=useState("standard");
  const [placement,setPlacement]=useState("center");
  const [busy,setBusy]=useState(false);
  const [result,setResult]=useState("");

  const ready=Boolean(connected && nodeId);

  async function send(payload){
    setBusy(true); setResult("");
    try{
      const response=await fetch(`/api/admin/device/${encodeURIComponent(deviceId)}/remote-action`,{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify(payload)
      });
      const data=await response.json();
      if(!response.ok) throw new Error((data.error || "Action failed") + (data.detail ? ": " + data.detail : ""));
      setResult(data.message || "Sent");
      if(payload.action==="open_url") setUrl("");
      if(payload.action==="message") setMessage("");
    }catch(err){
      setResult(err.message || "Action failed");
    }finally{
      setBusy(false);
    }
  }

  return (
    <section className="remoteActionPanel">
      <div className="remoteActionButtons">
        <button disabled={!ready} onClick={()=>setMode(mode==="message"?null:"message")}>Send message</button>
        <button disabled={!ready} onClick={()=>setMode(mode==="url"?null:"url")}>Open website</button>
      </div>

      {!ready ? <p className="remoteActionHint">Waiting for this PC's MeshCentral Node ID.</p> : null}

      {mode==="message" ? (
        <div className="remoteActionForm">
          <input value={title} onChange={(e)=>setTitle(e.target.value)} placeholder="Title" maxLength={80} />
          <textarea value={message} onChange={(e)=>setMessage(e.target.value)} placeholder="Type the message shown on the PC..." maxLength={1000} />
          <div className="remoteActionOptions">
            <label>Size
              <select value={size} onChange={(e)=>setSize(e.target.value)}>
                <option value="compact">Compact</option>
                <option value="standard">Standard</option>
                <option value="large">Large</option>
              </select>
            </label>
            <label>Placement
              <select value={placement} onChange={(e)=>setPlacement(e.target.value)}>
                <option value="center">Center</option>
                <option value="top_right">Top right</option>
                <option value="bottom_right">Bottom right</option>
              </select>
            </label>
          </div>
          <div className="remoteActionRow">
            <span className="remoteActionHint">Shown in the active Windows session.</span>
            <button disabled={busy || !message.trim()} onClick={()=>send({action:"message",title,message,size,placement})}>{busy?"Sending...":"Send to PC"}</button>
          </div>
        </div>
      ) : null}

      {mode==="url" ? (
        <div className="remoteActionForm">
          <input value={url} onChange={(e)=>setUrl(e.target.value)} placeholder="https://example.com" />
          <button disabled={busy || !url.trim()} onClick={()=>send({action:"open_url",url})}>{busy?"Opening...":"Open on PC"}</button>
        </div>
      ) : null}

      {result ? <div className="remoteActionResult">{result}</div> : null}
    </section>
  );
}
