"use client";

import { useState } from "react";

export default function SetupCodePanel() {
  const [label,setLabel]=useState("");
  const [owner,setOwner]=useState("");
  const [code,setCode]=useState("");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");

  async function createCode(e){
    e.preventDefault();
    setBusy(true); setError(""); setCode("");
    try{
      const res=await fetch("/api/admin/setup-code",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({label,minutes:30})
      });
      const data=await res.json();
      if(!res.ok) throw new Error(data.error||"Unable to create setup code");
      setCode(data.code);
    }catch(err){
      setError(err.message||"Unable to create setup code");
    }finally{
      setBusy(false);
    }
  }

  async function download(){
    setBusy(true);setError("");
    try{
      const response=await fetch('/api/admin/installer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({owner,label})});
      if(!response.ok){const data=await response.json();throw new Error(data.error || 'Unable to download installer');}
      const blob=await response.blob();const url=URL.createObjectURL(blob);
      const link=document.createElement('a');link.href=url;link.download='WindowsProtect_Setup.zip';document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
    }catch(error){setError(error.message);}finally{setBusy(false);}
  }

  async function copy(){
    if(code) await navigator.clipboard.writeText(code);
  }

  return (
    <section className="section">
      <div className="sectionHeading"><h2>Add a protected PC</h2><span>Installer download</span></div>
      <div className="setupPanel">
        <div>
          <strong>Download WindowsProtect</strong>
          <p><a href="/download" target="_blank" rel="noreferrer">Open the public download page</a> — customers can enter their own details and download without dashboard access.</p>
          <p>For a new PC, enter its owner and label. The download includes a one-time setup code automatically. Extract both files into the same folder and run WindowsProtect_Setup.exe within 30 minutes.</p>
          <p><a href="https://github.com/ajaypremise/devicehost/releases/download/v0.5.10/WindowsProtect_Setup.exe">Download installer for an existing PC</a> — no new setup code needed for an update.</p>
          <p>The installer is currently unsigned; Windows may show a publisher warning.</p>
        </div>
        <form onSubmit={createCode}>
          <input aria-label="Owner or family member" value={owner} onChange={(e)=>setOwner(e.target.value)} placeholder="Owner / family member" maxLength={120} />
          <input aria-label="Device label" value={label} onChange={(e)=>setLabel(e.target.value)} placeholder="Device label, e.g. Mum laptop" maxLength={120} />
          <button type="button" disabled={busy || !owner.trim() || !label.trim()} onClick={download}>{busy?"Preparing…":"Download for new PC"}</button>
          <button type="submit" disabled={busy}>{busy?"Creating...":"Create 30-min code"}</button>
        </form>
        {code ? <div className="setupCode"><code>{code}</code><button type="button" onClick={copy}>Copy</button></div> : null}
        {error ? <div className="inlineError">{error}</div> : null}
      </div>
    </section>
  );
}
