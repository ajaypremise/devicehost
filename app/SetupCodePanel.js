"use client";

import { useState } from "react";

export default function SetupCodePanel() {
  const [label,setLabel]=useState("");
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

  async function copy(){
    if(code) await navigator.clipboard.writeText(code);
  }

  return (
    <section className="section">
      <div className="sectionHeading"><h2>Add a protected PC</h2><span>One-time setup code</span></div>
      <div className="setupPanel">
        <div>
          <strong>WindowsProtect installer enrollment</strong>
          <p>Create a short-lived code instead of typing the permanent DeviceHost enrollment secret on a family PC.</p>
        </div>
        <form onSubmit={createCode}>
          <input value={label} onChange={(e)=>setLabel(e.target.value)} placeholder="Optional label, e.g. Mum laptop" />
          <button type="submit" disabled={busy}>{busy?"Creating...":"Create 30-min code"}</button>
        </form>
        {code ? <div className="setupCode"><code>{code}</code><button type="button" onClick={copy}>Copy</button></div> : null}
        {error ? <div className="inlineError">{error}</div> : null}
      </div>
    </section>
  );
}
