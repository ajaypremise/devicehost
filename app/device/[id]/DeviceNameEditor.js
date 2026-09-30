"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function DeviceNameEditor({ deviceId, personName, deviceName }) {
  const router = useRouter();
  const [open,setOpen]=useState(false);
  const [owner,setOwner]=useState(personName || "");
  const [label,setLabel]=useState(deviceName || "");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");

  async function save(e){
    e.preventDefault();
    setBusy(true); setError("");
    try{
      const response=await fetch(`/api/admin/device/${encodeURIComponent(deviceId)}`,{
        method:"PATCH",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({person_name:owner,device_name:label})
      });
      const data=await response.json();
      if(!response.ok) throw new Error(data.error||"Update failed");
      setOpen(false);
      router.refresh();
    }catch(err){
      setError(err.message||"Update failed");
    }finally{
      setBusy(false);
    }
  }

  if(!open) return <button className="secondaryAction" onClick={()=>setOpen(true)}>Edit names</button>;

  return (
    <form className="nameEditor" onSubmit={save}>
      <input value={owner} onChange={(e)=>setOwner(e.target.value)} placeholder="Owner / family member" maxLength={120} />
      <input value={label} onChange={(e)=>setLabel(e.target.value)} placeholder="Device label" maxLength={120} />
      <button type="submit" disabled={busy}>{busy?"Saving...":"Save"}</button>
      <button type="button" onClick={()=>{setOpen(false);setError("");}}>Cancel</button>
      {error ? <span>{error}</span> : null}
    </form>
  );
}
