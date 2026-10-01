"use client";
import {useState} from "react";
import {useRouter} from "next/navigation";
export default function UltraViewerControl({deviceId,allowedUntil}){
 const router=useRouter(),[busy,setBusy]=useState(false),[message,setMessage]=useState("");
 const active=Boolean(allowedUntil && Date.parse(allowedUntil)>Date.now());
 async function change(action){
  if(action==="allow" && !window.confirm("Allow UltraViewer on this PC for 30 minutes? It will be blocked again automatically."))return;
  setBusy(true);setMessage("");try{const response=await fetch(`/api/admin/device/${encodeURIComponent(deviceId)}/ultraviewer`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action,minutes:30})});const data=await response.json();if(!response.ok)throw new Error(data.error||"Action failed");setMessage(data.message);router.refresh();}catch(error){setMessage(error.message);}finally{setBusy(false);}
 }
 return <section className="ultraControl"><div><strong>UltraViewer exception</strong><p>{active?`Allowed until ${new Date(allowedUntil).toLocaleString()}. Blocking returns automatically.`:"UltraViewer is blocked while protection is active."}</p></div><button disabled={busy} className={active?"dangerAction":""} onClick={()=>change(active?"block":"allow")}>{busy?"Sending…":active?"End access now":"Allow for 30 minutes"}</button>{message?<span role="status">{message}</span>:null}</section>;
}
