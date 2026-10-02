"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export function activationLabel(device, now) {
  if(String(device.migration_status || "").startsWith("removal_requested:")) {
    return String(device.migration_status).endsWith(":waiting_for_user")?"Removal pending · installing user must sign in":"Removal pending · awaiting PC confirmation";
  }
  if(device.protection_status === "protected") return "Protected";
  const value=String(device.migration_status || "");
  const index=value.indexOf(":");
  const deadline=index<0?NaN:Date.parse(value.slice(index+1));
  if(!Number.isFinite(deadline)) return "Pending";
  const left=Math.max(0,Math.ceil((deadline-now)/60000));
  if(left===0) return "Activation due · awaiting PC confirmation";
  const duration=`${Math.floor(left/60)}h ${left%60}m`;
  return `${value.startsWith("awaiting_activation:")?"Setup window":"Verifying support"} · ${duration} left`;
}

export default function DeviceTable({devices}) {
  const router=useRouter();
  const [selected,setSelected]=useState([]), [busy,setBusy]=useState(false), [results,setResults]=useState([]), [now,setNow]=useState(null);
  const [salesBusy,setSalesBusy]=useState({}), [salesError,setSalesError]=useState("");
  useEffect(()=>{setNow(Date.now());const timer=setInterval(()=>{setNow(Date.now());if(!busy) router.refresh();},30000);return()=>clearInterval(timer);},[router,busy]);
  const visibleSelected=selected.filter(id=>devices.some(d=>d.id===id));
  const all=devices.length>0 && visibleSelected.length===devices.length;
  function toggle(id){setSelected(previous=>previous.includes(id)?previous.filter(x=>x!==id):[...previous,id]);}
  async function setSalesStatus(device,status){
    if(salesBusy[device.id] || !["sale","no_sale"].includes(status)) return;
    setSalesError("");setSalesBusy(previous=>({...previous,[device.id]:true}));
    try{
      const response=await fetch(`/api/admin/device/${device.id}/sales-status`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({status})});
      const body=await response.json();
      if(!response.ok)throw new Error(body.error||"Status update failed");
      router.refresh();
    }catch(error){setSalesError(`${device.person_name||"Device"}: ${error.message}`);}
    finally{setSalesBusy(previous=>({...previous,[device.id]:false}));}
  }
  async function action(type) {
    const ids=[...visibleSelected];
    if(!ids.length || busy) return;
    const text=type==="uninstall"?`Uninstall WindowsProtect AND approved remote support from ${ids.length} PC(s), then delete them from both dashboards? This ends scam protection and approved remote access. Offline PCs will stay pending until they reconnect. This cannot be undone.`:type==="delete"?`Delete ${ids.length} device(s) from both dashboards? This removes monitoring and approved remote access, but does not uninstall WindowsProtect or disable protection on the PC. Use this only for stale records. This cannot be undone.`:`Activate protection on ${ids.length} PC(s)? After secure support is verified, UltraViewer and other blocked remote tools will disconnect. Protection cannot be switched off here.`;
    if(!window.confirm(text)) return;
    setBusy(true);setResults([]);
    async function submit(batch) {
      try {
        const response=await fetch("/api/admin/devices/action",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:type,ids:batch,confirm:type==="delete"?"delete_records":type==="uninstall"?"uninstall_from_pc":undefined})});
        const body=await response.json();
        if(!response.ok) throw new Error(body.error || "Action failed");
        return body.results;
      }catch(error){return batch.map(id=>({id,status:"failed",error:error.message}));}
    }
    let outcome=[];
    if(type==="delete") outcome=await submit(ids);
    else if(type==="uninstall"){ for(const id of ids){ outcome.push(...await submit([id])); setResults([...outcome]); } }
    else {
      // Keep each support probe within its own request budget, even for 100 PCs.
      for(let i=0;i<ids.length;i+=3){
        const batch=await Promise.all(ids.slice(i,i+3).map(id=>submit([id])));
        outcome.push(...batch.flat());setResults([...outcome]);
      }
    }
    setResults(outcome);setSelected(outcome.filter(r=>r.status==="failed").map(r=>r.id));setBusy(false);router.refresh();
  }
  return <>
    <div className="bulkActions">
      <strong>{visibleSelected.length} selected</strong>
      <button className="secondaryAction" disabled={busy || !visibleSelected.length} onClick={()=>action("activate")}>{busy?"Working…":"Activate protection"}</button>
      <button className="secondaryAction dangerAction" disabled={busy || !visibleSelected.length} onClick={()=>action("delete")}>Delete stale records</button>
      <button className="secondaryAction dangerAction" disabled={busy || !visibleSelected.length} onClick={()=>action("uninstall")}>Uninstall from PC and delete</button>
      <span>Select individual PCs or all {devices.length} on this page. Setup windows last a maximum of four hours.</span>
    </div>
    {results.length>0 && <div className="bulkResults" role="status">{results.map(result=><div key={result.id}><strong>{devices.find(d=>d.id===result.id)?.person_name || "Device"}</strong>: {result.error || ({deleted:"Record deleted",removal_pending:"Removal pending — record stays until this PC confirms uninstall",activation_requested:"Activation requested — waiting for PC confirmation",already_active:"Protection already active"}[result.status])}</div>)}</div>}
    {salesError && <div className="errorBox compact" role="alert">{salesError}</div>}
    <div className="deviceTableWrap"><table className="deviceTable"><thead><tr>
      <th><input type="checkbox" aria-label="Select all devices on this page" checked={all} disabled={busy} onChange={()=>setSelected(all?[]:devices.map(d=>d.id))}/></th>
      <th>Owner / device</th><th>Contact</th><th>Agent</th><th>Sales</th><th>Computer</th><th>Status</th><th>Security</th><th>Remote</th><th>Protection</th><th>Last seen</th><th></th>
    </tr></thead><tbody>{devices.map(device=>{
      const online=device.last_seen_at && (now || Date.now())-Date.parse(device.last_seen_at)<600000;
      const remote=device.remote_access_provider==="meshcentral"?device.meshcentral_connected:device.rustdesk_service_running;
      return <tr key={device.id}>
        <td><input type="checkbox" aria-label={`Select ${device.person_name || device.device_name || device.device_code}`} checked={visibleSelected.includes(device.id)} disabled={busy} onChange={()=>toggle(device.id)}/></td>
        <td><Link className="devicePrimary" href={`/device/${device.id}`}><strong>{device.person_name || "Unnamed"}</strong><span>{device.device_name || "Unnamed device"} · {device.device_code}</span></Link></td>
        <td><span className="contactCell"><strong>{device.customer_email || "Not provided"}</strong><small>{device.customer_phone || "—"}</small></span></td>
        <td>{device.assigned_agent || "Unassigned"}</td>
        <td><select className={`salesStatus ${device.sales_status==="sale"?"isSale":"isNoSale"}`} value={device.sales_status||"no_sale"} disabled={Boolean(salesBusy[device.id])} onChange={event=>setSalesStatus(device,event.target.value)} aria-label={`Sales status for ${device.person_name||device.device_name||"device"}`}>
          <option value="no_sale">No Sale</option><option value="sale">Sale</option>
        </select></td>
        <td>{device.computer_name || "Pending"}</td><td><span className={online?"status online":"status offline"}>{online?"Online":"Offline"}</span></td>
        <td>{device.recent_remote_alert?<span className="health bad">Remote access blocked</span>:(device.security_posture && device.security_posture!=="unknown"?device.security_posture:"Awaiting telemetry")}</td>
        <td><span className={remote?"health good":"health bad"}>{remote?"On":"Off"}</span></td>
        <td className="activationCell">{now?activationLabel(device,now):(device.protection_status==="protected"?"Protected":"Pending")}<small>{device.agent_version || "Version pending"}</small></td>
        <td>{device.last_seen_at?new Date(device.last_seen_at).toISOString().replace("T"," ").slice(0,16)+" UTC":"Never"}</td>
        <td><Link className="openDevice" href={`/device/${device.id}`}>Open</Link></td>
      </tr>;
    })}</tbody></table></div>
  </>;
}
