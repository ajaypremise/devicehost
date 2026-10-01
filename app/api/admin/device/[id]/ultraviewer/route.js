import { adminAuthorized } from "../../../../../lib/device-actions.js";
import { sendMeshCentral } from "../../../../../lib/meshcentral.js";
import crypto from "node:crypto";

export const runtime="nodejs";
function headers(prefer="return=representation"){const key=process.env.SUPABASE_SECRET_KEY;if(!key)throw new Error("SUPABASE_SECRET_KEY missing");return{apikey:key,"Content-Type":"application/json",Prefer:prefer};}
function base(){const value=process.env.SUPABASE_URL;if(!value)throw new Error("SUPABASE_URL missing");return value;}
function supported(version){const match=/^(\d+)\.(\d+)\.(\d+)/.exec(String(version||""));if(!match)return false;const parts=match.slice(1).map(Number);return parts[0]>0 || parts[1]>5 || (parts[1]===5 && parts[2]>=11);}
export function ultraViewerServiceCommand(allow,until){
 const expiry=allow && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(until||"")?until:null;if(allow&&!expiry)throw new Error("Invalid allowance expiry");
 const registry=allow?`New-Item -Path 'HKLM:\\SOFTWARE\\WindowsProtect' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\WindowsProtect' -Name UltraViewerAllowedUntilUtc -Value '${expiry}'; `:"Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\WindowsProtect' -Name UltraViewerAllowedUntilUtc -ErrorAction SilentlyContinue; ";
 const change=allow?"& sc.exe config $t.Name start= auto | Out-Null; & sc.exe start $t.Name | Out-Null":"& sc.exe stop $t.Name | Out-Null; & sc.exe config $t.Name start= disabled | Out-Null";
 return `$ErrorActionPreference='Stop'; ${registry}$targets=@(Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'UltraViewer' -or $_.DisplayName -match 'UltraViewer' -or $_.PathName -match 'UltraViewer' }); if($targets.Count -eq 0){throw 'UltraViewer service not found'}; foreach($t in $targets){${change}}; $s=Get-Service DeviceSupportHost -ErrorAction Stop; $s.ExecuteCommand(128); 'OK'`;
}

export async function POST(request,{params}){
 if(!adminAuthorized(request))return Response.json({error:"Unauthorized"},{status:401});
 try{
  const {id}=await params;if(!/^[a-f0-9-]{36}$/i.test(id))return Response.json({error:"Invalid device"},{status:400});
  const found=await fetch(`${base()}/rest/v1/devices?id=eq.${encodeURIComponent(id)}&select=id,agent_version,last_seen_at,protection_status,meshcentral_node_id&limit=1`,{headers:headers(),cache:"no-store"});
  if(!found.ok)throw new Error(await found.text());const device=(await found.json())[0];if(!device)return Response.json({error:"Device not found"},{status:404});
  if(!supported(device.agent_version))return Response.json({error:"Install WindowsProtect 0.5.11 once to enable this control and automatic future updates."},{status:409});
  if(!device.last_seen_at || Date.now()-Date.parse(device.last_seen_at)>120000)return Response.json({error:"This PC must be online. Wait for it to reconnect and try again."},{status:409});
  const body=await request.json().catch(()=>({}));const allow=body.action==="allow";if(!allow && body.action!=="block")return Response.json({error:"Choose allow or block."},{status:400});
  const minutes=allow?Math.min(120,Math.max(5,Math.round(Number(body.minutes)||30))):0;
  const until=allow?new Date(Date.now()+minutes*60000).toISOString():null;
  const saved=await fetch(`${base()}/rest/v1/devices?id=eq.${encodeURIComponent(id)}`,{method:"PATCH",headers:headers(),body:JSON.stringify({temporary_support_enabled:allow,temporary_support_expires_at:until}),cache:"no-store"});
  if(!saved.ok)throw new Error(await saved.text());if(!(await saved.json()).length)return Response.json({error:"Device not found"},{status:404});
  let delivered=false;
  if(device.meshcentral_node_id)try{
   const command=ultraViewerServiceCommand(allow,until);
   await sendMeshCentral({action:"runcommands",nodeids:[device.meshcentral_node_id],type:2,cmds:command,runAsUser:0,reply:true,responseid:`ultraviewer-${crypto.randomBytes(12).toString("hex")}`},{timeoutMs:15000});delivered=true;
  }catch{}
  await fetch(`${base()}/rest/v1/security_events`,{method:"POST",headers:headers("return=minimal"),body:JSON.stringify({device_id:id,event_type:allow?"ultraviewer_allowed":"ultraviewer_blocked",severity:allow?"warning":"info",title:allow?"UltraViewer temporarily allowed":"UltraViewer allowance ended",details:{until}}),cache:"no-store"}).catch(()=>{});
  return Response.json({ok:true,allowed_until:until,message:allow?(delivered?`UltraViewer access is enabled for ${minutes} minutes.`:`Access is saved, but this PC did not confirm that UltraViewer started. Retry once.`):"UltraViewer blocking has been restored."});
 }catch{return Response.json({error:"Unable to change UltraViewer access."},{status:500});}
}
