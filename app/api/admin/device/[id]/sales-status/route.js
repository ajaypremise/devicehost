import { adminAuthorized } from "../../../../../lib/device-actions.js";

export const runtime = "nodejs";

function headers() {
  const key=process.env.SUPABASE_SECRET_KEY;
  if(!key)throw new Error("SUPABASE_SECRET_KEY missing");
  return {apikey:key,"Content-Type":"application/json",Prefer:"return=minimal"};
}

export async function POST(request,{params}){
  if(!adminAuthorized(request))return Response.json({error:"Unauthorized"},{status:401});
  try{
    const {id}=await params;
    const body=await request.json().catch(()=>({}));
    const status=String(body.status||"");
    if(!/^[0-9a-f-]{36}$/i.test(id)||!["sale","no_sale"].includes(status))return Response.json({error:"Invalid sales status"},{status:400});
    const base=process.env.SUPABASE_URL;
    if(!base)throw new Error("SUPABASE_URL missing");
    const saved=await fetch(`${base}/rest/v1/security_events`,{method:"POST",headers:headers(),body:JSON.stringify({device_id:id,event_type:"sales_status",severity:"info",title:status==="sale"?"Marked as Sale":"Marked as No Sale",details:{status}}),cache:"no-store"});
    if(!saved.ok)return Response.json({error:"Status was not saved",detail:await saved.text()},{status:500});
    return Response.json({ok:true,status});
  }catch(error){return Response.json({error:"Status update failed",detail:String(error)},{status:500});}
}
