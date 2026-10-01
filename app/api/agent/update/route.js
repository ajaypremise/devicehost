import crypto from "node:crypto";
import {agentVersion,fetchAgentRelease,newer} from "../../../lib/agent-release.js";
export const runtime="nodejs";
function headers(){const key=process.env.SUPABASE_SECRET_KEY;if(!key)throw new Error("SUPABASE_SECRET_KEY missing");return{apikey:key,Accept:"application/json"};}
export async function GET(request){
 try{
  const token=request.headers.get("x-device-token");if(!token)return Response.json({error:"Unauthorized"},{status:401});
  const base=process.env.SUPABASE_URL;if(!base)throw new Error("SUPABASE_URL missing");const hash=crypto.createHash("sha256").update(token).digest("hex");
  const auth=await fetch(`${base}/rest/v1/devices?agent_token_hash=eq.${encodeURIComponent(hash)}&select=id&limit=1`,{headers:headers(),cache:"no-store"});if(!auth.ok)throw new Error("Device lookup failed");if(!(await auth.json()).length)return Response.json({error:"Unauthorized"},{status:401});
  const current=new URL(request.url).searchParams.get("version")||"0.0.0";if(!newer(current,agentVersion))return Response.json({update:false,version:agentVersion},{headers:{"Cache-Control":"private, no-store"}});
  return Response.json({update:true,...await fetchAgentRelease()},{headers:{"Cache-Control":"private, no-store"}});
 }catch{return Response.json({error:"Update check unavailable"},{status:503,headers:{"Cache-Control":"no-store"}});}
}
