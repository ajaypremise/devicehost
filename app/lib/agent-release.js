export const agentVersion="0.5.12";
export const agentUrl=`https://github.com/ajaypremise/devicehost/releases/download/v${agentVersion}/DeviceSupportHost.exe`;
const manifestUrl=`https://github.com/ajaypremise/devicehost/releases/download/v${agentVersion}/agent-sha256.json`;
export function newer(current,available){const parse=v=>String(v||"").split(".").slice(0,3).map(x=>Number.parseInt(x,10));const a=parse(current),b=parse(available);if(a.some(Number.isNaN)||b.some(Number.isNaN))return false;for(let i=0;i<3;i++){if(b[i]>a[i])return true;if(b[i]<a[i])return false;}return false;}
export async function fetchAgentRelease(){
 const response=await fetch(manifestUrl,{cache:"no-store",signal:AbortSignal.timeout(10000)});if(!response.ok)throw new Error("Agent release is unavailable");const manifest=await response.json();
 if(manifest.version!==agentVersion || !/^[a-f0-9]{64}$/.test(manifest.sha256||""))throw new Error("Agent release manifest is invalid");
 return{version:agentVersion,url:agentUrl,sha256:manifest.sha256};
}
