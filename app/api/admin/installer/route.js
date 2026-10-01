import {adminAuthorized} from '../../../lib/device-actions.js';
import {fetchInstaller,setupZip} from '../../../lib/setup-package.js';
import {POST as createCode} from '../setup-code/route.js';
import {contactSetupLabel,normalizeEmail,normalizePhone} from '../../../lib/device-contact.js';
import crypto from 'node:crypto';
export const runtime='nodejs';
export const maxDuration=45;
export async function POST(request){
 if(!adminAuthorized(request))return Response.json({error:'Unauthorized'},{status:401});
 try{
  const body=await request.json();
  const owner=String(body.owner || '').trim().slice(0,120),label=String(body.label || '').trim().slice(0,120),agent=["Koko","Ashu"].includes(body.agent)?body.agent:"",email=normalizeEmail(body.email),phone=normalizePhone(body.phone);
  if(!owner || !label || !agent || !email || !phone)return Response.json({error:'Enter the owner, email, phone, device label and support agent.'},{status:400});
  const installer=await fetchInstaller();
  const fingerprint=crypto.createHmac('sha256',process.env.DASHBOARD_PASSWORD).update(`${email}|${phone}`).digest('hex').slice(0,24);
  const result=await createCode(new Request(new URL('/api/admin/setup-code',request.url),{method:'POST',headers:request.headers,body:JSON.stringify({label:contactSetupLabel(fingerprint,email,phone),minutes:30})}));
  const code=await result.json();
  if(!result.ok)throw new Error('Unable to authorize this installer. Try again.');
  const bytes=setupZip(installer,{code:code.code,owner,label,agent,expires_at:new Date(Date.now()+30*60*1000).toISOString()});
  return new Response(bytes,{headers:{'Content-Type':'application/zip','Content-Disposition':'attachment; filename="WindowsProtect_Setup.zip"','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}});
 }catch(error){return Response.json({error:error.message || 'Unable to prepare installer.'},{status:503,headers:{'Cache-Control':'no-store'}});}
}
