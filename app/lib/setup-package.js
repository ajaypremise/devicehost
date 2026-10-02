import crypto from 'node:crypto';
export const installerVersion='0.5.18';
export const installerUrl=`https://github.com/ajaypremise/devicehost/releases/download/v${installerVersion}/WindowsProtect_Setup.exe`;
const checksumUrl=`https://github.com/ajaypremise/devicehost/releases/download/v${installerVersion}/installer-sha256.json`;
export async function fetchInstaller(){
  const options={cache:'no-store',signal:AbortSignal.timeout(15000)};
  const responses=await Promise.all([fetch(installerUrl,options),fetch(checksumUrl,options)]);
  if(responses.some(r=>!r.ok))throw new Error('Installer download is not available yet. Try again shortly.');
  const manifest=await responses[1].json();
  if(manifest.version!==installerVersion || !/^[a-f0-9]{64}$/.test(manifest.sha256 || ''))throw new Error('Installer checksum is unavailable.');
  const bytes=Buffer.from(await responses[0].arrayBuffer());
  if(bytes.length>10*1024*1024 || bytes.length<1024 || bytes[0]!==0x4d || bytes[1]!==0x5a || crypto.createHash('sha256').update(bytes).digest('hex')!==manifest.sha256)throw new Error('Installer verification failed. No package was created.');
  return bytes;
}
function crc32(bytes){let crc=0xffffffff;for(const b of bytes){crc^=b;for(let i=0;i<8;i++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}return (crc^0xffffffff)>>>0;}
// A two-file ZIP with unchanged installer bytes. Setup authorization is a
// sidecar so it also works when the installer is Authenticode-signed later.
export function setupZip(installer,config){
  const files=[['WindowsProtect_Setup.exe',installer],['WindowsProtect_Setup.json',Buffer.from(JSON.stringify(config),'utf8')]];
  const locals=[],central=[];let offset=0;
  for(const [name,data] of files){
    const filename=Buffer.from(name);const crc=crc32(data);
    const local=Buffer.alloc(30);local.writeUInt32LE(0x04034b50);local.writeUInt16LE(20,4);local.writeUInt16LE(0x800,6);local.writeUInt16LE(33,12);local.writeUInt32LE(crc,14);local.writeUInt32LE(data.length,18);local.writeUInt32LE(data.length,22);local.writeUInt16LE(filename.length,26);
    const entry=Buffer.alloc(46);entry.writeUInt32LE(0x02014b50);entry.writeUInt16LE(20,4);entry.writeUInt16LE(20,6);entry.writeUInt16LE(0x800,8);entry.writeUInt16LE(33,14);entry.writeUInt32LE(crc,16);entry.writeUInt32LE(data.length,20);entry.writeUInt32LE(data.length,24);entry.writeUInt16LE(filename.length,28);entry.writeUInt32LE(offset,42);
    locals.push(local,filename,data);central.push(entry,filename);offset+=local.length+filename.length+data.length;
  }
  const directory=Buffer.concat(central);const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(files.length,8);end.writeUInt16LE(files.length,10);end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);
  return Buffer.concat([...locals,directory,end]);
}
