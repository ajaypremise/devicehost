export const onlineWindowMs=10*60*1000;

export function deviceOnline(lastSeen,now=Date.now()){
  const seen=Date.parse(lastSeen||"");
  return Number.isFinite(seen) && now-seen<onlineWindowMs;
}

export function remoteSupportConnected(device,now=Date.now()){
  if(!deviceOnline(device?.last_seen_at,now))return false;
  return device?.remote_access_provider==="meshcentral"
    ? device.meshcentral_connected===true
    : device?.rustdesk_service_running===true;
}
