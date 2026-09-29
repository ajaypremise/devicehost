alter table public.devices
  add column if not exists remote_access_provider text not null default 'meshcentral',
  add column if not exists meshcentral_node_id text,
  add column if not exists meshcentral_connected boolean not null default false,
  add column if not exists meshcentral_agent_version text,
  add column if not exists temporary_support_expires_at timestamptz;

create index if not exists devices_meshcentral_node_idx
  on public.devices(meshcentral_node_id);
