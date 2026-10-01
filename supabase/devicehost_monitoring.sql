-- DeviceHost monitoring expansion.
-- Safe to run after the initial DeviceHost schema.

alter table public.devices
  add column if not exists defender_enabled boolean,
  add column if not exists firewall_enabled boolean,
  add column if not exists smartscreen_enabled boolean,
  add column if not exists rustdesk_version text,
  add column if not exists rustdesk_service_running boolean,
  add column if not exists temporary_support_enabled boolean not null default false,
  add column if not exists uptime_seconds bigint,
  add column if not exists installed_apps_count integer,
  add column if not exists remote_tools_detected text[] not null default '{}',
  add column if not exists security_posture text not null default 'unknown'
    check (security_posture in ('unknown','healthy','warning','critical'));

create table if not exists public.software_inventory (
  id uuid primary key default gen_random_uuid(),
  device_id uuid not null references public.devices(id) on delete cascade,
  app_name text not null,
  app_version text,
  publisher text,
  is_remote_access boolean not null default false,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  unique(device_id, app_name)
);

alter table public.software_inventory enable row level security;
revoke all on public.software_inventory from anon, authenticated;
grant select, insert, update, delete on public.software_inventory to service_role;

create index if not exists software_inventory_device_idx
  on public.software_inventory(device_id, is_remote_access, app_name);

-- Lifecycle states used by 0.5.7+ setup and 0.5.8+ authenticated removal.
-- The original four states remain valid; unrelated constraints are preserved.
begin;
alter table public.devices drop constraint if exists devices_migration_status_check;
alter table public.devices add constraint devices_migration_status_check check (
  migration_status in ('not_started','ultraviewer_active','rustdesk_ready','completed')
  or migration_status ~ '^(verifying_support|awaiting_activation):[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?Z$'
  or migration_status ~ '^removal_requested:[a-f0-9]{64}(:waiting_for_user|:cleanup_failed|:support_removal_failed)?$'
);
commit;
