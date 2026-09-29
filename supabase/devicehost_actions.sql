-- DeviceHost fixed-action expansion.
-- Run in Supabase SQL Editor before enabling the new controls.

alter table public.device_commands
  drop constraint if exists device_commands_command_type_check;

alter table public.device_commands
  add constraint device_commands_command_type_check
  check (command_type in (
    'show_message',
    'open_url',
    'lock_pc',
    'launch_rustdesk',
    'restart_rustdesk',
    'request_status',
    'finalize_migration',
    'temporary_support_enable',
    'temporary_support_disable',
    'defender_quick_scan',
    'install_approved_app'
  ));

create table if not exists public.action_audit (
  id uuid primary key default gen_random_uuid(),
  device_id uuid not null references public.devices(id) on delete cascade,
  action_type text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.action_audit enable row level security;
revoke all on public.action_audit from anon, authenticated;
grant select, insert, update, delete on public.action_audit to service_role;

create index if not exists action_audit_device_created_idx
  on public.action_audit(device_id, created_at desc);
