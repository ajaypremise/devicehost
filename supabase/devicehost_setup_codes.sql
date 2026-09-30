-- One-time WindowsProtect setup codes.
-- Run once in the DeviceHost Supabase project.

create table if not exists public.setup_codes (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  label text,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.setup_codes enable row level security;
revoke all on public.setup_codes from anon, authenticated;
grant select, insert, update, delete on public.setup_codes to service_role;

create index if not exists setup_codes_expiry_idx
  on public.setup_codes(expires_at, used_at);
