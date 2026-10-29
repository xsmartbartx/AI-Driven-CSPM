-- Rule suppressions: an admin turns a rule off for one asset, for one environment, or everywhere (optionally until a date).
-- Matching findings are stored as false_positive with suppression_id set, so they stop counting toward the score, the
-- compliance view and alerts, and come back by themselves when the suppression is removed or expires.
create table if not exists suppressions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  rule_id text not null,
  asset_id uuid references assets(id) on delete cascade,
  environment text check (environment in ('production', 'staging', 'development')),
  reason text not null,
  expires_at timestamptz,
  created_by uuid references users(id) on delete set null,
  created_at timestamptz not null default now(),
  check (asset_id is null or environment is null)
);
create index if not exists suppressions_org_idx on suppressions (org_id);
alter table findings add column if not exists suppression_id uuid references suppressions(id) on delete set null;
grant select, insert, update, delete on suppressions to cspm_app;
alter table suppressions enable row level security;
drop policy if exists tenant_isolation on suppressions;
create policy tenant_isolation on suppressions to cspm_app using (org_id = app_org()) with check (org_id = app_org());
