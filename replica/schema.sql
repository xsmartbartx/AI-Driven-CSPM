-- GENERATED from lib/db/migrations by gen-schema.mjs. The current schema, for reading. Change schema by adding a migration.

-- ===== 0001_init =====
-- NEXORA CSPM schema. Postgres 15+. Times are timestamptz (UTC). Every tenant table has org_id.

create table organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  nexora_org_id text unique,
  plan text not null default 'free' check (plan in ('free','starter','team','enterprise')),
  stripe_customer_id text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  name text,
  nexora_user_id text unique,
  password_hash text,                       -- null when SSO only
  token_version int not null default 0,     -- bump to sign out everywhere
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table members (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  role text not null default 'viewer' check (role in ('owner','admin','analyst','viewer')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, user_id)
);
create index on members (user_id);

create table cloud_accounts (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  provider text not null check (provider in ('aws','azure','gcp','k8s')),
  external_id text not null,                -- AWS account id etc
  role_arn text,
  sts_external_id text,                     -- random per account, for confused-deputy protection
  status text not null default 'pending' check (status in ('pending','connected','error')),
  last_sync_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, provider, external_id)
);

create table scans (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  created_by uuid references users(id) on delete set null,
  source text not null check (source in ('paste','account')),
  account_id uuid references cloud_accounts(id) on delete set null,
  status text not null default 'completed' check (status in ('running','completed','failed')),
  resource_count int not null default 0,
  finding_count int not null default 0,
  score int check (score between 0 and 100),
  counts jsonb not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on scans (org_id, created_at desc);

create table assets (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  account_id uuid references cloud_accounts(id) on delete set null,
  provider text not null default 'aws',
  type text not null,
  name text not null,
  environment text not null default 'production' check (environment in ('production','staging','development')),
  criticality int not null default 5 check (criticality between 1 and 10),
  owner text,
  raw jsonb not null default '{}',
  last_seen_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, provider, type, name)
);
create index on assets (org_id, type);
create index on assets (account_id);

create table findings (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  scan_id uuid not null references scans(id) on delete cascade,
  asset_id uuid not null references assets(id) on delete cascade,
  rule_id text not null,
  title text not null,
  severity text not null check (severity in ('critical','high','medium','low')),
  risk_score int not null check (risk_score between 0 and 100),
  status text not null default 'open' check (status in ('open','fixed','accepted','false_positive')),
  status_reason text,
  accepted_until timestamptz,
  evidence jsonb not null default '{}',
  remediation text not null,
  frameworks text[] not null default '{}',
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- one live finding per rule per asset: rescans update, never duplicate
  unique (org_id, asset_id, rule_id),
  check (status <> 'accepted' or (status_reason is not null and accepted_until is not null))
);
create index on findings (org_id, status, risk_score desc);
create index on findings (scan_id);
create index on findings (asset_id);

create table risk_snapshots (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  day date not null,
  score int not null check (score between 0 and 100),
  critical int not null default 0, high int not null default 0,
  medium int not null default 0, low int not null default 0,
  created_at timestamptz not null default now(),
  unique (org_id, day)
);

create table ai_briefs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  finding_id uuid references findings(id) on delete cascade,
  kind text not null check (kind in ('finding','daily')),
  content text not null,
  model text not null,
  created_at timestamptz not null default now()
);
create index on ai_briefs (org_id, finding_id);

create table usage_events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  kind text not null check (kind in ('scan','ai')),
  period text not null,                     -- 'YYYY-MM'
  created_at timestamptz not null default now()
);
create index on usage_events (org_id, kind, period);

create table audit_events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  actor_id uuid references users(id) on delete set null,
  action text not null,
  target text,
  ip text,
  created_at timestamptz not null default now()
);
create index on audit_events (org_id, created_at desc);

create table api_keys (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  name text not null,
  key_hash text not null unique,            -- sha256; plaintext shown once
  prefix text not null,
  last_used_at timestamptz,
  created_at timestamptz not null default now()
);

create table invites (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  email text not null,
  role text not null check (role in ('admin','analyst','viewer')),
  token_hash text not null unique,
  expires_at timestamptz not null,
  accepted_at timestamptz,
  created_at timestamptz not null default now()
);

create table sso_tokens (
  jti text primary key,                     -- one-time use of Nexora handoff tokens
  expires_at timestamptz not null
);

create table billing_state (
  customer text primary key,                -- Stripe customer id
  plan text not null check (plan in ('free','starter','team','enterprise')),
  event_at timestamptz not null             -- time of the newest Stripe event applied; older events are ignored
);

create table stripe_events (
  id text primary key,                      -- idempotency: webhooks arrive twice
  received_at timestamptz not null default now()
);

-- Defense in depth: RLS keyed on a per-transaction setting. The API ALSO scopes every query by org_id.
-- Pattern for each tenant table:  alter table X enable row level security;
--   create policy tenant on X using (org_id = current_setting('app.org_id', true)::uuid);

-- ===== 0002_email =====
-- Email confirmation and password reset. Idempotent: databases created before migrations existed may already have parts of it.
alter table users add column if not exists email_verified_at timestamptz;

create table if not exists email_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  kind text not null check (kind in ('reset','verify')),
  token_hash text not null unique,          -- sha256; the token itself exists only in the email
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists email_tokens_user_id_kind_idx on email_tokens (user_id, kind);

-- ===== 0003_rls =====
-- Row level security as defense in depth. The API already scopes every query by org_id; this makes Postgres refuse
-- cross-tenant access even when a query forgets to.
--
-- Model: authenticated requests run as the restricted role cspm_app (SET ROLE) with app.org_id set to the caller's
-- organization. Policies compare org_id to that setting; with no setting they match nothing (fail closed).
-- Sign-up, login, SSO, invite acceptance and Stripe webhooks keep using the connection's own role, the table owner,
-- which is not subject to these policies (no FORCE ROW LEVEL SECURITY, on purpose).

-- Creating and granting the role can be refused on managed databases or shared clusters (no CREATEROLE, or the role
-- already exists and belongs to someone else). Do not fail the migration for that: the API checks at startup that it
-- can really SET ROLE cspm_app and refuses to run, with instructions, if it cannot.
do $$ begin
  begin
    if not exists (select 1 from pg_roles where rolname = 'cspm_app') then
      create role cspm_app nologin;
    end if;
  exception when insufficient_privilege then
    raise notice 'could not create role cspm_app: %. Ask an administrator to create it (NOLOGIN) and grant it to this database user.', sqlerrm;
  end;
  begin
    execute 'grant cspm_app to ' || quote_ident(current_user);   -- lets the app's own role SET ROLE cspm_app
  exception when insufficient_privilege then
    raise notice 'could not grant cspm_app to %: %', current_user, sqlerrm;
  end;
end $$;

create or replace function app_org() returns uuid language sql stable as
$$ select nullif(current_setting('app.org_id', true), '')::uuid $$;

grant usage on schema public to cspm_app;
grant execute on function app_org() to cspm_app;

-- tenant tables: full access to the caller's own rows only
grant select, insert, update, delete on
  members, cloud_accounts, scans, assets, findings, risk_snapshots, ai_briefs, usage_events, audit_events, api_keys, invites
  to cspm_app;

do $$ declare t text; begin
  foreach t in array array['members','cloud_accounts','scans','assets','findings','risk_snapshots','ai_briefs','usage_events','audit_events','api_keys','invites'] loop
    execute format('alter table %I enable row level security', t);
    execute format('drop policy if exists tenant_isolation on %I', t);
    execute format('create policy tenant_isolation on %I to cspm_app using (org_id = app_org()) with check (org_id = app_org())', t);
  end loop;
end $$;

-- organizations: read the own row; the only writable column is updated_at, which is what SELECT ... FOR UPDATE needs.
-- Plan, Stripe ids and name cannot be changed from a tenant request, even by a buggy or injected query.
alter table organizations enable row level security;
drop policy if exists tenant_isolation on organizations;
create policy tenant_isolation on organizations to cspm_app using (id = app_org()) with check (id = app_org());
grant select on organizations to cspm_app;
grant update (updated_at) on organizations to cspm_app;

-- users: read-only, and only people who belong to the caller's organization or appear in its history (scan authors, audit actors)
alter table users enable row level security;
drop policy if exists tenant_read on users;
create policy tenant_read on users for select to cspm_app using (
  exists (select 1 from members m where m.user_id = users.id and m.org_id = app_org())
  or exists (select 1 from scans s where s.created_by = users.id and s.org_id = app_org())
  or exists (select 1 from audit_events a where a.actor_id = users.id and a.org_id = app_org())
);
grant select (id, email, name, created_at) on users to cspm_app;   -- never password_hash, token_version or SSO ids

-- email_tokens, sso_tokens, stripe_events, billing_state, schema_migrations: no grants. Tenant requests cannot touch them.

-- ===== 0004_cloud_accounts =====
-- AWS account connections: one row per (account, region). The customer creates a read-only IAM role in their account
-- that trusts our AWS account with a per-connection ExternalId; we only ever hold short-lived assumed credentials.
alter table cloud_accounts add column if not exists region text not null default 'us-east-1';
alter table cloud_accounts add column if not exists last_error text;       -- short, safe code + sentence, never a raw AWS message
alter table cloud_accounts add column if not exists verified_at timestamptz;
alter table cloud_accounts add column if not exists last_scan_id uuid references scans(id) on delete set null;

-- the same account can be connected once per region
alter table cloud_accounts drop constraint if exists cloud_accounts_org_id_provider_external_id_key;
create unique index if not exists cloud_accounts_org_provider_account_region_idx on cloud_accounts (org_id, provider, external_id, region);
