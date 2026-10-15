-- NEXORA CSPM schema. Postgres 15+. Times are timestamptz (UTC). Every tenant table has org_id.
create extension if not exists pgcrypto;

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
  email_verified_at timestamptz,            -- set by the verify link, or by Nexora SSO (Nexora already verified it)
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

create table email_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  kind text not null check (kind in ('reset','verify')),
  token_hash text not null unique,          -- sha256; the token itself exists only in the email
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);
create index on email_tokens (user_id, kind);

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
