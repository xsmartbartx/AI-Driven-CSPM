-- AWS account connections: one row per (account, region). The customer creates a read-only IAM role in their account
-- that trusts our AWS account with a per-connection ExternalId; we only ever hold short-lived assumed credentials.
alter table cloud_accounts add column if not exists region text not null default 'us-east-1';
alter table cloud_accounts add column if not exists last_error text;       -- short, safe code + sentence, never a raw AWS message
alter table cloud_accounts add column if not exists verified_at timestamptz;
alter table cloud_accounts add column if not exists last_scan_id uuid references scans(id) on delete set null;

-- the same account can be connected once per region
alter table cloud_accounts drop constraint if exists cloud_accounts_org_id_provider_external_id_key;
create unique index if not exists cloud_accounts_org_provider_account_region_idx on cloud_accounts (org_id, provider, external_id, region);
