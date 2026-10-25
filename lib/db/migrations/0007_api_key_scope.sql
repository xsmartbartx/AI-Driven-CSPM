-- API keys get an access level and an optional expiry. Existing keys keep what they always had (analyst: run scans and
-- read findings) and never expire; new keys can be read-only and time-limited.
alter table api_keys add column if not exists role text not null default 'analyst';
alter table api_keys add column if not exists expires_at timestamptz;
do $$ begin
  alter table api_keys add constraint api_keys_role_check check (role in ('viewer', 'analyst'));
exception when duplicate_object then null;
end $$;
