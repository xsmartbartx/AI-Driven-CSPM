-- Optional daily summary email to owners and admins, alongside the per-scan alerts.
alter table notification_settings add column if not exists daily_digest boolean not null default false;
alter table notification_settings add column if not exists last_digest_at timestamptz;
