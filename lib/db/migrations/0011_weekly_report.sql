-- Optional weekly report email (Mondays), next to the per-scan alerts and the daily summary.
alter table notification_settings add column if not exists weekly_report boolean not null default false;
alter table notification_settings add column if not exists last_weekly_at timestamptz;
