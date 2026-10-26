-- Per-organization alert settings: email to owners and admins, and/or a Slack incoming webhook, when a scan finds new
-- findings at or above a severity. The webhook URL is a secret: it is stored here (row level security applies) and is
-- never returned by the API.
create table if not exists notification_settings (
  org_id uuid primary key references organizations(id) on delete cascade,
  email_enabled boolean not null default false,
  min_severity text not null default 'high' check (min_severity in ('critical', 'high')),
  slack_webhook text,
  last_sent_at timestamptz,
  last_error text,
  updated_at timestamptz not null default now()
);
grant select, insert, update, delete on notification_settings to cspm_app;
alter table notification_settings enable row level security;
drop policy if exists tenant_isolation on notification_settings;
create policy tenant_isolation on notification_settings to cspm_app using (org_id = app_org()) with check (org_id = app_org());
