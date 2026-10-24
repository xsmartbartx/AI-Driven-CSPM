-- Automatic rescans of connected AWS accounts.
-- schedule: off | daily | weekly. next_run_at is when the scheduler should pick the account up next.
-- scan_started_at is a lease: it is set while a scan of the account runs (manual or scheduled), on any instance, and
-- a lease older than 20 minutes is treated as abandoned (the process died), so two scans of one account never overlap.
alter table cloud_accounts add column if not exists schedule text not null default 'off' check (schedule in ('off','daily','weekly'));
alter table cloud_accounts add column if not exists next_run_at timestamptz;
alter table cloud_accounts add column if not exists failure_count int not null default 0;     -- consecutive scheduled failures
alter table cloud_accounts add column if not exists last_scheduled_at timestamptz;             -- last successful scheduled scan
alter table cloud_accounts add column if not exists scan_started_at timestamptz;
create index if not exists cloud_accounts_due_idx on cloud_accounts (next_run_at) where schedule <> 'off';
