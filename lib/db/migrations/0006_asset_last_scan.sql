-- Which scan last saw an asset. Attack paths are built only from what the latest scan of an account actually found, so a
-- resource that disappeared (or could not be read this time) stops appearing in paths at once, without any time window.
alter table assets add column if not exists last_scan_id uuid references scans(id) on delete set null;
create index if not exists assets_last_scan_idx on assets (last_scan_id);
