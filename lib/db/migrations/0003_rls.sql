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
