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
