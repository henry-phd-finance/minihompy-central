-- 중앙 공통 방문자 식별 테이블 및 보안 스키마
begin;

create extension if not exists "pgcrypto";
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

-- 1. 공통 사용자 테이블 (identity_members)
create table if not exists private.identity_members (
  id uuid primary key default gen_random_uuid(),
  handle text not null unique check (handle ~ '^[a-z0-9._-]{2,30}$'),
  display_name text not null check (char_length(trim(display_name)) between 1 and 50 and display_name !~ '[\u0000-\u001f\u007f]'),
  status text not null default 'active' check (status in ('active', 'suspended', 'deleted')),
  session_version integer not null default 1 check (session_version >= 1),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table private.identity_members enable row level security;
revoke all on private.identity_members from public, anon, authenticated;

-- 2. 등록된 미니홈피 사이트 테이블 (identity_sites)
create table if not exists private.identity_sites (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null unique references private.identity_members(id) on delete cascade,
  origin text not null check (origin ~ '^https?://[a-zA-Z0-9.-]+(:[0-9]+)?$'),
  base_path text not null check (base_path ~ '^/([a-zA-Z0-9._-]+/)*$'),
  homepage_url text not null unique,
  login_url text not null,
  supabase_project_ref text not null unique check (supabase_project_ref ~ '^[a-zA-Z0-9_-]+$'),
  status text not null default 'active' check (status in ('active', 'suspended', 'deleted')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table private.identity_sites enable row level security;
revoke all on private.identity_sites from public, anon, authenticated;

-- 3. 사이트와 로컬 Supabase 사용자 바인딩 테이블 (identity_bindings)
create table if not exists private.identity_bindings (
  site_id uuid primary key references private.identity_sites(id) on delete cascade,
  member_id uuid not null unique references private.identity_members(id) on delete cascade,
  local_user_id uuid not null,
  status text not null default 'active' check (status in ('active', 'revoked')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table private.identity_bindings enable row level security;
revoke all on private.identity_bindings from public, anon, authenticated;

commit;
