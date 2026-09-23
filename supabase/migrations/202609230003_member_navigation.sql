-- Read-only public navigation data, exposed only through the central API.
begin;
create or replace function private.identity_navigation(
  p_mode text, p_site uuid default null, p_members uuid[] default null,
  p_query text default null, p_after uuid default null, p_limit integer default 20
) returns jsonb language plpgsql stable security invoker set search_path = '' as $$
declare result jsonb;
begin
  if p_mode not in ('site','members','list','random') or p_mode is null
    or p_limit is null or p_limit not between 1 and 50
    or (p_mode in ('site','random') and p_site is null)
    or (p_mode = 'members' and (p_members is null or cardinality(p_members) not between 1 and 50))
    or (p_query is not null and (length(p_query) not between 2 and 30 or p_query ~ '[[:cntrl:]]')) then
    raise exception 'Invalid navigation parameters' using errcode = '22023';
  end if;
  with eligible as (
    select m.id, s.id as site_id, m.handle, m.display_name, s.homepage_url
    from private.identity_members m join private.identity_sites s on s.member_id = m.id
    where m.status = 'active' and s.status = 'active' and s.verification_status = 'verified'
      and s.origin ~ '^https://[a-zA-Z0-9.-]+(:[0-9]+)?$'
      and coalesce(substring(s.origin from ':([0-9]+)$')::numeric, 443) between 1 and 65535
      and s.homepage_url in (s.origin || s.base_path, s.origin || rtrim(s.base_path, '/'))
      and (p_mode <> 'site' or s.id = p_site)
      and (p_mode <> 'members' or m.id = any(p_members))
      and (p_mode <> 'random' or s.id <> p_site)
      and (p_mode <> 'list' or p_after is null or m.id > p_after)
      and (p_mode <> 'list' or p_query is null or strpos(m.handle, lower(p_query)) > 0)
  ), chosen as (
    select * from eligible
    order by case when p_mode = 'random' then random() else 0 end, id
    limit case when p_mode = 'random' then 1 when p_mode = 'list' then p_limit + 1 else 50 end
  ) select coalesce(jsonb_agg(to_jsonb(chosen)), '[]'::jsonb) into result from chosen;
  return result;
end $$;
revoke all on function private.identity_navigation(text,uuid,uuid[],text,uuid,integer) from public, anon, authenticated;
grant execute on function private.identity_navigation(text,uuid,uuid[],text,uuid,integer) to service_role;
commit;
