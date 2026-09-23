begin;
grant usage on schema private to service_role;
grant all privileges on all tables in schema private to service_role;
grant all privileges on all sequences in schema private to service_role;
commit;
