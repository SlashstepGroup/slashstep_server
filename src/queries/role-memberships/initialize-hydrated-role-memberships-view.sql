create or replace view hydrated_role_memberships as
  select
    role_memberships.*
  from 
    role_memberships