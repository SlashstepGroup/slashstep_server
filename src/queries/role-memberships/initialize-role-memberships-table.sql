do $$
begin
  if not exists (select 1 from pg_type where typname = 'role_membership_principal_type') then
    create type role_membership_principal_type as enum (
      'User',
      'Group',
      'App'
    );
  end if;

  create table if not exists role_memberships (
    id UUID default uuidv7() primary key,
    role_id UUID references roles(id) on delete cascade,
    principal_type role_membership_principal_type not null,
    principal_user_id UUID references users(id) on delete cascade,
    principal_group_id UUID references groups(id) on delete cascade,
    principal_app_id UUID references apps(id) on delete cascade
  );
end
$$ LANGUAGE plpgsql;