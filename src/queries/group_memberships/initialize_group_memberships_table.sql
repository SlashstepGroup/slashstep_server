DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'group_membership_principal_type') THEN
      CREATE TYPE group_membership_principal_type AS ENUM (
        'App',
        'Group',
        'User'
      );
    END IF;

    CREATE TABLE IF NOT EXISTS group_memberships (
      id UUID default uuidv7() primary key,
      group_id UUID references groups(id) on delete cascade,
      principal_id UUID references users(id) on delete cascade,
      principal_type group_membership_principal_type not null,
      principal_user_id UUID references users(id) on delete cascade,
      principal_group_id UUID references groups(id) on delete cascade,
      principal_app_id UUID references apps(id) on delete cascade
    );
  END
$$ LANGUAGE plpgsql;