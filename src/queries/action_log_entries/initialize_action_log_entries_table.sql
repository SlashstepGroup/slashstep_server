DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_log_entry_actor_type') THEN
      CREATE TYPE action_log_entry_actor_type AS ENUM (
        'User',
        'App'
      );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_log_entry_target_resource_type') THEN
      CREATE TYPE action_log_entry_target_resource_type AS ENUM (
        'AccessPolicy',
        'Action',
        'ActionLogEntry',
        'App',
        'AppAuthorization',
        'AppAuthorizationCredential',
        'AppCredential',
        'Group',
        'GroupMembership',
        'HTTPTransaction',
        'Instance',
        'Item',
        'Project',
        'Role',
        'RoleMembership',
        'ServerLogEntry',
        'Session',
        'User',
        'Workspace',
        'Milestone'
      );
    END IF;

    CREATE TABLE IF NOT EXISTS action_log_entries (
      id UUID default uuidv7() PRIMARY KEY,
      action_id UUID NOT NULL REFERENCES actions(id),
      http_transaction_id UUID REFERENCES http_transactions(id),
      actor_type action_log_entry_actor_type not null,
      actor_user_id UUID REFERENCES users(id),
      actor_app_id UUID REFERENCES apps(id),
      target_resource_type action_log_entry_target_resource_type not null,
      target_access_policy_id UUID, -- This needs to be referenced after the access policies table is created.
      target_action_id UUID REFERENCES actions(id),
      target_action_log_entry_id UUID REFERENCES action_log_entries(id),
      target_app_id UUID REFERENCES apps(id),
      target_app_authorization_id UUID REFERENCES app_authorizations(id),
      target_app_authorization_credential_id UUID REFERENCES app_authorization_credentials(id),
      target_app_credential_id UUID REFERENCES app_credentials(id),
      target_group_id UUID REFERENCES groups(id),
      target_group_membership_id UUID REFERENCES group_memberships(id),
      target_http_transaction_id UUID REFERENCES http_transactions(id),
      target_item_id UUID REFERENCES items(id),
      target_milestone_id UUID REFERENCES milestones(id),
      target_project_id UUID REFERENCES projects(id),
      target_role_id UUID REFERENCES roles(id),
      target_role_membership_id UUID REFERENCES role_memberships(id),
      target_server_log_entry_id UUID REFERENCES server_log_entries(id),
      target_session_id UUID REFERENCES sessions(id),
      target_user_id UUID REFERENCES users(id),
      target_workspace_id UUID REFERENCES workspaces(id),
      reason TEXT
    );
  END
$$ LANGUAGE plpgsql;