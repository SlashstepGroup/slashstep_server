DO $$ BEGIN
    DROP TYPE IF EXISTS permission_level CASCADE;
    DROP TYPE IF EXISTS resource_type CASCADE;
    DROP TYPE IF EXISTS principal_type CASCADE;
    DROP TABLE IF EXISTS access_policies CASCADE;
    DROP FUNCTION IF EXISTS can_principal_get_access_policy;
    DROP TABLE IF EXISTS group_memberships CASCADE;
    DROP TABLE IF EXISTS role_memberships CASCADE;
    DROP TABLE IF EXISTS actions CASCADE;
END $$ LANGUAGE plpgsql;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'permission_level') THEN
        CREATE TYPE permission_level AS ENUM (
            'None',
            'User',
            'Editor',
            'Admin'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'resource_type') THEN
        CREATE TYPE resource_type AS ENUM (
            'Action',
            'ActionLogEntry',
            'App',
            'AppAuthorization',
            'AppAuthorizationCredential',
            'AppCredential',
            'Group',
            'GroupMembership',
            'HTTPTransaction',
            'HTTPTransactionLogEntry',
            'Instance',
            'Item',
            'Milestone',
            'Project',
            'Role',
            'RoleMembership',
            'Session',
            'User',
            'Workspace'
        );
    END IF;

    if not exists (select 1 from pg_type where typname = 'principal_type') then
        create type principal_type as enum (
            'User',
            'Group',
            'Role',
            'App'
        );
    end if;
END $$ LANGUAGE plpgsql;

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
    role_id UUID,
    principal_type role_membership_principal_type not null,
    principal_user_id UUID,
    principal_group_id UUID,
    principal_app_id UUID
  );
end
$$ LANGUAGE plpgsql;

do $$
begin
  if not exists (select 1 from pg_type where typname = 'group_membership_principal_type') then
    create type group_membership_principal_type as enum (
      'User',
      'Group'
      'App'
    );
  end if;

  create table if not exists group_memberships (
    id UUID default uuidv7() primary key,
    group_id UUID,
    principal_type role_membership_principal_type not null,
    principal_user_id UUID,
    principal_group_id UUID,
    principal_app_id UUID
  );
end
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    CREATE TABLE IF NOT EXISTS actions (
        id UUID default uuidv7() primary key,
        name text not null unique,
        display_name text not null,
        description text not null,
        app_id UUID
    );

    CREATE TABLE IF NOT EXISTS group_memberships (
        id UUID default uuidv7() primary key,
        group_id UUID,
        user_id UUID,
        app_id UUID
    );

    CREATE TABLE IF NOT EXISTS access_policies (
        id UUID default uuidv7() primary key,

        /* Principals */
        principal_type principal_type not null,
        principal_user_id UUID,
        principal_group_id UUID,
        principal_role_id UUID,
        principal_app_id UUID,

        /* Scopes */
        scoped_resource_type resource_type not null,
        scoped_action_id UUID,
        scoped_action_log_entry_id UUID,
        scoped_app_id UUID,
        scoped_app_credential_id UUID,
        scoped_app_authorization_id UUID,
        scoped_app_authorization_credential_id UUID,
        scoped_group_id UUID,
        scoped_group_membership_id UUID,
        scoped_http_transaction_id UUID,
        scoped_http_transaction_log_entry_id UUID,
        scoped_item_id UUID,
        scoped_milestone_id UUID,
        scoped_project_id UUID,
        scoped_role_id UUID,
        scoped_role_membership_id UUID,
        scoped_user_id UUID,
        scoped_session_id UUID,
        scoped_workspace_id UUID,

        /* Permissions */
        action_id UUID not null,
        permission_level permission_level not null,
        is_inheritance_enabled BOOLEAN not null
    );
END $$ LANGUAGE plpgsql;

-- This function returns true if a principal can get an access policy.
-- It's helpful for filtering access policies on the database level, making offsets more consistent.
CREATE OR REPLACE FUNCTION can_principal_get_access_policy(parameter_principal_type principal_type, parameter_principal_user_id UUID, parameter_principal_app_id UUID, access_policy_record access_policies) RETURNS BOOLEAN AS $$
DECLARE
    get_access_policy_action_id UUID;
    current_permission_Level permission_level;
    is_inheritance_enabled_on_selected_resource BOOLEAN;
    selected_resource_type resource_type;
    principal_access_policies access_policies;
    selected_resource_id UUID;
    selected_resource_parent_type resource_type;
    selected_resource_parent_id UUID;
    needs_inheritance BOOLEAN := FALSE;
BEGIN

    -- Set the selected resource type and ID based on the principal type.
    get_access_policy_action_id := (
        select
            id
        from
            actions
        where
            name = 'slashstep.accessPolicies.get'
    );

    selected_resource_type := access_policy_record.scoped_resource_type;
    selected_resource_id := CASE selected_resource_type
        WHEN 'Action' THEN access_policy_record.scoped_action_id
        WHEN 'ActionLogEntry' THEN access_policy_record.scoped_action_log_entry_id
        WHEN 'App' THEN access_policy_record.scoped_app_id
        WHEN 'AppAuthorization' THEN access_policy_record.scoped_app_authorization_id
        WHEN 'AppAuthorizationCredential' THEN access_policy_record.scoped_app_authorization_credential_id
        WHEN 'AppCredential' THEN access_policy_record.scoped_app_credential_id
        WHEN 'Group' THEN access_policy_record.scoped_group_id
        WHEN 'GroupMembership' THEN access_policy_record.scoped_group_membership_id
        WHEN 'HTTPTransaction' THEN access_policy_record.scoped_http_transaction_id
        WHEN 'HTTPTransactionLogEntry' THEN access_policy_record.scoped_http_transaction_log_entry_id
        WHEN 'Instance' THEN NULL
        WHEN 'Item' THEN access_policy_record.scoped_item_id
        WHEN 'Milestone' THEN access_policy_record.scoped_milestone_id
        WHEN 'Project' THEN access_policy_record.scoped_project_id
        WHEN 'Role' THEN access_policy_record.scoped_role_id
        WHEN 'RoleMembership' THEN access_policy_record.scoped_role_membership_id
        WHEN 'Session' THEN access_policy_record.scoped_session_id
        WHEN 'User' THEN access_policy_record.scoped_user_id
        WHEN 'Workspace' THEN access_policy_record.scoped_workspace_id
    END;

    LOOP

        IF selected_resource_type = 'Instance' THEN

            -- Instance
            -- Get all group memberships, including those inherited from parent groups.
            WITH RECURSIVE all_group_memberships AS (
                SELECT
                    parameter_principal_user_id as principal_user_id,
                    parameter_principal_app_id as principal_app_id,
                    group_memberships.group_id,
                    group_memberships.principal_group_id
                FROM
                    group_memberships
                WHERE
                    group_memberships.principal_type::TEXT = parameter_principal_type::TEXT AND (
                        (
                            parameter_principal_type = 'User' AND
                            group_memberships.principal_user_id = parameter_principal_user_id
                        ) OR (
                            parameter_principal_type = 'App' AND
                            group_memberships.principal_app_id = parameter_principal_app_id
                        )
                    )
                UNION
                    SELECT
                        parameter_principal_user_id as principal_user_id,
                        parameter_principal_app_id as principal_app_id,
                        inherited_group_memberships.group_id,
                        inherited_group_memberships.principal_group_id
                    FROM
                        group_memberships inherited_group_memberships
                    JOIN
                        all_group_memberships ON all_group_memberships.group_id = inherited_group_memberships.principal_group_id
            )
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            LEFT JOIN
                all_group_memberships ON (
                    parameter_principal_type = 'User' AND
                    all_group_memberships.principal_user_id = parameter_principal_user_id
                ) OR (
                    parameter_principal_type = 'App' AND
                    all_group_memberships.principal_app_id = parameter_principal_app_id
                )
            LEFT JOIN
                role_memberships ON (
                    role_memberships.principal_group_id = all_group_memberships.group_id
                ) OR (
                    parameter_principal_type = 'User' AND
                    role_memberships.principal_user_id = parameter_principal_user_id
                ) OR (
                    parameter_principal_type = 'App' AND
                    role_memberships.principal_app_id = parameter_principal_app_id
                )   
            WHERE
                (
                    (
                        parameter_principal_type = 'User' AND
                        access_policies.principal_user_id = parameter_principal_user_id
                    ) OR (
                        parameter_principal_type = 'App' AND
                        access_policies.principal_app_id = parameter_principal_app_id
                    ) OR 
                    access_policies.principal_group_id = all_group_memberships.group_id OR
                    access_policies.principal_role_id = role_memberships.role_id
                ) AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'Instance' AND (
                    NOT needs_inheritance OR 
                    access_policies.is_inheritance_enabled
                )
            ORDER BY
                CASE access_policies.principal_type
                    WHEN 'User' THEN 1
                    WHEN 'App' THEN 2
                    WHEN 'Group' THEN 3
                    WHEN 'Role' THEN 4
                    ELSE 5
                END,
                CASE access_policies.permission_level
                    WHEN 'Admin' THEN 1
                    WHEN 'Editor' THEN 2
                    WHEN 'User' THEN 3
                    WHEN 'None' THEN 4
                    ELSE 5
                END
            LIMIT 1;

            RETURN current_permission_Level IS NOT NULL AND current_permission_Level >= 'User';

        ELSIF selected_resource_type = 'Action' THEN

            -- Action -> (App | Instance)
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'Action' AND 
                access_policies.scoped_action_id = parameter_scoped_action_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                parent_resource_type
            INTO
                selected_resource_parent_type
            FROM
                actions
            WHERE
                actions.id = parameter_scoped_action_id;

            IF selected_resource_parent_type = 'App' THEN

                SELECT
                    parent_app_id
                INTO
                    selected_resource_parent_id
                FROM
                    actions
                WHERE
                    actions.id = parameter_scoped_action_id;

                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent app for action %.', selected_resource_id;

                END IF;
                
                selected_resource_type := 'App';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_parent_type = 'Instance' THEN

                selected_resource_type := 'Instance';
                selected_resource_id := NULL;
                
            ELSE

                RAISE EXCEPTION 'Unknown parent resource type % for action %.', selected_resource_parent_type, parameter_scoped_action_id;

            END IF;

        ELSIF selected_resource_type = 'App' THEN

            -- App -> (Workspace | User | Instance)
            -- Check if the app has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'App' AND 
                access_policies.scoped_app_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                workspace_id
            INTO
                selected_resource_parent_id
            FROM
                apps
            WHERE
                apps.id = selected_resource_id;

            IF selected_resource_parent_id IS NOT NULL THEN

                selected_resource_type := 'Workspace';
                selected_resource_id := selected_resource_parent_id;
                CONTINUE;

            END IF;

            SELECT
                user_id
            INTO
                selected_resource_parent_id
            FROM
                apps
            WHERE
                apps.id = selected_resource_id;

            IF selected_resource_parent_id IS NOT NULL THEN

                selected_resource_type := 'User';
                selected_resource_id := selected_resource_parent_id;
                CONTINUE;

            END IF;

            selected_resource_type := 'Instance';
            selected_resource_id := NULL;

        ELSIF selected_resource_type = 'AppAuthorization' THEN

            -- AppAuthorization -> (User | Workspace | Instance)
            -- Check if the app authorization has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'AppAuthorization' AND 
                access_policies.scoped_app_authorization_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                parent_resource_type
            INTO
                selected_resource_parent_type
            FROM
                app_authorizations
            WHERE
                app_authorizations.id = selected_resource_id;

            IF selected_resource_parent_type = 'User' THEN

                SELECT
                    parent_user_id
                INTO
                    selected_resource_parent_id
                FROM
                    app_authorizations
                WHERE
                    app_authorizations.id = selected_resource_id;
                    
                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent user for app authorization %.', selected_resource_id;

                END IF;

                selected_resource_type := 'User';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_parent_type = 'Workspace' THEN

                SELECT
                    parent_workspace_id
                INTO
                    selected_resource_parent_id
                FROM
                    app_authorizations
                WHERE
                    app_authorizations.id = selected_resource_id;
                    
                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent workspace for app authorization %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Workspace';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_parent_type = 'Instance' THEN

                selected_resource_type := 'Instance';
                selected_resource_id := NULL;
                
            ELSE

                RAISE EXCEPTION 'Unknown parent resource type % for action %.', selected_resource_parent_type, parameter_scoped_action_id;

            END IF;

        ELSIF selected_resource_type = 'AppAuthorizationCredential' THEN

            -- AppAuthorizationCredential -> AppAuthorization
            -- Check if the app authorization credential has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'AppAuthorizationCredential' AND 
                access_policies.scoped_app_authorization_credential_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                app_authorization_id
            INTO
                selected_resource_parent_id
            FROM
                app_authorization_credentials
            WHERE
                app_authorization_credentials.id = selected_resource_id;

            IF selected_resource_parent_id IS NULL THEN

                RAISE EXCEPTION 'Couldn''t find a parent app authorization for app authorization credential %.', selected_resource_id;

            END IF;

            selected_resource_type := 'AppAuthorization';
            selected_resource_id := selected_resource_parent_id;

        ELSIF selected_resource_type = 'AppCredential' THEN

            -- AppCredential -> App
            -- Check if the app credential has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'AppCredential' AND 
                access_policies.scoped_app_credential_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                app_id
            INTO
                selected_resource_parent_id
            FROM
                app_credentials
            WHERE
                app_credentials.id = selected_resource_id;

            IF selected_resource_parent_id IS NULL THEN

                RAISE EXCEPTION 'Couldn''t find a parent app for app credential %.', selected_resource_id;

            END IF;

            selected_resource_type := 'App';
            selected_resource_id := selected_resource_parent_id;

        ELSIF selected_resource_type = 'Group' THEN

            -- Group -> Instance
            -- Check if the group has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'Group' AND 
                access_policies.scoped_group_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Use the parent resource type.
            needs_inheritance := TRUE;
            selected_resource_type := 'Instance';
            selected_resource_id := NULL;

        ELSIF selected_resource_type = 'HTTPTransaction' THEN

            -- HTTPTransaction -> Instance
            -- Check if the HTTP transaction has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'HTTPTransaction' AND 
                access_policies.scoped_http_transaction_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Use the parent resource type.
            needs_inheritance := TRUE;
            selected_resource_type := 'Instance';
            selected_resource_id := NULL;

        ELSIF selected_resource_type = 'HTTPTransactionLogEntry' THEN
        
            -- HTTPTransactionLogEntry -> HTTPTransaction
            -- Check if the HTTP transaction log entry has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'HTTPTransactionLogEntry' AND 
                access_policies.scoped_http_transaction_log_entry_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Use the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                http_transaction_id
            INTO
                selected_resource_parent_id
            FROM
                http_transaction_log_entries
            WHERE
                http_transaction_log_entries.id = selected_resource_id;

            IF selected_resource_parent_id IS NULL THEN

                RAISE EXCEPTION 'Couldn''t find a parent HTTP transaction for HTTP transaction log entry %.', selected_resource_id;

            END IF;

            selected_resource_type := 'HTTPTransaction';
            selected_resource_id := selected_resource_parent_id;
            
        ELSIF selected_resource_type = 'Item' THEN

            -- Item -> Project
            -- Check if the item has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'Item' AND 
                access_policies.scoped_item_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                project_id
            INTO
                selected_resource_parent_id
            FROM
                items
            WHERE
                items.id = selected_resource_id;

            IF selected_resource_parent_id IS NULL THEN

                RAISE EXCEPTION 'Couldn''t find a parent project for item %.', selected_resource_id;

            END IF;

            selected_resource_type := 'Project';
            selected_resource_id := selected_resource_parent_id;

        ELSIF selected_resource_type = 'Milestone' THEN

            -- Milestone -> (Project | Workspace)
            -- Check if the milestone has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'Milestone' AND 
                access_policies.scoped_milestone_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                parent_resource_type
            INTO
                selected_resource_parent_type
            FROM
                milestones
            WHERE
                milestones.id = selected_resource_id;

            IF selected_resource_parent_type = 'Project' THEN

                SELECT
                    project_id
                INTO
                    selected_resource_parent_id
                FROM
                    milestones
                WHERE
                    milestones.id = selected_resource_id;
                    
                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent project for milestone %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Project';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_parent_type = 'Workspace' THEN

                SELECT
                    workspace_id
                INTO
                    selected_resource_parent_id
                FROM
                    milestones
                WHERE
                    milestones.id = selected_resource_id;
                    
                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent workspace for milestone %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Workspace';
                selected_resource_id := selected_resource_parent_id;

            ELSE

                RAISE EXCEPTION 'Couldn''t find a parent resource for milestone %.', selected_resource_id;

            END IF;

        ELSIF selected_resource_type = 'Project' THEN

            -- Project -> Workspace
            -- Check if the project has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'Project' AND 
                access_policies.scoped_project_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Use the parent resource type.
            needs_inheritance := TRUE;
            
            SELECT
                workspace_id
            INTO
                selected_resource_parent_id
            FROM
                projects
            WHERE
                projects.id = selected_resource_id;

            IF selected_resource_parent_id IS NULL THEN

                RAISE EXCEPTION 'Couldn''t find a parent workspace for project %.', selected_resource_id;

            END IF;

            selected_resource_type := 'Workspace';
            selected_resource_id := selected_resource_parent_id;

        ELSIF selected_resource_type = 'Role' THEN

            -- Role -> (Project | Workspace | Group | Instance)
            -- Check if the role has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'Role' AND 
                access_policies.scoped_role_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                parent_resource_type
            INTO
                selected_resource_parent_type
            FROM
                roles
            WHERE
                roles.id = selected_resource_id;

            IF selected_resource_parent_type = 'Instance' THEN

                selected_resource_type := 'Instance';
                selected_resource_id := NULL;
                
            ELSIF selected_resource_parent_type = 'Workspace' THEN

                SELECT
                    workspace_id
                INTO
                    selected_resource_parent_id
                FROM
                    roles
                WHERE
                    roles.id = selected_resource_id;
                    
                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent workspace for role %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Workspace';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_parent_type = 'Project' THEN

                SELECT
                    project_id
                INTO
                    selected_resource_parent_id
                FROM
                    roles
                WHERE
                    roles.id = selected_resource_id;
                    
                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent project for role %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Project';
                selected_resource_id := selected_resource_parent_id;

            ELSIF selected_resource_parent_type = 'Group' THEN

                SELECT
                    group_id
                INTO
                    selected_resource_parent_id
                FROM
                    roles
                WHERE
                    roles.id = selected_resource_id;
                    
                IF selected_resource_parent_id IS NULL THEN

                    RAISE EXCEPTION 'Couldn''t find a parent group for role %.', selected_resource_id;

                END IF;

                selected_resource_type := 'Group';
                selected_resource_id := selected_resource_parent_id;

            ELSE

                RAISE EXCEPTION 'Couldn''t find a parent resource for role %.', selected_resource_id;

            END IF;

        ELSIF selected_resource_type = 'RoleMembership' THEN

            -- RoleMembership -> Role
            -- Check if the role membership has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'RoleMembership' AND 
                access_policies.scoped_role_membership_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                role_id
            INTO
                selected_resource_parent_id
            FROM
                role_memberships
            WHERE
                role_memberships.id = selected_resource_id;

            IF selected_resource_parent_id IS NULL THEN

                RAISE EXCEPTION 'Couldn''t find a parent role for role membership %.', selected_resource_id;

            END IF;

            selected_resource_type := 'Role';
            selected_resource_id := selected_resource_parent_id;

        ELSIF selected_resource_type = 'Session' THEN

            -- Session -> User
            -- Check if the session has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'Session' AND 
                access_policies.scoped_session_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;

            SELECT
                user_id
            INTO
                selected_resource_parent_id
            FROM
                sessions
            WHERE
                sessions.id = selected_resource_id;

            IF selected_resource_parent_id IS NULL THEN

                RAISE EXCEPTION 'Couldn''t find a parent user for session %.', selected_resource_id;

            END IF;

            selected_resource_type := 'User';
            selected_resource_id := selected_resource_parent_id;

        ELSIF selected_resource_type = 'User' THEN

            -- User -> Instance
            -- Check if the user has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'User' AND 
                access_policies.scoped_user_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Look for the parent resource type.
            needs_inheritance := TRUE;
            selected_resource_type := 'Instance';
            selected_resource_id := NULL;

        ELSIF selected_resource_type = 'Workspace' THEN

            -- Workspace -> Instance
            -- Check if the workspace has an associated access policy.
            SELECT
                permission_level,
                is_inheritance_enabled
            INTO
                current_permission_Level,
                is_inheritance_enabled_on_selected_resource
            FROM
                access_policies
            WHERE
                access_policies.principal_user_id = parameter_principal_user_id AND
                access_policies.action_id = get_access_policy_action_id AND
                access_policies.scoped_resource_type = 'Workspace' AND 
                access_policies.scoped_workspace_id = selected_resource_id;

            IF needs_inheritance AND NOT is_inheritance_enabled_on_selected_resource THEN

                RETURN FALSE;
            
            ELSIF current_permission_Level IS NOT NULL THEN

                RETURN current_permission_Level >= 'User';

            END IF;

            -- Use the parent resource type.
            needs_inheritance := TRUE;
            selected_resource_type := 'Instance';
            selected_resource_id := NULL;

        ELSE

            RAISE EXCEPTION 'Unknown resource type: %', selected_resource_type;

        END IF;

    END LOOP;

END;
$$ LANGUAGE plpgsql;

DO $$ 
DECLARE
    get_access_policy_action_id UUID;
    principal_group_id UUID;
BEGIN
    INSERT INTO actions (
        name,
        display_name,
        description
    ) VALUES (
        'slashstep.accessPolicies.get',
        'Get access policies',
        ''
    ) RETURNING id INTO get_access_policy_action_id;

    -- INSERT INTO access_policies (
    --     principal_type,
    --     principal_user_id,
    --     action_id,
    --     scoped_resource_type,
    --     permission_level,
    --     is_inheritance_enabled
    -- ) VALUES (
    --     'User',
    --     '019afa5b-9b69-7cd5-8e8e-0b50a13f68f5',
    --     get_access_policy_action_id,
    --     'Instance',
    --     'Admin',
    --     TRUE
    -- );

    INSERT INTO group_memberships (
        group_id,
        principal_type,
        principal_user_id
    ) VALUES (
        uuidv7(),
        'User',
        '019afa5b-9b69-7cd5-8e8e-0b50a13f68f5'
    ) RETURNING group_id INTO principal_group_id;

    INSERT INTO group_memberships (
        group_id,
        principal_type,
        principal_group_id
    ) VALUES (
        uuidv7(),
        'Group',
        principal_group_id
    ) RETURNING group_id INTO principal_group_id;

    INSERT INTO access_policies (
        principal_type,
        principal_group_id,
        action_id,
        scoped_resource_type,
        permission_level,
        is_inheritance_enabled
    ) VALUES (
        'Group',
        principal_group_id,
        get_access_policy_action_id,
        'Instance',
        'Admin',
        TRUE
    );

    INSERT INTO access_policies (
        principal_type,
        principal_user_id,
        action_id,
        scoped_resource_type,
        permission_level,
        is_inheritance_enabled
    ) VALUES (
        'User',
        '019afa5b-9b69-7cd5-8e8e-0b50a13f68f5',
        uuidv7(),
        'Instance',
        'Admin',
        TRUE
    );

    INSERT INTO access_policies (
        principal_type,
        principal_user_id,
        action_id,
        scoped_resource_type,
        permission_level,
        is_inheritance_enabled
    ) VALUES (
        'User',
        '019afa5b-9b69-7cd5-8e8e-0b50a13f68f5',
        uuidv7(),
        'Instance',
        'Editor',
        TRUE
    );

    INSERT INTO access_policies (
        principal_type,
        principal_user_id,
        action_id,
        scoped_resource_type,
        permission_level,
        is_inheritance_enabled
    ) VALUES (
        'User',
        '019afa5b-9b69-7cd5-8e8e-0b50a13f68f5',
        uuidv7(),
        'Instance',
        'User',
        TRUE
    );

    INSERT INTO access_policies (
        principal_type,
        principal_user_id,
        action_id,
        scoped_resource_type,
        permission_level,
        is_inheritance_enabled
    ) VALUES (
        'User',
        '019afa5b-9b69-7cd5-8e8e-0b50a13f68f5',
        uuidv7(),
        'Instance',
        'None',
        TRUE
    );
END $$ LANGUAGE plpgsql;

-- List access policies that the user has access to.
select 
    *
from
    access_policies
WHERE
    can_principal_get_access_policy('User', '019afa5b-9b69-7cd5-8e8e-0b50a13f68f5', NULL, access_policies.*);