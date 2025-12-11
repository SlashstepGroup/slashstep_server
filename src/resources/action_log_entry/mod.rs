use postgres_types::{FromSql, ToSql};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ActionLogEntryError {
  #[error("An action log entry with the ID \"{0}\" does not exist.")]
  NotFoundError(String),

  #[error(transparent)]
  PostgresError(#[from] postgres::Error)
}

#[derive(Debug, Clone, FromSql, ToSql)]
#[postgres(name = "action_log_entry_actor_type")]
pub enum ActionLogEntryActorType {
  User,
  App
}

#[derive(Debug, Clone, FromSql, ToSql)]
#[postgres(name = "action_log_entry_target_resource_type")]
pub enum ActionLogEntryTargetResourceType {
  AccessPolicy,
  Action,
  ActionLogEntry,
  App,
  AppAuthorization,
  AppAuthorizationCredential,
  AppCredential,
  Group,
  GroupMembership,
  HTTPTransaction,
  Instance,
  Item,
  Project,
  Role,
  RoleMembership,
  ServerLogEntry,
  Session,
  User,
  Milestone,
  Workspace
}

#[derive(Debug, Clone)]
pub struct ActionLogEntry {

  /// The ID of the action log entry.
  pub id: Uuid,

  /// The ID of the action.
  pub action_id: Uuid,

  /// The ID of the HTTP transaction related to the action log entry, if applicable.
  pub http_transaction_id: Option<Uuid>,

  /// The type of actor that performed the action.
  pub actor_type: ActionLogEntryActorType,

  /// The ID of the user actor that performed the action, if applicable.
  pub actor_user_id: Option<Uuid>,

  /// The ID of the app actor that performed the action, if applicable.
  pub actor_app_id: Option<Uuid>,

  /// The type of the target resource of the action.
  pub target_resource_type: ActionLogEntryTargetResourceType,

  /// The target action ID of the action, if applicable.
  pub target_action_id: Option<Uuid>,

  /// The target action log entry ID of the action, if applicable.
  pub target_action_log_entry_id: Option<Uuid>,

  /// The target app ID of the action, if applicable.
  pub target_app_id: Option<Uuid>,

  /// The target app authorization ID of the action, if applicable.
  pub target_app_authorization_id: Option<Uuid>,

  /// The target app authorization credential ID of the action, if applicable.
  pub target_app_authorization_credential_id: Option<Uuid>,

  /// The target app credential ID of the action, if applicable.
  pub target_app_credential_id: Option<Uuid>,

  /// The target group ID of the action, if applicable.
  pub target_group_id: Option<Uuid>,

  /// The target group membership ID of the action, if applicable.
  pub target_group_membership_id: Option<Uuid>,

  /// The target HTTP transaction ID of the action, if applicable.
  pub target_http_transaction_id: Option<Uuid>,

  /// The target HTTP transaction log entry ID of the action, if applicable.
  pub target_http_transaction_log_entry_id: Option<Uuid>,

  /// The target instance ID of the action, if applicable.
  pub target_instance_id: Option<Uuid>,

  /// The target item ID of the action, if applicable.
  pub target_item_id: Option<Uuid>,

  /// The target milestone ID of the action, if applicable.
  pub target_milestone_id: Option<Uuid>,

  /// The target project ID of the action, if applicable.
  pub target_project_id: Option<Uuid>,

  /// The target role ID of the action, if applicable.
  pub target_role_id: Option<Uuid>,

  /// The target role membership ID of the action, if applicable.
  pub target_role_membership_id: Option<Uuid>,

  /// The target server log entry ID of the action, if applicable.
  pub target_server_log_entry_id: Option<Uuid>,

  /// The target session ID of the action, if applicable.
  pub target_session_id: Option<Uuid>,

  /// The target user ID of the action, if applicable.
  pub target_user_id: Option<Uuid>,

  /// The target workspace ID of the action, if applicable.
  pub target_workspace_id: Option<Uuid>,

  /// The reason why the action was performed, if applicable.
  pub reason: Option<String>

}

impl ActionLogEntry {

  pub async fn get_by_id(id: &Uuid, postgres_client: &mut deadpool_postgres::Client) -> Result<Self, ActionLogEntryError> {

    let query = include_str!("../../queries/action_log_entries/get_action_log_entry_row_by_id.sql");
    let row = match postgres_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ActionLogEntryError::NotFoundError(id.to_string()))

      },

      Err(error) => return Err(ActionLogEntryError::PostgresError(error))

    };

    let action_log_entry = ActionLogEntry::from_row(&row);

    return Ok(action_log_entry);

  }

  fn from_row(row: &postgres::Row) -> Self {

    return ActionLogEntry {
      id: row.get("id"),
      action_id: row.get("action_id"),
      http_transaction_id: row.get("http_transaction_id"),
      actor_type: row.get("actor_type"),
      actor_user_id: row.get("actor_user_id"),
      actor_app_id: row.get("actor_app_id"),
      target_resource_type: row.get("target_resource_type"),
      target_action_id: row.get("target_action_id"),
      target_action_log_entry_id: row.get("target_action_log_entry_id"),
      target_app_id: row.get("target_app_id"),
      target_app_authorization_id: row.get("target_app_authorization_id"),
      target_app_authorization_credential_id: row.get("target_app_authorization_credential_id"),
      target_app_credential_id: row.get("target_app_credential_id"),
      target_group_id: row.get("target_group_id"),
      target_group_membership_id: row.get("target_group_membership_id"),
      target_http_transaction_id: row.get("target_http_transaction_id"),
      target_http_transaction_log_entry_id: row.get("target_http_transaction_log_entry_id"),
      target_instance_id: row.get("target_instance_id"),
      target_item_id: row.get("target_item_id"),
      target_milestone_id: row.get("target_milestone_id"),
      target_project_id: row.get("target_project_id"),
      target_role_id: row.get("target_role_id"),
      target_role_membership_id: row.get("target_role_membership_id"),
      target_server_log_entry_id: row.get("target_server_log_entry_id"),
      target_session_id: row.get("target_session_id"),
      target_user_id: row.get("target_user_id"),
      target_workspace_id: row.get("target_workspace_id"),
      reason: row.get("reason")
    };

  }

  /// Initializes the action_log_entries table.
  pub async fn initialize_action_log_entries_table(postgres_client: &mut deadpool_postgres::Client) -> Result<(), ActionLogEntryError> {

    let query = include_str!("../../queries/action_log_entries/initialize_action_log_entries_table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}