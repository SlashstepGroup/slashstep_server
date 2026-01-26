use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State}};
use crate::{
  AppState, 
  HTTPError, 
  middleware::authentication_middleware, 
  resources::{
    access_policy::AccessPolicyPermissionLevel, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User
  }, 
  utilities::route_handler_utilities::{get_action_from_name, get_app_from_id, get_resource_hierarchy_for_app, get_user_from_option_user, map_postgres_error_to_http_error, verify_user_permissions}
};

#[axum::debug_handler]
async fn handle_get_app_request(
  Path(app_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<Json<App>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let target_app = get_app_from_id(&app_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy_for_app(&target_app, &http_transaction, &mut postgres_client).await?;
  let get_apps_action = get_action_from_name("slashstep.apps.get", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &get_apps_action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  
  ActionLogEntry::create(&InitialActionLogEntryProperties {
    action_id: get_apps_action.id,
    http_transaction_id: Some(http_transaction.id),
    actor_type: ActionLogEntryActorType::User,
    actor_user_id: Some(user.id),
    target_resource_type: ActionLogEntryTargetResourceType::App,
    target_app_id: Some(target_app.id),
    ..Default::default()
  }, &mut postgres_client).await.ok();
  ServerLogEntry::success(&format!("Successfully returned app {}.", target_app.id), Some(&http_transaction.id), &mut postgres_client).await.ok();

  return Ok(Json(target_app));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/apps/{action_id}", axum::routing::get(handle_get_app_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user));
  return router;

}

#[cfg(test)]
mod tests;