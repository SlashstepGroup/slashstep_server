/**
 * 
 * This module defines the route handlers for specific action log entry resources.
 * Anything to do with /action-log-entries/{action_log_entry_id} should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::sync::Arc;
use axum::{Extension, Json, Router, extract::{Path, State}};
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::authentication_middleware, resources::{access_policy::{AccessPolicy, AccessPolicyError, AccessPolicyPermissionLevel, ResourceHierarchy}, action_log_entry::ActionLogEntry, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{resource_hierarchy::{self, ResourceHierarchyError}, route_handler_utilities::{get_action_from_name, get_user_from_option_user, map_postgres_error_to_http_error, verify_user_permissions}}};

async fn get_action_log_entry_from_id(action_log_entry_id: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<ActionLogEntry, HTTPError> {

  let access_policy_id = match Uuid::parse_str(&access_policy_id) {

    Ok(access_policy_id) => access_policy_id,

    Err(_) => {

      let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the access policy ID.".to_string()));
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  let _ = ServerLogEntry::trace(&format!("Getting access policy {}...", access_policy_id), Some(&http_transaction.id), &mut postgres_client).await;
  
  let access_policy = match AccessPolicy::get_by_id(&access_policy_id, &mut postgres_client).await {

    Ok(access_policy) => access_policy,

    Err(error) => {

      let http_error = match error {
        AccessPolicyError::NotFoundError(_) => HTTPError::NotFoundError(Some(error.to_string())),
        AccessPolicyError::PostgresError(error) => {

          match error.as_db_error() {

            Some(error) => HTTPError::InternalServerError(Some(error.to_string())),
            None => HTTPError::InternalServerError(Some(error.to_string()))

          }

        }
        _ => HTTPError::InternalServerError(Some(error.to_string()))
      };
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;

      return Err(http_error);

    }

  };

  return Ok(access_policy);

}

#[axum::debug_handler]
async fn handle_get_action_log_entry_request(
  Path(action_log_entry_id): Path<String>,
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Extension(user): Extension<Option<Arc<User>>>
) -> Result<Json<ActionLogEntry>, HTTPError> {

  let http_transaction = http_transaction.clone();
  let mut postgres_client = state.database_pool.get().await.map_err(map_postgres_error_to_http_error)?;
  let action_log_entry = get_action_log_entry_from_id(&action_log_entry_id, &http_transaction, &mut postgres_client).await?;
  let user = get_user_from_option_user(&user, &http_transaction, &mut postgres_client).await?;
  let resource_hierarchy = get_resource_hierarchy(&action_log_entry, &http_transaction, &mut postgres_client).await?;
  let action = get_action_from_name("slashstep.actionLogEntries.get", &http_transaction, &mut postgres_client).await?;
  verify_user_permissions(&user, &action, &resource_hierarchy, &http_transaction, &AccessPolicyPermissionLevel::User, &mut postgres_client).await?;
  
  ServerLogEntry::success(&format!("Successfully returned action log entry {}.", action_log_entry_id), Some(&http_transaction.id), &mut postgres_client).await;

  return Ok(Json(action_log_entry));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/action-log-entries/{action_log_entry_id}", axum::routing::get(handle_get_action_log_entry_request))
    .layer(axum::middleware::from_fn_with_state(state, authentication_middleware::authenticate_user));
  return router;

}

#[cfg(test)]
mod tests;