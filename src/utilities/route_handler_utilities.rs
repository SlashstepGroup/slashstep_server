use std::sync::Arc;

use crate::{HTTPError, resources::{access_policy::{AccessPolicyPermissionLevel, Principal, ResourceHierarchy}, action::Action, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::principal_permission_verifier::{PrincipalPermissionVerifier, PrincipalPermissionVerifierError}};
use colored::Colorize;

pub fn map_postgres_error_to_http_error(error: deadpool_postgres::PoolError) -> HTTPError {

  let http_error = HTTPError::InternalServerError(Some(error.to_string()));
  eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
  return http_error;

}

pub async fn get_action_from_name(action_name: &str, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Action, HTTPError> {

  let _ = ServerLogEntry::trace(&format!("Getting action \"{}\"...", action_name), Some(&http_transaction.id), &mut postgres_client).await;
  let action = match Action::get_by_name(&action_name, &mut postgres_client).await {

    Ok(action) => action,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to get action \"{}\": {:?}", action_name, error)));
      let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  };

  return Ok(action);

}

pub async fn get_user_from_option_user(user: &Option<Arc<User>>, http_transaction: &HTTPTransaction, mut postgres_client: &mut deadpool_postgres::Client) -> Result<Arc<User>, HTTPError> {

  let Some(user) = user else {

    let http_error = HTTPError::InternalServerError(Some(format!("Couldn't find a user for the request. This is a bug. Make sure the authentication middleware is installed and is working properly.")));
    let _ = http_error.print_and_save(Some(&http_transaction.id), &mut postgres_client).await;
    return Err(http_error);

  };

  return Ok(user.clone());

}

pub async fn verify_user_permissions(user: &User, action: &Action, resource_hierarchy: &ResourceHierarchy, http_transaction: &HTTPTransaction, minimum_permission_level: &AccessPolicyPermissionLevel, mut postgres_client: &mut deadpool_postgres::Client) -> Result<(), HTTPError> {

  let _ = ServerLogEntry::trace(&format!("Verifying principal may use \"{}\" action...", action.name), Some(&http_transaction.id), &mut postgres_client).await;

  match PrincipalPermissionVerifier::verify_permissions(&Principal::User(user.id), &action.id, &resource_hierarchy, &minimum_permission_level, &mut postgres_client).await {

    Ok(_) => {},

    Err(error) => {

      let http_error = match error {

        PrincipalPermissionVerifierError::ForbiddenError { .. } => {
          
          let message = format!("You need at least {} permission to the \"{}\" action.", minimum_permission_level.to_string(), action.name);
          if user.is_anonymous {

            HTTPError::UnauthorizedError(Some(message))

          } else {

            HTTPError::ForbiddenError(Some(message))
          
          }

        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };
      let _ = ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &mut postgres_client).await;
      return Err(http_error);

    }

  }

  return Ok(());

}