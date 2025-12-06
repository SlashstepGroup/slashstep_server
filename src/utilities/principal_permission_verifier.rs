use thiserror::Error;
use uuid::Uuid;

use crate::resources::{access_policy::{AccessPolicy, AccessPolicyError, AccessPolicyPermissionLevel, ResourceHierarchy}, user::UserError};

#[derive(Debug, Error)]
pub enum PrincipalPermissionVerifierError {

  #[error("The principal does not have the required permissions to perform the action \"{action_id}\".")]
  ForbiddenError {
    user_id: String,
    action_id: String,
    minimum_permission_level: AccessPolicyPermissionLevel,
    actual_permission_level: AccessPolicyPermissionLevel
  },

  #[error(transparent)]
  UserError(#[from] UserError),

  #[error(transparent)]
  AccessPolicyError(#[from] AccessPolicyError)
}

pub struct PrincipalPermissionVerifier;

impl PrincipalPermissionVerifier {

  pub async fn verify_user_permissions(user_id: &Uuid, action_id: &Uuid, resource_hierarchy: &ResourceHierarchy, minimum_permission_level: &AccessPolicyPermissionLevel, postgres_client: &mut deadpool_postgres::Client) -> Result<(), PrincipalPermissionVerifierError> {

    let relevant_access_policies = AccessPolicy::list_by_hierarchy(resource_hierarchy, action_id, postgres_client).await?;
    let deepest_access_policy = relevant_access_policies.first();

    if deepest_access_policy.is_none() {

      return Err(PrincipalPermissionVerifierError::ForbiddenError {
        user_id: user_id.to_string(), 
        action_id: action_id.to_string(),
        minimum_permission_level: minimum_permission_level.clone(),
        actual_permission_level: AccessPolicyPermissionLevel::None
      });

    }

    return Ok(());

  }

}