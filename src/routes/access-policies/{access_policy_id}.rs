use axum::{Extension, Json, Router, extract::{Path, State}};
use uuid::Uuid;
use anyhow::{Result};
use colored::Colorize;

use crate::{AppState, HTTPError, RequestData, middleware::authentication_middleware::authenticate_user, resources::{access_policy::AccessPolicy, server_log_entry::{InitialServerLogEntryProperties, ServerLogEntry, ServerLogEntryLevel}}};

#[axum::debug_handler]
async fn get_access_policy(
  Path(access_policy_id): Path<String>,
  State(state): State<AppState>, 
  Extension(request_data): Extension<RequestData>
) -> Result<Json<AccessPolicy>, HTTPError> {

  // Make sure the access policy exists.
  let http_request_id = request_data.http_request.id;
  let mut postgres_client = state.database_pool.get().await.map_err(|error| {
    
    let http_error = HTTPError::InternalServerError(Some(error.to_string()));
    eprintln!("{}", format!("Failed to get database connection, so the log cannot be saved. Printing to the console: {}", error).red());
    return http_error;

  })?;
  let access_policy_id = Uuid::parse_str(&access_policy_id).map_err(|_| {
      
    let http_error = HTTPError::BadRequestError(Some("You must provide a valid UUID for the access policy ID.".to_string()));
    ServerLogEntry::from_http_error(&http_error, http_request_id, &mut postgres_client);
    return http_error;

  })?;
  
  let http_request = request_data.http_request;

  ServerLogEntry::create_trace_log(&format!("Getting access policy {}...", access_policy_id), Some(http_request.id), &mut postgres_client).await;
  
  let access_policy = AccessPolicy::get_by_id(&access_policy_id, &mut postgres_client).await.map_err(|error| {

    let http_error = match error.downcast_ref::<HTTPError>() {
      Some(error) => error.clone(),
      None => HTTPError::InternalServerError(Some(error.to_string()))
    };
    ServerLogEntry::from_http_error(&http_error, http_request_id, &mut postgres_client);

    return http_error;

  })?;

  // Verify the principal has permission to get the access policy.
  ServerLogEntry::create(&InitialServerLogEntryProperties {
    message: format!("Verifying principal's permissions to get access policy {}...", access_policy_id),
    http_request_id: Some(http_request.id),
    level: ServerLogEntryLevel::Trace
  }, &mut postgres_client, true).await;

  return Ok(Json(access_policy));
  /*
  
  const { user, app, server, httpRequest } = response.locals;
  const { accessPolicyID } = request.params;

  await ServerLogEntry.create({
    message: `Getting access policy ${accessPolicyID}...`,
    httpRequestID: httpRequest.id,
    level: ServerLogEntryLevel.Trace
  }, server.pool, true);
  const accessPolicy = await AccessPolicy.getByID(accessPolicyID, server.pool);

  await ServerLogEntry.create({
    message: `Verifying principal's permissions to get access policy ${accessPolicy.id}...`,
    httpRequestID: httpRequest.id,
    level: ServerLogEntryLevel.Trace
  }, server.pool, true);
  const accessPolicyScopeData = await accessPolicy.getScopeData();
  const principal = app ?? user;
  HTTPTypeGuard.assertPrincipal(principal);
  const getAccessPolicyAction = await Action.getPreDefinedActionByName("slashstep.accessPolicies.get", server.pool);
  await principal.verifyPermissions({Action, AccessPolicy, Role, RoleMembership}, getAccessPolicyAction.id, accessPolicyScopeData);

  const includedResources: AccessPolicyIncludedResourceClassMap = {};
  const { include } = request.query;

  if (include) {

    await ServerLogEntry.create({
      message: `Getting included resources for access policy ${accessPolicy.id}...`,
      httpRequestID: httpRequest.id,
      level: ServerLogEntryLevel.Trace
    }, server.pool, true);

    const addResourceClass = (resourceType: string) => {

      switch (resourceType) {

        case "scopedAction":
          includedResources.scopedAction = Action;
          break;
        
        case "scopedApp":
          includedResources.scopedApp = App;
          break;
        
        case "scopedGroup":
          includedResources.scopedGroup = Group;
          break;
        
        case "scopedItem":
          includedResources.scopedItem = Item;
          break;
        
        case "scopedMilestone":
          includedResources.scopedMilestone = Milestone;
          break;
        
        case "scopedProject":
          includedResources.scopedProject = Project;
          break;
        
        case "scopedRole":
          includedResources.scopedRole = Role;
          break;
        
        case "scopedUser":
          includedResources.scopedUser = User;
          break;
        
        case "scopedWorkspace":
          includedResources.scopedWorkspace = Workspace;
          break;

        default:
          throw new BadRequestError(`include query must be "scopedAction", "scopedApp", "scopedGroup", "scopedItem", "scopedMilestone", "scopedProject", "scopedRole", "scopedUser", "scopedWorkspace", or excluded.`);

      }

    }

    if (typeof(include) === "string") {

      addResourceClass(include);

    } else if (include instanceof Array) {

      for (const resourceType of include) {

        if (typeof(resourceType) !== "string") {

          throw new BadRequestError("include query must be an array of strings.");

        }

        addResourceClass(resourceType);

      }

    }

  }

  await ActionLogEntry.create({
    actorType: principal.resourceType,
    actorUserID: principal.resourceType === "User" ? principal.id : null,
    actorAppID: principal.resourceType === "App" ? principal.id : null,
    httpRequestID: httpRequest.id,
    actionID: getAccessPolicyAction.id,
    targetResourceType: "AccessPolicy",
    targetAccessPolicyID: accessPolicy.id
  }, server.pool);

  await ServerLogEntry.create({
    message: `Successfully returned access policy ${accessPolicy.id}.`,
    httpRequestID: httpRequest.id,
    level: ServerLogEntryLevel.Success
  }, server.pool, true);

  response.json(accessPolicy);

  await httpRequest.update({
    statusCode: 200
  });
  
  */

}

async fn patch_access_policy() {


}

async fn delete_access_policy() {

}

pub fn get_router() -> Router<AppState> {

  let router = Router::<AppState>::new()
    .layer(axum::middleware::from_fn(authenticate_user))
    .route("/", axum::routing::get(get_access_policy))
    .route("/{access_policy_id}", axum::routing::patch(patch_access_policy))
    .route("/{access_policy_id}", axum::routing::delete(delete_access_policy));

  return router;

}

#[cfg(test)]
#[path = "./{access_policy_id}.tests.rs"]
mod tests;