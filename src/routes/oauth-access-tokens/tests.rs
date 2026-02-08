/**
 * 
 * Any test cases for /oauth-access-tokens should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

use std::net::SocketAddr;
use axum_test::TestServer;
use crate::{AppState, get_json_web_token_private_key, initialize_required_tables, predefinitions::{initialize_predefined_actions, initialize_predefined_roles}, resources::{access_policy::ActionPermissionLevel, action::Action}, routes::{oauth_access_tokens::CreateOAuthAccessTokenQueryParameters}, tests::{TestEnvironment, TestSlashstepServerError}};

/// Verifies that the router can return a 201 status code and the created resource.
#[tokio::test]
async fn verify_successful_creation() -> Result<(), TestSlashstepServerError> {

  let test_environment = TestEnvironment::new().await?;
  initialize_required_tables(&test_environment.database_pool).await?;
  initialize_predefined_actions(&test_environment.database_pool).await?;
  initialize_predefined_roles(&test_environment.database_pool).await?;

  // Create dummy resources.
  let json_web_token_private_key = get_json_web_token_private_key().await?;
  let dummy_oauth_authorization = test_environment.create_random_oauth_authorization(None).await?;
  let authorization_code = dummy_oauth_authorization.generate_authorization_code(json_web_token_private_key.as_ref())?;

  // Set up the server and send the request.
  let state = AppState {
    database_pool: test_environment.database_pool.clone(),
  };
  let router = super::get_router(state.clone())
    .with_state(state)
    .into_make_service_with_connect_info::<SocketAddr>();
  let test_server = TestServer::new(router)?;
  let response = test_server.post("/oauth-access-tokens")
    .add_query_params(CreateOAuthAccessTokenQueryParameters {
      client_id: dummy_oauth_authorization.app_id.to_string(),
      code: authorization_code,
      grant_type: "authorization_code".to_string(),
      ..Default::default()
    })
    .await;
  
  // Verify the response.
  assert_eq!(response.status_code(), 201);

  // let response_oauth_authorization: CreateOAuthAuthorizationResponseBody = response.json();
  // assert_eq!(initial_oauth_authorization_properties.app_id, response_oauth_authorization.oauth_authorization.app_id);
  // assert_eq!(dummy_user.id, response_oauth_authorization.oauth_authorization.authorizing_user_id);
  // assert_eq!(initial_oauth_authorization_properties.code_challenge, response_oauth_authorization.oauth_authorization.code_challenge);
  // assert_eq!(initial_oauth_authorization_properties.app_id, response_oauth_authorization.app_id);
  // assert_eq!(dummy_user.id, response_oauth_authorization.authorizing_user_id);
  // assert_eq!(initial_oauth_authorization_properties.code_challenge, response_oauth_authorization.code_challenge);

  return Ok(());
  
}