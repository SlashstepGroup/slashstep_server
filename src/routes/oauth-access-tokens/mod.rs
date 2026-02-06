/**
 * 
 * Any functionality for /oauth-access-tokens should be handled here.
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2026 Beastslash LLC
 * 
 */

#[cfg(test)]
mod tests;

use std::sync::Arc;
use argon2::{Argon2, PasswordHash, PasswordVerifier, password_hash};
use axum::{Extension, Json, Router, extract::{Query, State}};
use base64::{Engine, engine::general_purpose};
use chrono::{Duration, Utc};
use postgres::error::SqlState;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use crate::{AppState, HTTPError, middleware::{authentication_middleware::get_decoding_key, http_request_middleware}, resources::{DeletableResource, ResourceError, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::{App, AppClientType}, app_authorization::{AppAuthorization, AppAuthorizationAuthorizingResourceType, InitialAppAuthorizationProperties}, app_authorization_credential::{AppAuthorizationCredential, InitialAppAuthorizationCredentialProperties}, http_transaction::HTTPTransaction, oauth_authorization::{EditableOAuthAuthorizationProperties, OAuthAuthorization, OAuthAuthorizationClaims}, server_log_entry::ServerLogEntry}, utilities::route_handler_utilities::{get_action_by_name, get_json_web_token_private_key, get_json_web_token_public_key}};

#[derive(Debug, Deserialize)]
pub struct CreateOAuthAccessTokenQueryParameters {
  pub client_id: String,
  pub client_secret: Option<String>,
  pub code: String,
  pub redirect_uri: String,
  pub code_verifier: Option<String>,
  pub grant_type: String
}

#[derive(Debug, Serialize)]
pub struct OAuthError {
  pub error: String,
  pub error_description: String,
  pub error_uri: Option<String>
}

#[derive(Debug, Serialize)]
pub struct AccessTokenResponseBody {
  pub access_token: String,
  pub token_type: String,
  pub expires_in: i64,
  pub refresh_expires_in: i64,
  pub refresh_token: Option<String>,
  pub state: Option<String>,
  pub app_authorization_credential_id: Uuid
}

impl OAuthError {

  pub fn new(error: &str, error_description: &str, error_uri: Option<&str>) -> Self {

    OAuthError {
      error: error.to_string(),
      error_description: error_description.to_string(),
      error_uri: error_uri.map(|error_uri| error_uri.to_string())
    }

  }

}

pub async fn convert_client_id_string_to_uuid(client_id: &str, http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Uuid, HTTPError> {

  let client_id = match Uuid::parse_str(client_id) {

    Ok(client_id) => client_id,

    Err(_) => {

      let oauth_error = OAuthError::new("invalid_client", "The client ID must be a valid UUID.", None);
      let http_error = match serde_json::to_string_pretty(&oauth_error) {

        Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),

        Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(client_id);

}

pub async fn decode_json_web_token_claims(http_transaction_id: &Uuid, database_pool: &deadpool_postgres::Pool, json_web_token_public_key: &str, token: &str) -> Result<jsonwebtoken::TokenData<OAuthAuthorizationClaims>, HTTPError> {

  let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
  let decoding_key = get_decoding_key(&http_transaction_id, &database_pool, &json_web_token_public_key).await?;
  let decoded_claims = match jsonwebtoken::decode::<OAuthAuthorizationClaims>(token, &decoding_key, &validation) {

    Ok(decoded_claims) => decoded_claims,

    Err(error) => {

      let http_error = match &error.kind() {

        jsonwebtoken::errors::ErrorKind::InvalidToken => HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string())),

        jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claims) => {
         
          ServerLogEntry::warning(&format!("Missing required claim \"{}\" in session token.", claims), Some(&http_transaction_id), &database_pool).await.ok();
          HTTPError::UnauthorizedError(Some("Please provide a valid session token.".to_string()))
          
        },

        _ => HTTPError::InternalServerError(Some(error.to_string()))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction_id), &database_pool).await.ok();
      return Err(http_error);

    }

  };

  return Ok(decoded_claims);

}

/// POST /users/{user_id}/oauth-authorizations
/// 
/// Creates an OAuth authorization for a user.
#[axum::debug_handler]
async fn handle_create_oauth_access_token_request(
  State(state): State<AppState>, 
  Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
  Query(query_parameters): Query<CreateOAuthAccessTokenQueryParameters>,
) -> Result<(StatusCode, Json<AccessTokenResponseBody>), HTTPError> {
  
  let http_transaction = http_transaction.clone();

  ServerLogEntry::trace(format!("Converting client ID \"{}\" to UUID...", query_parameters.client_id).as_str(), Some(&http_transaction.id), &state.database_pool).await.ok();
  let client_id = convert_client_id_string_to_uuid(&query_parameters.client_id, &http_transaction.id, &state.database_pool).await?;

  ServerLogEntry::trace(format!("Getting app {}...", client_id).as_str(), Some(&http_transaction.id), &state.database_pool).await.ok();
  let app = match App::get_by_id(&client_id, &state.database_pool).await {

    Ok(app) => app,

    Err(error) => {
      
      let http_error = match error {

        ResourceError::NotFoundError(_) => {

          let oauth_error = OAuthError::new("invalid_client", "The client ID or client secret is incorrect.", None);
          let http_error = match serde_json::to_string_pretty(&oauth_error) {

            Ok(http_error) => HTTPError::UnauthorizedError(Some(http_error)),

            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

          };

          http_error

        },

        _ => HTTPError::InternalServerError(Some(format!("Failed to get app {}: {:?}", client_id, error)))

      };

      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  if app.client_type == AppClientType::Confidential {

    ServerLogEntry::trace("Verifying client secret is present...", Some(&http_transaction.id), &state.database_pool).await.ok();
    let client_secret = match query_parameters.client_secret {

      Some(client_secret) => client_secret,

      None => {

        let oauth_error = OAuthError::new("invalid_client", "The client ID or client secret is incorrect.", None);
        let http_error = match serde_json::to_string_pretty(&oauth_error) {

          Ok(http_error) => HTTPError::UnauthorizedError(Some(http_error)),

          Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

        };

        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    };

    ServerLogEntry::trace("Converting client secret hash string to Argon2 password hash...", Some(&http_transaction.id), &state.database_pool).await.ok();
    let client_secret_hash_string = match app.client_secret_hash {

      Some(client_secret_hash_string) => client_secret_hash_string,

      None => {

        let http_error = HTTPError::InternalServerError(Some("The app is confidential, but the client secret hash is not set. Database table constraints should have prevented this from happening.".to_string()));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }
      
    };

    let client_secret_hash = match PasswordHash::new(&client_secret_hash_string) {

      Ok(client_secret_hash) => client_secret_hash,

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to parse client secret hash: {:?}", error)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    };

    ServerLogEntry::trace("Verifying client secret is correct...", Some(&http_transaction.id), &state.database_pool).await.ok();
    match Argon2::default().verify_password(client_secret.as_bytes(), &client_secret_hash) {

      Ok(_) => {},

      Err(error) => {

        let http_error = match error {

          password_hash::Error::Password => HTTPError::UnauthorizedError(Some("The client ID or client secret is incorrect.".to_string())),

          _ => HTTPError::InternalServerError(Some(format!("Failed to verify client secret: {:?}", error)))

        };
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    }

  }

  let app_authorization: AppAuthorization;
  if query_parameters.grant_type == "authorization_code" {

    // Decode and verify the authorization code.
    ServerLogEntry::trace("Decoding and verifying authorization code...", Some(&http_transaction.id), &state.database_pool).await.ok();
    let json_web_token_public_key = get_json_web_token_public_key(&http_transaction.id, &state.database_pool).await?;
    let decoded_claims = decode_json_web_token_claims(&http_transaction.id, &state.database_pool, &json_web_token_public_key, &query_parameters.code).await?;

    // Authorization codes are single-use (https://datatracker.ietf.org/doc/html/rfc6749#section-10.5), 
    // so we should add a usage date to the OAuth authorization to prevent it from being used multiple times.
    ServerLogEntry::trace(&format!("Converting OAuth authorization ID \"{}\" to UUID...", decoded_claims.claims.jti), Some(&http_transaction.id), &state.database_pool).await.ok();
    let oauth_authorization_id = match Uuid::parse_str(&decoded_claims.claims.jti) {

      Ok(oauth_authorization_id) => oauth_authorization_id,

      Err(_) => {

        let oauth_error = OAuthError::new("invalid_grant", "The authorization code is invalid.", None);
        let http_error = match serde_json::to_string_pretty(&oauth_error) {

          Ok(oauth_error) => HTTPError::UnauthorizedError(Some(oauth_error)),

          Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

        };
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    };

    ServerLogEntry::trace(&format!("Getting OAuth authorization {}...", decoded_claims.claims.jti), Some(&http_transaction.id), &state.database_pool).await.ok();
    let oauth_authorization = match OAuthAuthorization::get_by_id(&oauth_authorization_id, &state.database_pool).await {

      Ok(oauth_authorization) => oauth_authorization,

      Err(error) => {

        let http_error = match error {

          ResourceError::NotFoundError(_) => HTTPError::UnauthorizedError(Some("The authorization code is invalid.".to_string())),

          ResourceError::PostgresError(error) => match error.as_db_error() {

            Some(db_error) => match db_error.code() {

              &SqlState::NO_DATA_FOUND => HTTPError::UnauthorizedError(Some("The authorization code is invalid.".to_string())),

              _ => HTTPError::InternalServerError(Some(error.to_string()))

            },

            None => HTTPError::InternalServerError(Some(error.to_string()))

          },

          _ => HTTPError::InternalServerError(Some(error.to_string()))

        };

        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    };

    ServerLogEntry::trace(&format!("Ensuring OAuth authorization code hasn't been reused..."), Some(&http_transaction.id), &state.database_pool).await.ok();
    if oauth_authorization.usage_date.is_some() {

      // Delete any app authorizations that are associated with the OAuth authorization.
      let delete_app_authorizations_action = get_action_by_name("slashstep.appAuthorizations.delete", &http_transaction, &state.database_pool).await?;
      loop {

        let app_authorizations = match AppAuthorization::list(&format!("oauth_authorization_id = \"{}\"", oauth_authorization_id), &state.database_pool, None).await {

          Ok(app_authorizations) => app_authorizations,

          Err(error) => {

            let http_error = HTTPError::InternalServerError(Some(format!("Failed to list app authorizations: {:?}", error)));
            ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
            return Err(http_error);

          }

        };

        if app_authorizations.len() == 0 {

          break;

        }

        for app_authorization in app_authorizations {

          ServerLogEntry::trace(&format!("Deleting app authorization {}...", app_authorization.id), Some(&http_transaction.id), &state.database_pool).await.ok();

          ActionLogEntry::create(&InitialActionLogEntryProperties {
            action_id: delete_app_authorizations_action.id,
            http_transaction_id: Some(http_transaction.id),
            actor_type: ActionLogEntryActorType::Server,
            target_resource_type: ActionLogEntryTargetResourceType::AppAuthorization,
            target_app_authorization_id: Some(app_authorization.id),
            reason: Some("OAuth authorization code was reused. Deleting this app authorization in accordance with the OAuth 2.0 specification.".to_string()),
            ..Default::default()
          }, &state.database_pool).await.ok();

          match app_authorization.delete(&state.database_pool).await {

            Ok(_) => {},

            Err(error) => {

              let http_error = HTTPError::InternalServerError(Some(format!("Failed to delete app authorization: {:?}", error)));
              ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
              return Err(http_error);

            }

          }

        }

      }

      let oauth_error = OAuthError::new("invalid_grant", "The authorization code is invalid.", None);
      let http_error = match serde_json::to_string_pretty(&oauth_error) {

        Ok(oauth_error) => HTTPError::BadRequestError(Some(oauth_error)),

        Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

      };
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

    ServerLogEntry::trace(&format!("Updating OAuth authorization {} with a usage date...", oauth_authorization.id), Some(&http_transaction.id), &state.database_pool).await.ok();
    match oauth_authorization.update(&EditableOAuthAuthorizationProperties {
      usage_date: Some(Utc::now())
    }, &state.database_pool).await {

      Ok(_) => {},

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to update OAuth authorization: {:?}", error)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);

      }

    }

    // Verify the code challenge if applicable.
    if let Some(code_challenge) = &oauth_authorization.code_challenge {

      ServerLogEntry::trace("Verifying code_verifier...", Some(&http_transaction.id), &state.database_pool).await.ok();

      if oauth_authorization.code_challenge_method.is_none_or(|code_challenge_method| code_challenge_method != "S256") {
        
        let oauth_error = OAuthError::new("invalid_request", "The code challenge method must be \"S256\".", None);
        let http_error = match serde_json::to_string_pretty(&oauth_error) {
          
          Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),
          
          Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))
          
        };
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);
        
      }

      let code_verifier = match query_parameters.code_verifier {
        
        Some(code_verifier) => code_verifier,
        
        None => {
          
          let oauth_error = OAuthError::new("invalid_request", "The code verifier is required.", None);
          let http_error = match serde_json::to_string_pretty(&oauth_error) {
            
            Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),
            
            Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))
            
          };
          ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
          return Err(http_error);
          
        }

      };

      let hashed_code_verifier = Sha256::digest(code_verifier.as_bytes());
      let base64_hashed_code_verifier = general_purpose::STANDARD.encode(hashed_code_verifier);
      if oauth_authorization.code_challenge != Some(base64_hashed_code_verifier) {
        
        let oauth_error = OAuthError::new("invalid_grant", "The code verifier is incorrect.", None);
        let http_error = match serde_json::to_string_pretty(&oauth_error) {
          
          Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),
          
          Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))
          
        };
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);
        
      }

    }

    ServerLogEntry::trace("Creating app authorization...", Some(&http_transaction.id), &state.database_pool).await.ok();
    app_authorization = match AppAuthorization::create(&InitialAppAuthorizationProperties {
      app_id: app.id,
      authorizing_resource_type: AppAuthorizationAuthorizingResourceType::User,
      authorizing_user_id: Some(oauth_authorization.authorizing_user_id),
      ..Default::default()
    }, &state.database_pool).await {

      Ok(app_authorization) => app_authorization,
      
      Err(error) => {
        
        let http_error = HTTPError::InternalServerError(Some(format!("Failed to create app authorization: {:?}", error)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error);
        
      }

    };

    let create_app_authorizations_action = get_action_by_name("slashstep.appAuthorizations.create", &http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(&InitialActionLogEntryProperties {
      action_id: create_app_authorizations_action.id,
      http_transaction_id: Some(http_transaction.id),
      actor_type: ActionLogEntryActorType::App,
      actor_user_id: None,
      actor_app_id: Some(app.id),
      target_resource_type: ActionLogEntryTargetResourceType::AppAuthorization,
      target_app_authorization_id: Some(app_authorization.id),
      reason: Some("OAuth authorization code was used to create an app authorization.".to_string()),
      ..Default::default()
    }, &state.database_pool).await.ok();

  } else if query_parameters.grant_type == "refresh_token" {

    // TODO: Implement refresh token grant type.
    return Err(HTTPError::NotImplementedError(Some("Refresh token grant type is not implemented.".to_string())));

  } else {

    let oauth_error = OAuthError::new("unsupported_grant_type", "The grant type is not supported.", None);
    let http_error = match serde_json::to_string_pretty(&oauth_error) {

      Ok(http_error) => HTTPError::BadRequestError(Some(http_error)),

      Err(error) => HTTPError::InternalServerError(Some(format!("Failed to serialize OAuth error: {:?}", error)))

    };
    ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
    return Err(http_error);

  }

  ServerLogEntry::trace("Creating app authorization credential...", Some(&http_transaction.id), &state.database_pool).await.ok();
  let app_authorization_credential = match AppAuthorizationCredential::create(&InitialAppAuthorizationCredentialProperties {
    app_authorization_id: app_authorization.id,
    access_token_expiration_date: Utc::now() + Duration::hours(8),
    refresh_token_expiration_date: Utc::now() + Duration::days(30),
    refreshed_app_authorization_credential_id: None
  }, &state.database_pool).await {

    Ok(app_authorization_credential) => app_authorization_credential,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to create app authorization credential: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let json_web_token_private_key = get_json_web_token_private_key(&http_transaction.id, &state.database_pool).await?;
  let access_token = match app_authorization_credential.generate_access_token(&json_web_token_private_key) {

    Ok(access_token) => access_token,

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to generate access token: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };
  let refresh_token = match app_authorization_credential.generate_refresh_token(&json_web_token_private_key) {

    Ok(refresh_token) => Some(refresh_token),

    Err(error) => {

      let http_error = HTTPError::InternalServerError(Some(format!("Failed to generate refresh token: {:?}", error)));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error);

    }

  };

  let access_token_response_body = AccessTokenResponseBody {
    access_token,
    token_type: "Bearer".to_string(),
    expires_in: Utc::now().signed_duration_since(app_authorization_credential.access_token_expiration_date).num_seconds(),
    refresh_expires_in: Utc::now().signed_duration_since(app_authorization_credential.refresh_token_expiration_date).num_seconds(),
    refresh_token,
    state: None,
    app_authorization_credential_id: app_authorization_credential.id
  };

  return Ok((StatusCode::CREATED, Json(access_token_response_body)));

}

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .route("/oauth-access-tokens", axum::routing::post(handle_create_oauth_access_token_request))
    .layer(axum::middleware::from_fn_with_state(state.clone(), http_request_middleware::create_http_request));
  return router;

}