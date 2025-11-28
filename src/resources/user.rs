/**
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 Beastslash LLC
 * 
 */

use std::net::IpAddr;
use anyhow::{Result, anyhow};
use postgres::error::SqlState;
use postgres_types::ToSql;
use uuid::Uuid;

use crate::HTTPError;

pub struct User {

  /// The user's ID.
  pub id: Uuid,

  /// The user's username, if applicable. Only non-anonymous users have a username.
  pub username: Option<String>,

  /// The user's display name, if applicable. Only non-anonymous users have a display name.
  pub display_name: Option<String>,

  /// The user's hashed password, if applicable. Only non-anonymous users have a hashed password.
  hashed_password: Option<String>,

  /// Whether the user is anonymous.
  pub is_anonymous: bool,

  /// The user's IP address, if applicable. Only anonymous users have an IP address.
  pub ip_address: Option<IpAddr>

}

pub struct InitialUserProperties {

  /// The user's username, if applicable. Only non-anonymous users have a username.
  pub username: Option<String>,

  /// The user's display name, if applicable. Only non-anonymous users have a display name.
  pub display_name: Option<String>,

  /// The user's hashed password, if applicable. Only non-anonymous users have a hashed password.
  pub hashed_password: Option<String>,

  /// Whether the user is anonymous.
  pub is_anonymous: bool,

  /// The user's IP address, if applicable. Only anonymous users have an IP address.
  pub ip_address: Option<IpAddr>

}

impl User {

  /// Creates a new user.
  pub async fn create(initial_properties: &InitialUserProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self> {

    // Insert the access policy into the database.
    let query = include_str!("../queries/users/insert-user-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.username,
      &initial_properties.display_name,
      &initial_properties.hashed_password,
      &initial_properties.is_anonymous,
      &initial_properties.ip_address
    ];
    let row = postgres_client.query_one(query, parameters).await.map_err(|error| match error.as_db_error() {

      Some(db_error) => match db_error.code() {

        &SqlState::UNIQUE_VIOLATION => anyhow!(HTTPError::ConflictError(Some(String::from("A user with the same username already exists.")))),
        
        _ => anyhow!(error)

      },

      None => anyhow!(error)

    })?;

    // Return the action.
    let user = User {
      id: row.get("id"),
      username: row.get("username"),
      display_name: row.get("display_name"),
      hashed_password: row.get("hashed_password"),
      is_anonymous: row.get("is_anonymous"),
      ip_address: row.get("ip_address")
    };

    return Ok(user);

  }

  /// Initializes the users table.
  pub async fn initialize_users_table(postgres_client: &mut deadpool_postgres::Client) -> Result<()> {

    let query = include_str!("../queries/users/initialize-users-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

  pub fn get_hashed_password(&self) -> &str {

    let hashed_password = self.hashed_password.as_ref().expect("User does not have a hashed password.");
    return &hashed_password;

  }

}