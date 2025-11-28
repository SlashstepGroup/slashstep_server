use std::net::IpAddr;
use anyhow::Result;
use postgres_types::ToSql;
use uuid::Uuid;
use chrono::NaiveDateTime;

#[derive(Debug, Clone)]
pub struct HttpRequest {

  /// The ID of the HTTP request.
  pub id: Uuid,

  /// The HTTP method of the HTTP request.
  pub method: String,

  /// The URL of the HTTP request.
  pub url: String,

  /// The IP address of the HTTP request.
  pub ip_address: IpAddr,

  /// The headers of the HTTP request.
  pub headers: String,

  /// The status code of the HTTP request.
  pub status_code: Option<i32>,

  /// The expiration date of the HTTP request.
  pub expiration_date: Option<NaiveDateTime>

}

pub struct InitialHttpRequestProperties {

  /// The HTTP method of the HTTP request.
  pub method: String,

  /// The URL of the HTTP request.
  pub url: String,

  /// The IP address of the HTTP request.
  pub ip_address: IpAddr,

  /// The headers of the HTTP request.
  pub headers: String,

  /// The status code of the HTTP request.
  pub status_code: Option<i32>,

  /// The expiration date of the HTTP request.
  pub expiration_date: Option<NaiveDateTime>

}

impl HttpRequest {

  pub async fn create(properties: &InitialHttpRequestProperties, postgres_client: &mut deadpool_postgres::Client) -> Result<Self> {

    let query = include_str!("../queries/http-requests/insert-http-request-row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &properties.method,
      &properties.url,
      &properties.ip_address,
      &properties.headers,
      &properties.status_code,
      &properties.expiration_date
    ];
    let row = postgres_client.query_one(query, parameters).await?;

    let http_request = HttpRequest {
      id: row.get("id"),
      method: row.get("method"),
      url: row.get("url"),
      ip_address: row.get("ip_address"),
      headers: row.get("headers"),
      status_code: row.get("status_code"),
      expiration_date: row.get("expiration_date")
    };

    return Ok(http_request);

  }

}