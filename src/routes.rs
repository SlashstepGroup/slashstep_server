#[path = "./routes/access-policies.rs"]
mod access_policies;

use axum::{Json, Router, http::{StatusCode}, response::IntoResponse};
use crate::errors::not_found_error::NotFoundError;

async fn fallback() -> impl IntoResponse {

  return (StatusCode::NOT_FOUND, Json(NotFoundError::new(None)));

}

pub fn get_router() -> Router {

  let mut router = Router::new();
  router = router.merge(access_policies::get_router());
  router = router.fallback(fallback);
  return router;

}