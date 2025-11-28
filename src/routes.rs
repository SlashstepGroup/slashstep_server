#[path = "./routes/access-policies.rs"]
mod access_policies;

use axum::{Router, response::IntoResponse};
use crate::{AppState, HTTPError};

async fn fallback() -> impl IntoResponse {

  return HTTPError::NotFoundError(None);

}

pub fn get_router() -> Router<AppState> {

  let router = Router::<AppState>::new()
    .nest("/access-policies", access_policies::get_router())
    .fallback(fallback);
  return router;

}