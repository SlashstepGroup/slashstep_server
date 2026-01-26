use axum::Router;

use crate::{AppState, middleware::authentication_middleware};

#[path = "./{app_id}/mod.rs"]
mod app_id;

pub fn get_router(state: AppState) -> Router<AppState> {

  let router = Router::<AppState>::new()
    .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
    .merge(app_id::get_router(state.clone()));
  return router;

}