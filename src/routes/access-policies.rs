use axum::Router;

use crate::AppState;

#[path = "./access-policies/{access_policy_id}.rs"]
mod access_policy_id;

async fn list_access_policies() {

}

pub fn get_router() -> Router<AppState> {

  let mut router = Router::<AppState>::new();
  router = router.route("/", axum::routing::get(list_access_policies));
  router = router.nest("/{access_policy_id}", access_policy_id::get_router());
  return router;

}

#[cfg(test)]
#[path = "./access-policies.tests.rs"]
mod tests;