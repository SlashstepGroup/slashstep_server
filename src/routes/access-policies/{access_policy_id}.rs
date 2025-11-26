use axum::{Router, http::StatusCode};

async fn get_access_policy() {

}

async fn patch_access_policy() {


}

async fn delete_access_policy() {

}

pub fn get_router() -> Router {

  let mut router = Router::new();
  router = router.route("/access-policies/{access_policy_id}", axum::routing::get(get_access_policy));
  router = router.route("/access-policies/{access_policy_id}", axum::routing::patch(patch_access_policy));
  router = router.route("/access-policies/{access_policy_id}", axum::routing::delete(delete_access_policy));
  return router;

}

#[cfg(test)]
#[path = "./{access_policy_id}.tests.rs"]
mod tests;