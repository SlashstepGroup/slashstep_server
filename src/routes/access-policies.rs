use axum::Router;

#[path = "./access-policies/{access_policy_id}.rs"]
mod access_policy_id;

async fn list_access_policies() {

}

pub fn get_router() -> Router {

  let mut router = Router::new();
  router = router.route("/access-policies", axum::routing::get(list_access_policies));
  router = router.merge(access_policy_id::get_router());
  return router;

}