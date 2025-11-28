use anyhow::Result;

pub struct AppAuthorization {}

impl AppAuthorization {

  /// Initializes the app_authorizations table.
  pub async fn initialize_app_authorizations_table(postgres_client: &mut deadpool_postgres::Client) -> Result<()> {

    let query = include_str!("../queries/app-authorizations/initialize-app-authorizations-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}