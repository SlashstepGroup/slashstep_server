use anyhow::Result;

pub struct AppCredential {}

impl AppCredential {

  /// Initializes the app_credentials table.
  pub async fn initialize_app_credentials_table(postgres_client: &mut deadpool_postgres::Client) -> Result<()> {

    let query = include_str!("../queries/app-credentials/initialize-app-credentials-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}