use anyhow::Result;

pub struct App {}

impl App {

  /// Initializes the apps table.
  pub async fn initialize_apps_table(postgres_client: &mut deadpool_postgres::Client) -> Result<()> {

    let query = include_str!("../queries/apps/initialize-apps-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}