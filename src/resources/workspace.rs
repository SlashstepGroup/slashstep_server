use anyhow::Result;

pub struct Workspace {}

impl Workspace {

  /// Initializes the workspaces table.
  pub async fn initialize_workspaces_table(postgres_client: &mut deadpool_postgres::Client) -> Result<()> {

    let query = include_str!("../queries/workspaces/initialize-workspaces-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}