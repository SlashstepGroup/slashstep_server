use anyhow::Result;

pub struct Group {}

impl Group {

  /// Initializes the groups table.
  pub async fn initialize_groups_table(postgres_client: &mut deadpool_postgres::Client) -> Result<()> {

    let query = include_str!("../queries/groups/initialize-groups-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}