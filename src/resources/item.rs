use anyhow::Result;

pub struct Item {}

impl Item {

  /// Initializes the items table.
  pub async fn initialize_items_table(postgres_client: &mut deadpool_postgres::Client) -> Result<()> {

    let query = include_str!("../queries/items/initialize-items-table.sql");
    postgres_client.execute(query, &[]).await?;
    return Ok(());

  }

}