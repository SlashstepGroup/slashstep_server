#[cfg(test)]
mod tests;

use std::{fmt::Display, str::FromStr};

use postgres_types::{FromSql, ToSql};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use strum::EnumIter;
use uuid::Uuid;
use crate::{resources::{DeletableResource, ResourceError, access_policy::IndividualPrincipal, configuration::ConfigurationValueType}, utilities::slashstepql::{self, SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter, SlashstepQLSanitizeFunctionOptions}};

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] = &[
  "id",
  "configuration_id",
  "parent_resource_type",
  "parent_configuration_id",
  "value_type",
  "text_value",
  "number_value",
  "boolean_value"
];
pub const UUID_QUERY_KEYS: &[&str] = &[
  "id",
  "configuration_id",
  "parent_configuration_id"
];
pub const RESOURCE_NAME: &str = "ConfigurationValue";
pub const DATABASE_TABLE_NAME: &str = "configuration_values";
pub const GET_RESOURCE_ACTION_NAME: &str = "slashstep.configurationValues.get";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, EnumIter, FromSql, ToSql, Default)]
#[postgres(name = "configuration_value_parent_resource_type")]
pub enum ConfigurationValueParentResourceType {
  Configuration,
  #[default]
  Server
}

impl Display for ConfigurationValueParentResourceType {

  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

    match self {

      ConfigurationValueParentResourceType::Configuration => write!(f, "Configuration"),
      ConfigurationValueParentResourceType::Server => write!(f, "Server")

    }

  }

}

impl FromStr for ConfigurationValueParentResourceType {

  type Err = String;

  fn from_str(s: &str) -> Result<Self, Self::Err> {

    match s {

      "Configuration" => Ok(ConfigurationValueParentResourceType::Configuration),
      "Server" => Ok(ConfigurationValueParentResourceType::Server),
      _ => Err(format!("\"{}\" is not a valid ConfigurationValueParentResourceType.", s))

    }

  }

}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InitialConfigurationValueProperties {

  /// The configuration value's configuration ID.
  pub configuration_id: Uuid,

  /// The configuration value's parent resource type.
  pub parent_resource_type: ConfigurationValueParentResourceType,

  /// The configuration value's parent configuration ID, if applicable.
  pub parent_configuration_id: Option<Uuid>,

  /// The configuration value's value type.
  pub value_type: ConfigurationValueType,

  /// The configuration value's text value, if applicable.
  pub text_value: Option<String>,

  /// The configuration value's number value, if applicable.
  pub number_value: Option<Decimal>,

  /// The configuration value's boolean value, if applicable.
  pub boolean_value: Option<bool>

}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InitialConfigurationValuePropertiesWithoutConfigurationID {
  
  /// The configuration value's parent resource type.
  pub parent_resource_type: ConfigurationValueParentResourceType,

  /// The configuration value's parent configuration ID, if applicable.
  pub parent_configuration_id: Option<Uuid>,

  /// The configuration value's value type.
  pub value_type: ConfigurationValueType,

  /// The configuration value's text value, if applicable.
  pub text_value: Option<String>,

  /// The configuration value's number value, if applicable.
  pub number_value: Option<Decimal>,

  /// The configuration value's boolean value, if applicable.
  pub boolean_value: Option<bool>

}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EditableConfigurationValueProperties {

  /// The configuration value's text value, if applicable.
  pub text_value: Option<String>,

  /// The configuration value's number value, if applicable.
  pub number_value: Option<Decimal>,

  /// The configuration value's boolean value, if applicable.
  pub boolean_value: Option<bool>

}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigurationValue {

  /// The configuration value's ID.
  pub id: Uuid,
  
  /// The configuration value's configuration ID.
  pub configuration_id: Uuid,

  /// The configuration value's parent resource type.
  pub parent_resource_type: ConfigurationValueParentResourceType,

  /// The configuration value's parent configuration ID, if applicable.
  pub parent_configuration_id: Option<Uuid>,

  /// The configuration value's value type.
  pub value_type: ConfigurationValueType,

  /// The configuration value's text value, if applicable.
  pub text_value: Option<String>,

  /// The configuration value's number value, if applicable.
  pub number_value: Option<Decimal>,

  /// The configuration value's boolean value, if applicable.
  pub boolean_value: Option<bool>

}

impl ConfigurationValue {

  fn add_parameter<T: ToSql + Sync + Clone + Send + 'static>(mut parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>>, mut query: String, key: &str, parameter_value: Option<&T>) -> (Vec<Box<dyn ToSql + Sync + Send>>, String) {

    let parameter_value = parameter_value.and_then(|parameter_value| Some(parameter_value.clone()));
    if let Some(parameter_value) = parameter_value {

      query.push_str(format!("{}{} = ${}", if parameter_boxes.len() > 0 { ", " } else { "" }, key, parameter_boxes.len() + 1).as_str());
      parameter_boxes.push(Box::new(parameter_value));

    }
    
    return (parameter_boxes, query);

  }
  
  /// Counts the number of configuration_values based on a query.
  pub async fn count(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<i64, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: None,
      maximum_limit: None,
      should_ignore_limit: true,
      should_ignore_offset: true
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, &RESOURCE_NAME, &DATABASE_TABLE_NAME, &GET_RESOURCE_ACTION_NAME, true);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query and return the count.
    let database_client = database_pool.get().await?;
    let rows = database_client.query_one(&query, &parameters).await?;
    let count = rows.get(0);
    return Ok(count);

  }

  /// Gets a configuration by its ID.
  pub async fn get_by_id(id: &Uuid, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/configuration_values/get_configuration_value_row_by_id.sql");
    let row = match database_client.query_opt(query, &[&id]).await {

      Ok(row) => match row {

        Some(row) => row,

        None => return Err(ResourceError::NotFoundError(format!("A configuration with the ID \"{}\" does not exist.", id)))

      },

      Err(error) => return Err(ResourceError::PostgresError(error))

    };

    let configuration = Self::convert_from_row(&row);

    return Ok(configuration);

  }

  /// Converts a row into a configuration.
  fn convert_from_row(row: &postgres::Row) -> Self {

    return ConfigurationValue {
      id: row.get("id"),
      configuration_id: row.get("configuration_id"),
      parent_resource_type: row.get("parent_resource_type"),
      parent_configuration_id: row.get("parent_configuration_id"),
      value_type: row.get("value_type"),
      text_value: row.get("text_value"),
      number_value: row.get("number_value"),
      boolean_value: row.get("boolean_value")
    };

  }

  /// Initializes the configuration_values table.
  pub async fn initialize_resource_table(database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/configuration_values/initialize_configuration_values_table.sql");
    database_client.execute(query, &[]).await?;
    return Ok(());

  }

  /// Creates a new configuration.
  pub async fn create(initial_properties: &InitialConfigurationValueProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    
    let query = include_str!("../../queries/configuration_values/insert_configuration_value_row.sql");
    let parameters: &[&(dyn ToSql + Sync)] = &[
      &initial_properties.configuration_id,
      &initial_properties.parent_resource_type,
      &initial_properties.parent_configuration_id,
      &initial_properties.value_type,
      &initial_properties.text_value,
      &initial_properties.number_value,
      &initial_properties.boolean_value
    ];
    let database_client = database_pool.get().await?;
    let row = database_client.query_one(query, parameters).await.map_err(|error| {

      return ResourceError::PostgresError(error)
    
    })?;

    // Return the configuration value.
    let configuration_value = Self::convert_from_row(&row);

    return Ok(configuration_value);

  }

  /// Parses a string into a parameter for a slashstepql query.
  fn parse_string_slashstepql_parameters<'a>(key: &'a str, value: &'a str) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError> {

    if UUID_QUERY_KEYS.contains(&key) {

      let uuid = match Uuid::parse_str(value) {
        Ok(uuid) => uuid,
        Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse UUID from \"{}\" for key \"{}\".", value, key)))
      };

      return Ok(Box::new(uuid));

    }

    match key {

      "value_type" => {

        let value_type = match ConfigurationValueType::from_str(value) {

          Ok(value_type) => value_type,
          Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\".", value, key)))

        };
        
        return Ok(Box::new(value_type));

      },

      "parent_resource_type" => {

        let parent_resource_type = match ConfigurationValueParentResourceType::from_str(value) {

          Ok(parent_resource_type) => parent_resource_type,
          Err(_) => return Err(SlashstepQLError::StringParserError(format!("Failed to parse \"{}\" for key \"{}\".", value, key)))

        };
        
        return Ok(Box::new(parent_resource_type));

      },

      _ => {

        return Ok(Box::new(value));

      }

    }

  }

  /// Returns a list of configuration_values based on a query.
  pub async fn list(query: &str, database_pool: &deadpool_postgres::Pool, individual_principal: Option<&IndividualPrincipal>) -> Result<Vec<Self>, ResourceError> {

    // Prepare the query.
    let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
      filter: query.to_string(),
      allowed_fields: ALLOWED_QUERY_KEYS.into_iter().map(|string| string.to_string()).collect(),
      default_limit: Some(DEFAULT_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      maximum_limit: Some(DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
      should_ignore_limit: false,
      should_ignore_offset: false
    };
    let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
    let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(&sanitized_filter, individual_principal, &RESOURCE_NAME, &DATABASE_TABLE_NAME, &GET_RESOURCE_ACTION_NAME, false);
    let parsed_parameters = slashstepql::parse_parameters(&sanitized_filter.parameters, Self::parse_string_slashstepql_parameters)?;
    let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();

    // Execute the query.
    let database_client = database_pool.get().await?;
    let rows = database_client.query(&query, &parameters).await?;
    let configuration_values = rows.iter().map(Self::convert_from_row).collect();
    return Ok(configuration_values);

  }

  /// Updates this configuration and returns a new instance of the configuration.
  pub async fn update(&self, properties: &EditableConfigurationValueProperties, database_pool: &deadpool_postgres::Pool) -> Result<Self, ResourceError> {

    let query = String::from("update configuration_values set ");
    let parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let database_client = database_pool.get().await?;

    database_client.query("begin;", &[]).await?;
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "text_value", properties.text_value.as_ref());
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "number_value", properties.number_value.as_ref());
    let (parameter_boxes, query) = Self::add_parameter(parameter_boxes, query, "boolean_value", properties.boolean_value.as_ref());
    let (mut parameter_boxes, mut query) = (parameter_boxes, query);

    query.push_str(format!(" where id = ${} returning *;", parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(&self.id));
    let parameters: Vec<&(dyn ToSql + Sync)> = parameter_boxes.iter().map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync)).collect();
    let row = database_client.query_one(&query, &parameters).await?;
    database_client.query("commit;", &[]).await?;

    let configuration_value = Self::convert_from_row(&row);
    return Ok(configuration_value);

  }

}

impl DeletableResource for ConfigurationValue {

  /// Deletes this configuration value.
  async fn delete(&self, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceError> {

    let database_client = database_pool.get().await?;
    let query = include_str!("../../queries/configuration_values/delete_configuration_value_row_by_id.sql");
    database_client.execute(query, &[&self.id]).await?;
    return Ok(());

  }

}