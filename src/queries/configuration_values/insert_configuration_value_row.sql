INSERT INTO configuration_values (
  configuration_id,
  parent_resource_type,
  parent_configuration_id,
  value_type,
  text_value,
  number_value,
  boolean_value
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7
) RETURNING *;