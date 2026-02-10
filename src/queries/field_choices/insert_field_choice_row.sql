INSERT INTO field_choices (
  field_id,
  description,
  type,
  text_value,
  number_value,
  date_time_value
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6
) RETURNING *;