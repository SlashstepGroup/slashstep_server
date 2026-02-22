INSERT INTO configurations (
  name,
  description,
  value_type
) VALUES (
  $1,
  $2,
  $3
) RETURNING *;