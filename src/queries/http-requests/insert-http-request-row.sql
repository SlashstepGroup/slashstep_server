insert into http_requests (
  method,
  url,
  ip_address,
  headers,
  status_code,
  expiration_date
) values (
  $1,
  $2,
  $3,
  $4,
  $5,
  COALESCE($6, now() + interval '14 days')
) returning *;