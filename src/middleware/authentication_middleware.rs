use axum::{http::{StatusCode}, middleware::Next, response::Response, extract::Request};

pub async fn authenticate_user(request: Request, next: Next) -> Result<Response, StatusCode> {
  // Perform actions before the handler
  println!("Request received: {}", request.uri());

  // Call the next service in the stack (the handler or next middleware)
  let response = next.run(request).await;

  // Perform actions after the handler
  println!("Response status: {}", response.status());

  Ok(response)
}

pub async fn authenticate_app(request: Request, next: Next) -> Result<Response, StatusCode> {
  // Perform actions before the handler
  
  println!("Request received: {}", request.uri());

  // Call the next service in the stack (the handler or next middleware)
  let response = next.run(request).await;

  // Perform actions after the handler
  println!("Response status: {}", response.status());

  return Ok(response);
}