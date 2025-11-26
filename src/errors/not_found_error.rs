use serde::Serialize;

#[derive(Serialize)]
pub struct NotFoundError {
  pub message: String
}

impl NotFoundError {

  pub fn new(message: Option<String>) -> Self {

    let message = match message {
      Some(message) => message,
      None => "Not found".to_string()
    };

    NotFoundError {
      message
    }
  }

}