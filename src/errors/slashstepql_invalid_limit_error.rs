use std::fmt;
use std::error::Error;

/// An error that occurs when a resource does not exist.
#[derive(Debug)]
pub struct SlashstepQLInvalidLimitError {

  pub limit_string: String,
  
  pub maximum_limit: Option<i64>

}

impl Error for SlashstepQLInvalidLimitError {}

impl fmt::Display for SlashstepQLInvalidLimitError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Invalid limit \"{}\" in filter query. It must be a non-negative integer{}.", self.limit_string, if let Some(maximum_limit) = self.maximum_limit { format!(" and must be less than or equal to {}", maximum_limit) } else { "".to_string() })
  }
}