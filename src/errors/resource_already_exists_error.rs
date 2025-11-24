use std::fmt;
use std::error::Error;

/// An error that occurs when a resource already exists.
#[derive(Debug, Eq, PartialEq)]
pub struct ResourceAlreadyExistsError {

  /// The type of the resource.
  pub resource_type: String,

}

impl Error for ResourceAlreadyExistsError {}

impl fmt::Display for ResourceAlreadyExistsError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "That {} already exists.", self.resource_type.to_lowercase())
  }
}