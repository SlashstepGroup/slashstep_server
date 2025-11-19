/**
 * 
 * Programmers: 
 * - Christian Toney (https://christiantoney.com)
 * 
 * © 2025 Beastslash LLC
 * 
 */

pub enum AccessPolicyPermissionLevel {
  None,
  User,
  Editor,
  Admin
}

pub enum AccessPolicyPrinicipalType {

  /// A resource that identifies a user.
  User,

  /// A resource that identifies multiple users, apps, and other groups.
  Group,

  /// A resource that identifies a role.
  Role,

  /// A resource that identifies an app.
  App

}

/// A piece of information that defines the level of access and inheritance for a principal to perform an action.
pub struct AccessPolicy<'a> {

  /// The access policy's ID.
  pub id: &'a str,
  
  /// The action ID that this access policy refers to.
  pub action_id: &'a str,

  pub principal_type: AccessPolicyPrinicipalType

}

pub struct InitialAccessPolicyProperties<'a> {

  pub action_id: &'a str,

  pub principal_type: AccessPolicyPrinicipalType

}

impl<'a> AccessPolicy<'a> {
  
  pub fn new(properties: AccessPolicy<'a>) -> Self {

    AccessPolicy {
      id: properties.id,
      action_id: properties.action_id,
      principal_type: properties.principal_type
    }

  }

  pub fn create(initialProperties: InitialAccessPolicyProperties<'a>) -> Self {


  }

  /// Deletes this access policy.
  pub fn delete(&self) {
    

  }

}