# REST API endpoints for access policies
## List access policies from all scopes
```
GET /access-policies
```

Returns a list of access policies. Authentication may be required if anonymous users lack the permission to use this endpoint.

### Headers
| Header name | Description | Required? |
| :- | :- | :- |
| `Content-Type` | Must be `application/json`. | Yes |

### Query parameters
| Query | Description | Required? |
| :- | :- | :- |
| `query` | A SlashstepQL query to filter and limit results. | Yes |

### Required permissions
* `slashstep.accessPolicies.list` on the server level.

### Optional permissions
* For any applicable resource, the principal must have `slashstep.accessPolicies.get` on the scoped resource level or inherited from a higher level to see the access policy through this endpoint.

## Get an access policy by ID
| Method | Endpoint |
| :- | :- |
| GET | `/access-policies/{access_policy_id}` |

### Headers
None.

### Query parameters
TBA.

### Required permissions
* [`slashstep.accessPolicies.get`](/src/resources/AccessPolicy/README.md#slashstepaccesspoliciesget) on the scoped resource level or inherited from a higher level.

## Update an access policy
| Method | Endpoint |
| :- | :- |
| PATCH | `/access-policies/{access_policy_id}` |

### Required permissions
* [`slashstep.accessPolicies.update`](/src/resources/AccessPolicy/README.md#slashstepaccesspoliciesupdate) on the scoped resource level or inherited from a higher level.

## Delete an access policy
| Method | Endpoint |
| :- | :- |
| DELETE | `/access-policies/{access_policy_id}` |

### Required permissions
* [`slashstep.accessPolicies.delete`](/src/resources/AccessPolicy/README.md#slashstepaccesspoliciesdelete) on the scoped resource level or inherited from a higher level.