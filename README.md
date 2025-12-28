# @marianmeres/rbac

[![JSR version](https://jsr.io/badges/@marianmeres/rbac)](https://jsr.io/@marianmeres/rbac)
[![NPM version](https://img.shields.io/npm/v/@marianmeres/rbac.svg)](https://www.npmjs.com/package/@marianmeres/rbac)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Lightweight, type-safe Role-Based Access Control (RBAC) library for managing permissions through roles and groups. Includes optional Attribute-Based Access Control (ABAC) for fine-grained resource and context-based permissions.

## Features

- **Simple API** - Fluent, chainable interface for easy configuration
- **Groups & Roles** - Organize permissions hierarchically with group inheritance
- **ABAC Support** - Optional rule-based conditional access control
- **Type-safe** - Full TypeScript support with strict typing
- **Serializable** - Export and restore configurations as JSON
- **Zero dependencies** - Minimal footprint
- **Runtime agnostic** - Works with Deno, Node.js, and browsers

## Installation

**Deno:**
```sh
deno add jsr:@marianmeres/rbac
```

**Node.js:**
```sh
npm install @marianmeres/rbac
```

## Concepts

- **Permission** - A string representing an action (e.g., `"article:read"`, `"user:delete"`)
- **Role** - A named set of permissions assigned to users (e.g., `"editor"`, `"admin"`)
- **Group** - A reusable set of permissions that roles can inherit from (e.g., `"editors"`)

Roles can have both direct permissions and inherit permissions from groups they belong to.

## Quick Start

```ts
import { Rbac } from "@marianmeres/rbac";

const rbac = new Rbac();

// Define groups with shared permissions
rbac
    .addGroup("admins", ["*:*"])
    .addGroup("editors", ["article:read", "article:update"]);

// Define roles with direct permissions and group memberships
rbac
    .addRole("admin", [], ["admins"])
    .addRole("editor", [], ["editors"])
    .addRole("user", ["article:read"], []);

// Check permissions
rbac.hasPermission("admin", "*:*");             // true
rbac.hasPermission("editor", "article:update"); // true
rbac.hasPermission("user", "article:update");   // false

// Check for any matching permission (OR logic)
const canRead = rbac.hasSomePermission("user", [
    "*:*",
    "article:*",
    "article:read"
]); // true
```

## API Overview

For complete API documentation with all parameters, return types, and examples, see [API.md](./API.md).

### Role Management
| Method | Description |
|--------|-------------|
| `addRole(name, permissions?, groups?)` | Create/update a role |
| `removeRole(name)` | Remove a role entirely |
| `removeRolePermissions(name, permissions?)` | Remove specific permissions |
| `hasRole(name)` | Check if a role exists |
| `getRoles()` | Get all role names |

### Group Management
| Method | Description |
|--------|-------------|
| `addGroup(name, permissions?)` | Create/update a group |
| `removeGroup(name)` | Remove a group entirely |
| `removeGroupPermissions(name, permissions?)` | Remove specific permissions |
| `hasGroup(name)` | Check if a group exists |
| `getGroups()` | Get all group names |

### Role-Group Association
| Method | Description |
|--------|-------------|
| `addRoleToGroup(role, group)` | Add a role to a group |
| `removeRoleFromGroup(role, group)` | Remove a role from a group |

### Permission Checks
| Method | Description |
|--------|-------------|
| `hasPermission(role, permission)` | Check if a role has a permission |
| `hasSomePermission(role, permissions)` | Check if a role has any of the permissions |
| `getPermissions(role)` | Get all permissions for a role |

### ABAC (Attribute-Based)
| Method | Description |
|--------|-------------|
| `can(subject, permission, resource?, context?)` | Check with optional rule evaluation |
| `addRule(permission, ruleFn)` | Add a conditional rule |
| `removeRule(permission)` | Remove a rule |
| `hasRule(permission)` | Check if a rule exists |
| `getRules()` | Get all permissions with rules |

### Serialization
| Method | Description |
|--------|-------------|
| `dump()` | Export configuration as JSON string |
| `Rbac.restore(dump)` | Create instance from dump |
| `toJSON()` | Get configuration as plain object |

## ABAC Example

```ts
// Authors can only edit their own drafts
rbac
    .addRole("author", ["article:update"])
    .addRule("article:update", (subject, resource) => {
        if (subject.role === "author") {
            return resource?.authorId === subject.id && resource?.status === "draft";
        }
        return true; // Other roles can edit anything
    });

// Check with resource attributes
rbac.can(
    { role: "author", id: "user123" },
    "article:update",
    { authorId: "user123", status: "draft" }
); // true
```

## Persistence

```ts
// Save
const dump = rbac.dump();
localStorage.setItem("rbac-config", dump);

// Restore
const rbac2 = Rbac.restore(localStorage.getItem("rbac-config"));

// Note: Rules are NOT serialized - re-add them after restore
rbac2.addRule("article:update", ownershipRule);
```

## Notes

- Permission matching is exact (no wildcard expansion)
- Groups must exist before adding roles to them
- Removing a group automatically removes it from all roles
- Roles can belong to multiple groups
- Duplicate permissions are automatically deduplicated
- Rules are **not serialized** - re-add them after `restore()`

## License

MIT
