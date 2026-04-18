# @marianmeres/rbac

[![JSR version](https://jsr.io/badges/@marianmeres/rbac)](https://jsr.io/@marianmeres/rbac)
[![NPM version](https://img.shields.io/npm/v/@marianmeres/rbac.svg)](https://www.npmjs.com/package/@marianmeres/rbac)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Lightweight, type-safe Role-Based Access Control (RBAC) library for managing permissions through roles and groups. Includes optional Attribute-Based Access Control (ABAC) for fine-grained resource and context-based permissions.

## Features

- **Simple API** - Fluent, chainable interface for easy configuration
- **Groups & Roles** - Nested group hierarchy + role-to-group inheritance
- **ABAC Support** - Optional rule chains for conditional access control
- **Multi-role subjects** - `can()` accepts `role: string | string[]`
- **Type-safe** - Full TypeScript support, generic ABAC rule types
- **Serializable** - Export/restore configurations (rules re-added after restore)
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
- **Group** - A reusable set of permissions that roles (and other groups) can inherit from

Roles can have direct permissions and inherit permissions from groups they belong
to. Groups can also inherit from parent groups, forming a hierarchy.

## Quick Start

```ts
import { Rbac } from "@marianmeres/rbac";

const rbac = new Rbac();

// Define groups with shared permissions
rbac
    .addGroup("admins", ["system:admin"])
    .addGroup("editors", ["article:read", "article:update"]);

// Define roles with direct permissions and group memberships
rbac
    .addRole("admin", [], ["admins"])
    .addRole("editor", [], ["editors"])
    .addRole("user", ["article:read"], []);

// Check permissions
rbac.hasPermission("admin", "system:admin");    // true
rbac.hasPermission("editor", "article:update"); // true
rbac.hasPermission("user", "article:update");   // false

// OR check
rbac.hasSomePermission("user", ["article:read", "article:update"]); // true

// AND check
rbac.hasEveryPermission("editor", ["article:read", "article:update"]); // true
```

> **Permission matching is exact.** There is no wildcard expansion — `"article:*"`
> is a literal permission string, not a pattern. If you want wildcard-like
> behavior, model it yourself (e.g., a group granting every concrete permission).

## Group Hierarchy

```ts
rbac
    .addGroup("viewers", ["article:read"])
    .addGroup("editors", ["article:update"])
    .addGroupToGroup("editors", "viewers")  // editors inherit from viewers
    .addRole("editor", [], ["editors"]);

rbac.hasPermission("editor", "article:read");   // true (inherited transitively)
rbac.hasPermission("editor", "article:update"); // true (from editors)
```

Cycles in the group graph are silently tolerated at query time — a group that
(directly or transitively) lists itself as a parent is simply skipped during
traversal.

## API Overview

For complete API documentation with all parameters, return types, and examples,
see [API.md](./API.md).

### Role Management
| Method | Description |
|--------|-------------|
| `addRole(name, permissions?, groups?)` | Create/update a role |
| `removeRole(name)` | Remove a role entirely |
| `removeRolePermissions(name, permissions?)` | Remove specific permissions |
| `hasRole(name)` | Check if a role exists |
| `getRoles()` | Get all role names |
| `getRoleGroups(name, transitive?)` | Groups a role belongs to |

### Group Management
| Method | Description |
|--------|-------------|
| `addGroup(name, permissions?)` | Create/update a group |
| `removeGroup(name)` | Remove a group entirely |
| `removeGroupPermissions(name, permissions?)` | Remove specific permissions |
| `hasGroup(name)` | Check if a group exists |
| `getGroups()` | Get all group names |
| `getGroupRoles(name)` | Roles that directly belong to a group |
| `getGroupParents(name)` | Direct parents of a group |
| `getGroupChildren(name)` | Direct children of a group |

### Role-Group Association
| Method | Description |
|--------|-------------|
| `addRoleToGroup(role, group)` | Add a role to a group |
| `removeRoleFromGroup(role, group)` | Remove a role from a group |
| `addGroupToGroup(child, parent)` | Make a group inherit from another group |
| `removeGroupFromGroup(child, parent)` | Break a group-to-group link |

### Permission Checks
| Method | Description |
|--------|-------------|
| `hasPermission(role, permission)` | Check if a role has a permission |
| `hasSomePermission(role, permissions)` | OR check |
| `hasEveryPermission(role, permissions)` | AND check |
| `getPermissions(role)` | Get all permissions for a role |
| `explainPermission(role, permission)` | Trace how a permission is granted |

### ABAC (Attribute-Based)
| Method | Description |
|--------|-------------|
| `can(subject, permission, resource?, context?)` | Check with optional rule evaluation |
| `addRule(permission, ruleFn)` | Set (replace) the rule chain for a permission |
| `appendRule(permission, ruleFn)` | Append a rule to the chain (AND semantics) |
| `removeRule(permission)` | Remove the rule chain |
| `hasRule(permission)` | Check if a rule chain exists |
| `getRules()` | Permissions with rules attached |
| `getMissingRules()` | Permissions that had rules at dump-time but are missing now |

### Serialization
| Method | Description |
|--------|-------------|
| `dump()` | Export configuration as JSON string |
| `toJSON()` | Get configuration as plain object |
| `Rbac.restore(dump)` | Create instance from dump |
| `new Rbac(dump?)` | Equivalent constructor form |
| `clone()` | Deep copy including rule chains |

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

### Rule chains

Compose multiple conditions per permission with `appendRule` (AND semantics —
all rules must pass):

```ts
rbac
    .addRole("author", ["article:update"])
    .appendRule("article:update", isOwner)
    .appendRule("article:update", isDuringBusinessHours);

rbac.can(subject, "article:update", article, ctx);
// true only if BOTH rules return true
```

`addRule` replaces any existing chain with a single-rule chain.

### Multi-role subjects

```ts
rbac.can({ role: ["author", "reviewer"], id: "u1" }, "article:publish", article);
// Granted if ANY of the listed roles has the permission,
// AND the rule chain (if any) passes.
```

## Persistence

```ts
// Save
const dump = rbac.dump();
localStorage.setItem("rbac-config", dump);

// Restore
const rbac2 = Rbac.restore(localStorage.getItem("rbac-config"));
// or: const rbac2 = new Rbac(localStorage.getItem("rbac-config"));

// Rules are NOT serialized — re-add them after restore.
rbac2.addRule("article:update", ownershipRule);

// Detect forgotten rules (permissions that had rules at dump time)
const missing = rbac2.getMissingRules();
if (missing.length > 0) {
    throw new Error(`Missing rules: ${missing.join(", ")}`);
}
```

## Introspection

```ts
rbac.explainPermission("editor", "article:read");
// {
//   granted: true,
//   source: "group",
//   path: ["editor", "editors", "viewers"]
// }
```

## Notes

- Permission matching is exact (no wildcard expansion)
- Groups must exist before roles or other groups reference them
- Removing a group automatically removes it from all roles and from other groups'
  memberships
- Roles and groups can have multiple parents
- Duplicate permissions are deduplicated (internal `Set`)
- Rule chains run in order; all must return `true` for `can()` to grant access
- Rules are **not serialized** — re-add them after `restore()`. Use
  `getMissingRules()` to detect forgotten rules.

## Upgrade notes (v2.1)

Most changes are additive. Possible compatibility impacts:

- **`RbacGroupInternal` now has a `memberOf: Set<string>` field.** Affects only
  consumers that implement this interface themselves (uncommon).
- **Dump format adds `groups[*].memberOf` and an optional top-level `rules`
  array.** Additive fields — old dumps still restore correctly.
- **`RbacSubject.role` widened to `string | string[]`.** Rule functions that
  did `subject.role === "x"` continue to work when callers pass a string; if
  you start passing an array, handle both cases.
- **`RbacRuleFunction` now has generic parameters with defaults.** Existing
  un-typed usages are unaffected.
- Internally, `#rules` is now `Map<string, RbacRuleFunction[]>` instead of
  `Map<string, RbacRuleFunction>`. Not part of the public API.

## License

MIT
