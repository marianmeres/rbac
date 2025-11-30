# @marianmeres/rbac

Lightweight, type-safe Role-Based Access Control (RBAC) library for managing permissions through roles and groups. Includes optional Attribute-Based Access Control (ABAC) for fine-grained resource and context-based permissions.

## Features

- **Simple API** - Fluent, chainable interface for easy configuration
- **Groups & Roles** - Organize permissions hierarchically with group inheritance
- **ABAC Support** - Optional rule-based conditional access control for ownership and resource checks
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
- **Group** - A reusable set of permissions that roles can inherit from (e.g., `"editors"`, `"moderators"`)

Roles can have both direct permissions and inherit permissions from groups they belong to.

## Usage

```ts
import { Rbac } from "@marianmeres/rbac";
```

## Quick Start

```ts
const rbac = new Rbac();

// Define groups with shared permissions
rbac
    .addGroup("admins", ["*:*"])  // Wildcard permission
    .addGroup("editors", ["article:read", "article:update"]);

// Define roles with direct permissions and group memberships
rbac
    .addRole("admin", [], ["admins"])           // Inherits from admins
    .addRole("editor", [], ["editors"])         // Inherits from editors
    .addRole("user", ["article:read"], []);     // Direct permission only

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

## API Methods

### Group Management
- `addGroup(name, permissions)` - Create/update a group with permissions
- `removeGroup(name)` - Remove a group entirely
- `removeGroupPermissions(name, permissions)` - Remove specific permissions from a group
- `hasGroup(name)` - Check if a group exists
- `getGroups()` - Get all group names

### Role Management
- `addRole(name, permissions, groups)` - Create/update a role with permissions and group memberships
- `removeRole(name)` - Remove a role entirely
- `removeRolePermissions(name, permissions)` - Remove specific permissions from a role
- `addRoleToGroup(roleName, groupName)` - Add a role to a group
- `removeRoleFromGroup(roleName, groupName)` - Remove a role from a group
- `hasRole(name)` - Check if a role exists
- `getRoles()` - Get all role names

### Permission Checks (RBAC)
- `hasPermission(roleName, permission)` - Check if a role has a specific permission
- `hasSomePermission(roleName, permissions)` - Check if a role has any of the given permissions
- `getPermissions(roleName)` - Get all permissions for a role (direct + inherited)

### Attribute-Based Access Control (ABAC)
- `can(subject, permission, resource?, context?)` - Check permission with optional attribute evaluation
- `addRule(permission, ruleFunction)` - Add conditional rule for a permission
- `removeRule(permission)` - Remove a rule
- `hasRule(permission)` - Check if a rule exists
- `getRules()` - Get all permissions with rules

### Serialization
- `dump()` - Export configuration as JSON string
- `Rbac.restore(dump)` - Create new instance from dump
- `toJSON()` - Get configuration as plain object

## Advanced Examples

### Dynamic Group Assignment
```ts
rbac.addGroup("premium-features", ["feature:ai", "feature:analytics"]);
rbac.addRole("user", ["article:read"], []);

// Upgrade user to premium
rbac.addRoleToGroup("user", "premium-features");

// Downgrade
rbac.removeRoleFromGroup("user", "premium-features");
```

### Flexible Permission Patterns
```ts
// Permissions are just strings - use any naming convention
rbac
    .addGroup("api-users", [
        "api:read",
        "api:write",
        "endpoint:/users",
        "endpoint:/posts"
    ])
    .addRole("service-account", [], ["api-users"]);
```

### Configuration Persistence
```ts
// Save to storage
const dump = rbac.dump();
localStorage.setItem("rbac-config", dump);

// Restore later
const rbac2 = Rbac.restore(localStorage.getItem("rbac-config"));
rbac2.hasPermission("editor", "article:update"); // true
```

### Attribute-Based Access Control (ABAC)

ABAC extends RBAC with conditional rules based on attributes of the subject, resource, and context.

**Basic Usage:**
```ts
// Add a rule: authors can only edit their own drafts
rbac.addRule("article:update", (subject, resource) => {
  if (subject.role === "author") {
    return resource.authorId === subject.id && resource.status === "draft";
  }
  return true; // Other roles can edit anything
});

// Check permission with resource
const canUpdate = rbac.can(
  { role: "author", id: "user123" },  // subject
  "article:update",                    // permission
  { authorId: "user123", status: "draft" }  // resource
);
```

**How it Works:**
1. `can()` first checks basic RBAC permissions (same as `hasPermission()`)
2. If a rule exists for the permission, it's evaluated with the provided attributes
3. Both checks must pass for access to be granted

**Real-World Example:**
```ts
rbac
  .addRole("author", ["article:create", "article:update", "article:delete"])
  .addRole("editor", ["article:update", "article:publish"])
  .addRule("article:update", (subject, resource) => {
    // Authors: own drafts only
    if (subject.role === "author") {
      return resource.authorId === subject.id && resource.status === "draft";
    }
    // Editors: any article
    return true;
  })
  .addRule("article:delete", (subject, resource) => {
    // Only delete own drafts
    return resource.authorId === subject.id && resource.status === "draft";
  });

// In your application
app.put("/api/articles/:id", async (req, res) => {
  const article = await Article.findById(req.params.id);

  if (!rbac.can(req.user, "article:update", article)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  // Proceed with update...
});
```

**Using Context:**
```ts
// Time-based access control
rbac.addRule("data:export", (subject, resource, context) => {
  const hour = new Date().getHours();
  // Only allow exports during business hours
  return hour >= 9 && hour < 17;
});

rbac.can({ role: "analyst" }, "data:export", {}, { timestamp: Date.now() });
```

**When to Use ABAC:**
- ✅ Ownership checks ("edit own articles")
- ✅ Status-based permissions ("delete draft articles only")
- ✅ Time/location-based access
- ✅ Resource-specific conditions
- ❌ Don't need for simple role-based permissions

## Notes

- Permission strings are matched exactly (no wildcard expansion)
- Groups must exist before adding roles to them
- Removing a group automatically removes it from all roles
- Roles can belong to multiple groups
- Duplicate permissions are automatically deduplicated
- Rules are **not serialized** - you must re-add them after `restore()`
- ABAC rules are optional - use only when needed

## Package Identity

- **Name:** @marianmeres/rbac
- **Author:** Marian Meres
- **Repository:** https://github.com/marianmeres/rbac
- **License:** MIT