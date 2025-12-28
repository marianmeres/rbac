# API Reference

Complete API documentation for `@marianmeres/rbac`.

## Table of Contents

- [Class: Rbac](#class-rbac)
- [Types](#types)
- [Role Management](#role-management)
- [Group Management](#group-management)
- [Role-Group Association](#role-group-association)
- [Permission Checks (RBAC)](#permission-checks-rbac)
- [Attribute-Based Access Control (ABAC)](#attribute-based-access-control-abac)
- [Serialization](#serialization)

---

## Class: Rbac

The main class for managing permissions through roles and groups.

```ts
import { Rbac } from "@marianmeres/rbac";

const rbac = new Rbac();
```

All mutating methods return `this` for method chaining:

```ts
rbac
  .addGroup("admins", ["*:*"])
  .addRole("admin", [], ["admins"])
  .addRule("article:update", (subject, resource) => resource?.authorId === subject.id);
```

---

## Types

### RbacRuleFunction

Callback type for ABAC rule evaluation.

```ts
type RbacRuleFunction = (
  subject: Record<string, any>,
  resource?: Record<string, any>,
  context?: Record<string, any>
) => boolean;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `subject` | `Record<string, any>` | Object containing user/role information and attributes |
| `resource` | `Record<string, any>` | Optional resource object with attributes to check against |
| `context` | `Record<string, any>` | Optional context object (e.g., time, IP address, request metadata) |
| **Returns** | `boolean` | `true` if the rule allows access, `false` otherwise |

### RbacDump

Serializable representation of the RBAC configuration.

```ts
interface RbacDump {
  roles: Record<string, Partial<Record<"permissions" | "memberOf", string[]>>>;
  groups: Record<string, Partial<Record<"permissions", string[]>>>;
}
```

### RbacRoleInternal

Internal role structure (exported for advanced use cases).

```ts
interface RbacRoleInternal {
  permissions: Set<string>;
  memberOf: Set<string>;
}
```

### RbacGroupInternal

Internal group structure (exported for advanced use cases).

```ts
interface RbacGroupInternal {
  permissions: Set<string>;
}
```

---

## Role Management

### addRole()

Creates or updates a role with permissions and group memberships.

```ts
addRole(name: string, permissions?: string[], groupNames?: string[]): Rbac
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `string` | - | The role name |
| `permissions` | `string[]` | `[]` | Array of permission strings to add |
| `groupNames` | `string[]` | `[]` | Array of group names the role should belong to |

**Throws:** `Error` if any specified group doesn't exist.

```ts
// Create role with direct permissions
rbac.addRole("user", ["article:read"]);

// Create role with group membership
rbac.addRole("admin", [], ["admins"]);

// Create role with both
rbac.addRole("editor", ["comment:delete"], ["editors"]);

// Add more permissions to existing role
rbac.addRole("editor", ["comment:pin"]);
```

### removeRole()

Removes a role entirely from the RBAC system.

```ts
removeRole(name: string): Rbac
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `string` | The role name to remove |

```ts
rbac.removeRole("guest");
```

### removeRolePermissions()

Removes specific permissions from a role.

```ts
removeRolePermissions(name: string, permissions?: string[]): Rbac
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `string` | - | The role name |
| `permissions` | `string[]` | `[]` | Array of permission strings to remove |

```ts
rbac.removeRolePermissions("editor", ["article:delete"]);
```

### hasRole()

Checks if a role exists in the RBAC system.

```ts
hasRole(name: string): boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `string` | The role name to check |
| **Returns** | `boolean` | `true` if the role exists |

```ts
if (rbac.hasRole("admin")) {
  // Role exists
}
```

### getRoles()

Returns an array of all role names.

```ts
getRoles(): string[]
```

| Returns | Type | Description |
|---------|------|-------------|
| - | `string[]` | Array of all role names |

```ts
const roles = rbac.getRoles(); // ["admin", "editor", "user"]
```

---

## Group Management

### addGroup()

Creates or updates a group with permissions.

```ts
addGroup(name: string, permissions?: string[]): Rbac
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `string` | - | The group name |
| `permissions` | `string[]` | `[]` | Array of permission strings |

```ts
rbac.addGroup("admins", ["*:*"]);
rbac.addGroup("editors", ["article:read", "article:update"]);

// Add more permissions to existing group
rbac.addGroup("editors", ["article:publish"]);
```

### removeGroup()

Removes a group entirely. Roles that were members will no longer inherit its permissions.

```ts
removeGroup(name: string): Rbac
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `string` | The group name to remove |

```ts
rbac.removeGroup("guests");
// All roles that were members of "guests" lose those permissions
```

### removeGroupPermissions()

Removes specific permissions from a group.

```ts
removeGroupPermissions(name: string, permissions?: string[]): Rbac
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `string` | - | The group name |
| `permissions` | `string[]` | `[]` | Array of permission strings to remove |

```ts
rbac.removeGroupPermissions("editors", ["article:delete"]);
```

### hasGroup()

Checks if a group exists in the RBAC system.

```ts
hasGroup(name: string): boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `string` | The group name to check |
| **Returns** | `boolean` | `true` if the group exists |

```ts
if (rbac.hasGroup("admins")) {
  // Group exists
}
```

### getGroups()

Returns an array of all group names.

```ts
getGroups(): string[]
```

| Returns | Type | Description |
|---------|------|-------------|
| - | `string[]` | Array of all group names |

```ts
const groups = rbac.getGroups(); // ["admins", "editors"]
```

---

## Role-Group Association

### addRoleToGroup()

Adds a role to a group, allowing it to inherit the group's permissions. Creates the role if it doesn't exist.

```ts
addRoleToGroup(roleName: string, groupName: string): Rbac
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `roleName` | `string` | The role name |
| `groupName` | `string` | The group name to add the role to |

**Throws:** `Error` if the group doesn't exist.

```ts
rbac.addGroup("premium-features", ["feature:ai", "feature:analytics"]);
rbac.addRole("user", ["article:read"]);

// Upgrade user to premium
rbac.addRoleToGroup("user", "premium-features");
```

### removeRoleFromGroup()

Removes a role from a group, stopping it from inheriting the group's permissions.

```ts
removeRoleFromGroup(roleName: string, groupName: string): Rbac
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `roleName` | `string` | The role name |
| `groupName` | `string` | The group name to remove the role from |

```ts
// Downgrade user from premium
rbac.removeRoleFromGroup("user", "premium-features");
```

---

## Permission Checks (RBAC)

### hasPermission()

Checks if a role has a specific permission (direct or inherited from groups).

```ts
hasPermission(roleName: string, permission: string): boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `roleName` | `string` | The role name |
| `permission` | `string` | The permission to check |
| **Returns** | `boolean` | `true` if the role has the permission |

```ts
if (rbac.hasPermission("editor", "article:update")) {
  // Allow update
}
```

### hasSomePermission()

Checks if a role has at least one of the given permissions. Useful for OR-based permission checks.

```ts
hasSomePermission(roleName: string, permissions: string[]): boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `roleName` | `string` | The role name |
| `permissions` | `string[]` | Array of permissions to check |
| **Returns** | `boolean` | `true` if the role has any of the permissions |

```ts
// Check if user can read articles via any permission level
const canRead = rbac.hasSomePermission("user", [
  "*:*",         // Super admin
  "article:*",   // Article admin
  "article:read" // Basic read
]);
```

### getPermissions()

Returns the full set of permissions for a role, including inherited group permissions.

```ts
getPermissions(roleName: string): Set<string>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `roleName` | `string` | The role name |
| **Returns** | `Set<string>` | Set of all permissions (direct and inherited) |

```ts
const perms = rbac.getPermissions("editor");
// Set { "article:read", "article:update", ... }

for (const perm of perms) {
  console.log(perm);
}
```

---

## Attribute-Based Access Control (ABAC)

ABAC extends RBAC with conditional rules based on attributes of the subject, resource, and context.

### can()

Checks if a subject can perform an action, with optional ABAC rule evaluation. This method first checks basic RBAC permissions, then evaluates any attached rules.

```ts
can(
  subject: { role: string; [key: string]: any },
  permission: string,
  resource?: Record<string, any>,
  context?: Record<string, any>
): boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `subject` | `{ role: string; [key: string]: any }` | Object with at least a `role` property |
| `permission` | `string` | The permission to check |
| `resource` | `Record<string, any>` | Optional resource object with attributes |
| `context` | `Record<string, any>` | Optional context (time, IP, metadata, etc.) |
| **Returns** | `boolean` | `true` if access is granted |

**How it works:**
1. First checks basic RBAC permissions (same as `hasPermission()`)
2. If a rule exists for the permission, evaluates it with provided attributes
3. Both checks must pass for access to be granted

```ts
// Basic RBAC check (no rule for this permission)
rbac.can({ role: "admin" }, "article:delete");

// ABAC check with resource
rbac.can(
  { role: "author", id: "user123" },
  "article:update",
  { authorId: "user123", status: "draft" }
);

// ABAC check with context
rbac.can(
  { role: "editor" },
  "data:export",
  {},
  { currentHour: 14 }
);
```

### addRule()

Adds a conditional rule for attribute-based access control. Rules are evaluated after basic RBAC permission checks pass.

```ts
addRule(permission: string, rule: RbacRuleFunction): Rbac
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `permission` | `string` | The permission string to attach this rule to |
| `rule` | `RbacRuleFunction` | Function that evaluates attributes |

```ts
// Ownership rule: authors can only edit their own drafts
rbac.addRule("article:update", (subject, resource) => {
  if (subject.role === "author") {
    return resource?.authorId === subject.id && resource?.status === "draft";
  }
  return true; // Other roles can edit anything
});

// Time-based rule
rbac.addRule("data:export", (subject, resource, context) => {
  const hour = context?.currentHour ?? new Date().getHours();
  return hour >= 9 && hour < 17; // Business hours only
});
```

### removeRule()

Removes a rule for a specific permission.

```ts
removeRule(permission: string): Rbac
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `permission` | `string` | The permission to remove the rule from |

```ts
rbac.removeRule("article:update");
```

### hasRule()

Checks if a rule exists for a specific permission.

```ts
hasRule(permission: string): boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `permission` | `string` | The permission to check |
| **Returns** | `boolean` | `true` if a rule exists |

```ts
if (rbac.hasRule("article:update")) {
  // Rule-based check required
}
```

### getRules()

Returns all permissions that have rules attached.

```ts
getRules(): string[]
```

| Returns | Type | Description |
|---------|------|-------------|
| - | `string[]` | Array of permission names with rules |

```ts
const ruledPerms = rbac.getRules(); // ["article:update", "article:delete"]
```

---

## Serialization

### dump()

Exports the configuration as a JSON string. Use with `Rbac.restore()` to recreate the configuration.

```ts
dump(): string
```

| Returns | Type | Description |
|---------|------|-------------|
| - | `string` | JSON string representation |

> **Note:** Rules (ABAC functions) are **not serialized**. You must re-add them after restoring.

```ts
const dump = rbac.dump();
localStorage.setItem("rbac", dump);
```

### toJSON()

Returns the internal data structure as a plain object. Useful for serialization and inspection.

```ts
toJSON(): RbacDump
```

| Returns | Type | Description |
|---------|------|-------------|
| - | `RbacDump` | Plain object representation |

```ts
const data = rbac.toJSON();
console.log(data.roles);
console.log(data.groups);
```

### Rbac.restore() (static)

Creates a new Rbac instance from a dump (JSON string or object).

```ts
static restore(dump: string | Partial<RbacDump>): Rbac
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `dump` | `string \| Partial<RbacDump>` | JSON string or RbacDump object |
| **Returns** | `Rbac` | New Rbac instance with restored configuration |

**Throws:** `Error` if dump is invalid or cannot be parsed.

```ts
// From string
const rbac = Rbac.restore(localStorage.getItem("rbac"));

// From object (partial data supported)
const rbac2 = Rbac.restore({
  groups: {
    admins: { permissions: ["*:*"] }
  },
  roles: {
    admin: { memberOf: ["admins"] }
  }
});

// Re-add rules after restore
rbac.addRule("article:update", ownershipRule);
```

---

## Important Notes

- **Permission matching is exact** - No wildcard expansion. `"article:*"` does not match `"article:read"`.
- **Groups must exist before roles reference them** - Create groups first, then add roles to them.
- **Removing a group cascades** - Roles lose inherited permissions automatically.
- **Roles can belong to multiple groups** - Permissions from all groups are combined.
- **Duplicate permissions are deduplicated** - Sets are used internally.
- **Rules are not serialized** - Must be re-added after `restore()`.
- **ABAC rules are optional** - Use only when needed; `can()` works without rules.
