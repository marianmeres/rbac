# API Reference

Complete API documentation for `@marianmeres/rbac`.

## Table of Contents

- [Class: Rbac](#class-rbac)
- [Types](#types)
- [Role Management](#role-management)
- [Group Management](#group-management)
- [Role-Group Association](#role-group-association)
- [Group-Group Association](#group-group-association)
- [Permission Checks (RBAC)](#permission-checks-rbac)
- [Introspection](#introspection)
- [Attribute-Based Access Control (ABAC)](#attribute-based-access-control-abac)
- [Serialization](#serialization)

---

## Class: Rbac

The main class for managing permissions through roles and groups.

### Constructor

```ts
new Rbac(dump?: string | Partial<RbacDump>)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dump` | `string \| Partial<RbacDump>` | `undefined` | Optional initial configuration (JSON string or object). Equivalent to `Rbac.restore(dump)`. |

**Throws:** `Error` if `dump` is invalid JSON or references missing groups.

```ts
import { Rbac } from "@marianmeres/rbac";

// Empty
const rbac = new Rbac();

// From a dump
const rbac2 = new Rbac(previousDump);
```

All mutating methods return `this` for method chaining:

```ts
rbac
    .addGroup("admins", ["system:admin"])
    .addRole("admin", [], ["admins"])
    .addRule("article:update", (subject, resource) => resource?.authorId === subject.id);
```

---

## Types

### RbacSubject

The subject shape accepted by `can()` and (by default) `RbacRuleFunction`.

```ts
interface RbacSubject {
    role: string | string[];
    [key: string]: any;
}
```

### RbacRuleFunction

Callback type for ABAC rule evaluation. Generic with permissive defaults.

```ts
type RbacRuleFunction<
    Subject extends RbacSubject = RbacSubject,
    Resource extends Record<string, any> = Record<string, any>,
    Context extends Record<string, any> = Record<string, any>,
> = (subject: Subject, resource?: Resource, context?: Context) => boolean;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `subject` | `Subject` | User/role information and attributes |
| `resource` | `Resource` | Optional resource with attributes to check against |
| `context` | `Context` | Optional environmental context (time, IP, metadata) |
| **Returns** | `boolean` | `true` to grant, `false` to deny |

```ts
// Un-typed usage still works (defaults apply):
rbac.addRule("article:update", (subject, resource) => {
    return subject.id === resource?.authorId;
});

// Narrow types per rule:
interface User { role: string | string[]; id: number }
interface Article { authorId: number; status: "draft" | "published" }

const ownershipRule: RbacRuleFunction<User, Article> = (subject, resource) =>
    resource?.authorId === subject.id;

rbac.addRule("article:update", ownershipRule);
```

### RbacDump

Serializable representation of the RBAC configuration.

```ts
interface RbacDump {
    roles: Record<string, Partial<Record<"permissions" | "memberOf", string[]>>>;
    groups: Record<string, Partial<Record<"permissions" | "memberOf", string[]>>>;
    rules?: string[];
}
```

| Field | Description |
|-------|-------------|
| `roles` | Per role: direct `permissions` and `memberOf` group names |
| `groups` | Per group: direct `permissions` and `memberOf` (parent group names) |
| `rules` | Optional list of permissions that had rule chains attached at dump time (rule functions themselves are not serialized) |

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
    memberOf: Set<string>;  // parent groups
}
```

### RbacPermissionExplanation

Detailed result returned by `explainPermission()`.

```ts
interface RbacPermissionExplanation {
    granted: boolean;
    source: "role" | "group" | null;
    path: string[];
}
```

| Field | Description |
|-------|-------------|
| `granted` | Whether the role has the permission |
| `source` | `"role"` for a direct permission, `"group"` if inherited, `null` if not granted |
| `path` | `[roleName]` for direct; `[roleName, groupName, ...]` for inherited (closest group first) |

---

## Role Management

### addRole()

Creates or updates a role with permissions and group memberships. Additive — can
be called multiple times for the same role.

```ts
addRole(name: string, permissions?: string[], groupNames?: string[]): Rbac
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `string` | - | The role name |
| `permissions` | `string[]` | `[]` | Permissions to add |
| `groupNames` | `string[]` | `[]` | Groups to add the role to |

**Throws:** `Error` if any specified group doesn't exist.

```ts
rbac.addRole("user", ["article:read"]);
rbac.addRole("admin", [], ["admins"]);
rbac.addRole("editor", ["comment:delete"], ["editors"]);

// Adding more permissions to an existing role
rbac.addRole("editor", ["comment:pin"]);
```

### removeRole()

Removes a role entirely.

```ts
removeRole(name: string): Rbac
```

```ts
rbac.removeRole("guest");
```

### removeRolePermissions()

Removes specific permissions from a role. No-op if the role doesn't exist.

```ts
removeRolePermissions(name: string, permissions?: string[]): Rbac
```

### hasRole()

```ts
hasRole(name: string): boolean
```

### getRoles()

```ts
getRoles(): string[]
```

### getRoleGroups()

Returns the groups a role belongs to.

```ts
getRoleGroups(roleName: string, transitive?: boolean): string[]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `roleName` | `string` | - | The role name |
| `transitive` | `boolean` | `false` | Include groups inherited through group-to-group membership |

```ts
rbac.getRoleGroups("editor");        // ["editors"]
rbac.getRoleGroups("editor", true);  // ["editors", "viewers", ...]
```

---

## Group Management

### addGroup()

Creates or updates a group. Additive.

```ts
addGroup(name: string, permissions?: string[]): Rbac
```

```ts
rbac.addGroup("admins", ["system:admin"]);
rbac.addGroup("editors", ["article:read", "article:update"]);
```

### removeGroup()

Removes a group entirely. Cascades: all roles and other groups that referenced
this group lose the membership.

```ts
removeGroup(name: string): Rbac
```

### removeGroupPermissions()

Removes specific permissions from a group. No-op if the group doesn't exist.

```ts
removeGroupPermissions(name: string, permissions?: string[]): Rbac
```

### hasGroup()

```ts
hasGroup(name: string): boolean
```

### getGroups()

```ts
getGroups(): string[]
```

### getGroupRoles()

Roles that directly list `groupName` in their `memberOf`.

```ts
getGroupRoles(groupName: string): string[]
```

### getGroupParents()

Direct parent groups of `groupName`.

```ts
getGroupParents(groupName: string): string[]
```

### getGroupChildren()

Direct child groups of `groupName` (groups that list `groupName` as a parent).

```ts
getGroupChildren(groupName: string): string[]
```

---

## Role-Group Association

### addRoleToGroup()

Adds a role to a group. Creates the role if it doesn't exist.

```ts
addRoleToGroup(roleName: string, groupName: string): Rbac
```

**Throws:** `Error` if the group doesn't exist.

### removeRoleFromGroup()

Removes a role from a group. No-op if the role doesn't exist.

```ts
removeRoleFromGroup(roleName: string, groupName: string): Rbac
```

---

## Group-Group Association

Groups can be members of other groups, forming a hierarchy. Cycles are tolerated
at query time (traversal skips already-visited groups).

### addGroupToGroup()

Makes `childName` a member of `parentName`. Child inherits parent's permissions.

```ts
addGroupToGroup(childName: string, parentName: string): Rbac
```

**Throws:** `Error` if either group doesn't exist, or if `childName === parentName`.

```ts
rbac
    .addGroup("viewers", ["article:read"])
    .addGroup("editors", ["article:update"])
    .addGroupToGroup("editors", "viewers");
// "editors" now has ["article:read", "article:update"]
```

### removeGroupFromGroup()

Removes a group-to-group membership. No-op if either group doesn't exist.

```ts
removeGroupFromGroup(childName: string, parentName: string): Rbac
```

---

## Permission Checks (RBAC)

### hasPermission()

Checks if a role has a permission (direct or inherited through the group chain,
including nested groups). Short-circuits on first match.

```ts
hasPermission(roleName: string, permission: string): boolean
```

### hasSomePermission()

OR check — true if the role has at least one of the permissions.

```ts
hasSomePermission(roleName: string, permissions: string[]): boolean
```

### hasEveryPermission()

AND check — true if the role has all of the permissions. An empty list returns
`true` (vacuous truth).

```ts
hasEveryPermission(roleName: string, permissions: string[]): boolean
```

```ts
if (rbac.hasEveryPermission("editor", ["article:read", "article:update"])) {
    // allow batch operation
}
```

### getPermissions()

Returns the full effective permission set for a role.

```ts
getPermissions(roleName: string): Set<string>
```

---

## Introspection

### explainPermission()

Detailed trace of how (or whether) a role has a permission. Useful for auditing.

```ts
explainPermission(roleName: string, permission: string): RbacPermissionExplanation
```

```ts
rbac.explainPermission("editor", "article:read");
// { granted: true, source: "group", path: ["editor", "editors", "viewers"] }

rbac.explainPermission("editor", "unknown");
// { granted: false, source: null, path: [] }
```

---

## Attribute-Based Access Control (ABAC)

ABAC extends RBAC with conditional rule chains. Rule chains use AND semantics —
every rule must return `true` for `can()` to grant access.

### can()

```ts
can(
    subject: RbacSubject,
    permission: string,
    resource?: Record<string, any>,
    context?: Record<string, any>
): boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `subject` | `RbacSubject` | `{ role: string \| string[], ... }` |
| `permission` | `string` | The permission to check |
| `resource` | `Record<string, any>` | Optional resource attributes |
| `context` | `Record<string, any>` | Optional context (time, IP, etc.) |
| **Returns** | `boolean` | `true` if granted |

**Evaluation order:**
1. RBAC: at least one of `subject.role` must have the permission (direct or inherited)
2. If a rule chain exists for `permission`, every rule must return `true`

```ts
rbac.can({ role: "admin" }, "article:delete");

// Multi-role subject
rbac.can({ role: ["author", "reviewer"], id: "u1" }, "article:publish", article);

// With resource + context
rbac.can(
    { role: "editor" },
    "data:export",
    { classification: "internal" },
    { currentHour: 14 }
);
```

### addRule()

Replaces the rule chain for `permission` with a single-rule chain.

```ts
addRule(permission: string, rule: RbacRuleFunction): Rbac
```

```ts
rbac.addRule("article:update", (subject, resource) => {
    if (subject.role === "author") {
        return resource?.authorId === subject.id && resource?.status === "draft";
    }
    return true;
});
```

### appendRule()

Appends a rule to the chain for `permission`. All rules in the chain must
return `true` (AND semantics). If no chain exists yet, behaves like `addRule()`.

```ts
appendRule(permission: string, rule: RbacRuleFunction): Rbac
```

```ts
rbac
    .appendRule("article:update", isOwner)
    .appendRule("article:update", isDuringBusinessHours);
```

### removeRule()

Removes the entire rule chain for a permission.

```ts
removeRule(permission: string): Rbac
```

### hasRule()

`true` if at least one rule is registered for `permission`.

```ts
hasRule(permission: string): boolean
```

### getRules()

Permissions that have a rule chain attached.

```ts
getRules(): string[]
```

### getMissingRules()

Returns permissions that had rules at dump-time but have no rule registered on
this instance. `[]` for instances created without a dump or once all expected
rules have been re-added.

```ts
getMissingRules(): string[]
```

```ts
const rbac = new Rbac(previousDump);
rbac.addRule("article:update", ownershipRule);

const missing = rbac.getMissingRules();
if (missing.length > 0) {
    throw new Error(`Missing rules: ${missing.join(", ")}`);
}
```

---

## Serialization

### dump()

Exports the configuration as a JSON string.

```ts
dump(): string
```

> **Note:** Rule functions are **not** serialized. Their permission names are
> recorded in `RbacDump.rules` so you can detect missing rules via
> `getMissingRules()` after restore.

```ts
const dump = rbac.dump();
localStorage.setItem("rbac", dump);
```

### toJSON()

Plain-object form of the configuration. Same information as `dump()`.

```ts
toJSON(): RbacDump
```

### Rbac.restore() (static)

Creates a new `Rbac` from a dump. Equivalent to `new Rbac(dump)`.

```ts
static restore(dump: string | Partial<RbacDump>): Rbac
```

**Throws:** `Error` (with `cause`) if the dump is invalid or references missing
groups.

```ts
// From string
const rbac = Rbac.restore(localStorage.getItem("rbac")!);

// From object (partial data supported)
const rbac2 = Rbac.restore({
    groups: { admins: { permissions: ["system:admin"] } },
    roles:  { admin:  { memberOf: ["admins"] } },
});

// Re-add rules
rbac.addRule("article:update", ownershipRule);
```

### clone()

Deep copy of this `Rbac` instance, including rule chains. Mutations on the
clone do not affect the source.

```ts
clone(): Rbac
```

---

## Important Notes

- **Permission matching is exact.** There is no wildcard expansion — `"article:*"`
  is a literal permission string. Model wildcards yourself if needed.
- **Groups must exist before references.** `addRole`, `addRoleToGroup`, and
  `addGroupToGroup` throw if the referenced group is missing.
- **Removing a group cascades.** All roles and child groups lose the membership.
- **Roles and groups can have multiple parents.** Permission sets are unioned.
- **Cycles in the group graph are tolerated** at query time — they just don't
  produce infinite traversal.
- **Duplicate permissions are deduplicated** (internal `Set`).
- **Rule chains are AND** — every rule must return `true`.
- **Rules are not serialized.** Re-add them after `restore()`. Use
  `getMissingRules()` to detect forgotten rules.
- **ABAC is optional.** `can()` works without rules (behaves like
  `hasPermission` with multi-role support).
