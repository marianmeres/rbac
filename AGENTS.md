# AGENTS.md

Machine-readable context for AI agents working with this codebase.

## Package Identity

```yaml
name: "@marianmeres/rbac"
version: "2.1.0"
license: MIT
author: Marian Meres
repository: https://github.com/marianmeres/rbac
```

## Purpose

Role-Based Access Control (RBAC) library with optional Attribute-Based Access
Control (ABAC) support. Manages permissions through roles and groups. Supports
group-to-group inheritance and multi-role subjects.

## Technology Stack

- Language: TypeScript
- Runtime: Deno (primary), Node.js, Browser
- Build: `deno task npm:build` (uses `@marianmeres/npmbuild`)
- Test: `deno test`
- No external runtime dependencies

## Project Structure

```
src/
  mod.ts          # Entry point, re-exports rbac.ts
  rbac.ts         # Core implementation (~650 lines)
tests/
  rbac.test.ts    # Test suite (65 tests)
scripts/
  build-npm.ts    # NPM build script
.npm-dist/        # Generated NPM distribution
mcp.ts            # MCP tool definitions
mcp-include.txt   # MCP description blurb
```

## Entry Points

- JSR/Deno: `./src/mod.ts`
- NPM: `.npm-dist/dist/mod.js`

## Exported Types

```typescript
class Rbac

interface RbacSubject {
    role: string | string[];
    [key: string]: any;
}

type RbacRuleFunction<Subject, Resource, Context> =
    (subject, resource?, context?) => boolean  // all generics default to permissive shapes

interface RbacDump {
    roles:  Record<string, Partial<Record<"permissions" | "memberOf", string[]>>>;
    groups: Record<string, Partial<Record<"permissions" | "memberOf", string[]>>>;
    rules?: string[];   // permission names that had rule chains at dump time
}

interface RbacRoleInternal  { permissions: Set<string>; memberOf: Set<string> }
interface RbacGroupInternal { permissions: Set<string>; memberOf: Set<string> }
interface RbacPermissionExplanation {
    granted: boolean;
    source:  "role" | "group" | null;
    path:    string[];
}
```

## Public API Summary

### Constructor

| Signature | Notes |
|-----------|-------|
| `new Rbac(dump?: string \| Partial<RbacDump>)` | Optional initial config (same as `Rbac.restore`) |

### Role Management

| Method | Signature | Returns |
|--------|-----------|---------|
| addRole | `(name, permissions?, groupNames?)` | `Rbac` |
| removeRole | `(name)` | `Rbac` |
| removeRolePermissions | `(name, permissions?)` | `Rbac` |
| hasRole | `(name)` | `boolean` |
| getRoles | `()` | `string[]` |
| getRoleGroups | `(name, transitive?)` | `string[]` |

### Group Management

| Method | Signature | Returns |
|--------|-----------|---------|
| addGroup | `(name, permissions?)` | `Rbac` |
| removeGroup | `(name)` | `Rbac` |
| removeGroupPermissions | `(name, permissions?)` | `Rbac` |
| hasGroup | `(name)` | `boolean` |
| getGroups | `()` | `string[]` |
| getGroupRoles | `(name)` | `string[]` |
| getGroupParents | `(name)` | `string[]` |
| getGroupChildren | `(name)` | `string[]` |

### Associations

| Method | Signature | Returns |
|--------|-----------|---------|
| addRoleToGroup | `(roleName, groupName)` | `Rbac` |
| removeRoleFromGroup | `(roleName, groupName)` | `Rbac` |
| addGroupToGroup | `(childName, parentName)` | `Rbac` |
| removeGroupFromGroup | `(childName, parentName)` | `Rbac` |

### Permission Checks

| Method | Signature | Returns |
|--------|-----------|---------|
| hasPermission | `(roleName, permission)` | `boolean` |
| hasSomePermission | `(roleName, permissions)` | `boolean` |
| hasEveryPermission | `(roleName, permissions)` | `boolean` |
| getPermissions | `(roleName)` | `Set<string>` |
| explainPermission | `(roleName, permission)` | `RbacPermissionExplanation` |

### ABAC

| Method | Signature | Returns |
|--------|-----------|---------|
| can | `(subject, permission, resource?, context?)` | `boolean` |
| addRule | `(permission, ruleFn)` | `Rbac` (replaces chain) |
| appendRule | `(permission, ruleFn)` | `Rbac` (AND append) |
| removeRule | `(permission)` | `Rbac` |
| hasRule | `(permission)` | `boolean` |
| getRules | `()` | `string[]` |
| getMissingRules | `()` | `string[]` |

### Serialization

| Method | Signature | Returns |
|--------|-----------|---------|
| toJSON | `()` | `RbacDump` |
| dump | `()` | `string` |
| clone | `()` | `Rbac` |
| Rbac.restore (static) | `(dump)` | `Rbac` |

## Internal Data Structures

```typescript
#roles: Map<string, RbacRoleInternal>
#groups: Map<string, RbacGroupInternal>              // groups also have memberOf
#rules: Map<string, RbacRuleFunction[]>              // array = rule chain
#expectedRules: Set<string>                          // populated from dump.rules
```

## Key Behaviors

1. **Method chaining**: all mutating methods return `this`
2. **Role inherits from groups** (direct `memberOf`)
3. **Group inherits from groups** (via `addGroupToGroup`, transitive)
4. **Group prerequisite**: groups must exist before being referenced
5. **Cascading removal**: `removeGroup` cleans up role + group memberships
6. **Cycle tolerance**: group-to-group cycles are skipped at traversal time,
   not an error
7. **Multi-role `can()`**: `subject.role` can be `string` or `string[]`
8. **Rule chains**: `#rules` maps permission → array; `can()` applies AND
9. **addRule vs appendRule**: `addRule` replaces the chain; `appendRule`
   appends to it (creates if missing)
10. **Permission deduplication**: internal `Set`
11. **Exact matching**: no wildcard expansion
12. **Serialization limitation**: rule functions are not serialized;
    `RbacDump.rules` stores their permission names so callers can detect
    missing rules via `getMissingRules()`

## Error Conditions

- `addRole(_, _, [missingGroup])` → throws
- `addRoleToGroup(_, missingGroup)` → throws
- `addGroupToGroup(missingChild, _)` or `(_, missingParent)` → throws
- `addGroupToGroup(x, x)` → throws (self-membership)
- `Rbac.restore(...)` / `new Rbac(dump)` → throws `Error` with `cause` on
  invalid JSON or missing group references
- Silent no-ops: `removeRolePermissions` / `removeRoleFromGroup` /
  `removeGroupPermissions` / `removeGroupFromGroup` on non-existent targets

## Test Commands

```sh
deno test              # Run all tests (65)
deno test --watch      # Watch mode
```

## Build Commands

```sh
deno task npm:build    # Build NPM package to .npm-dist/
deno task publish      # Publish to JSR and NPM
deno task rp           # Release patch and publish
deno task rpm          # Release minor and publish
```

## Code Style

- Tabs for indentation, 4-space indent width
- 90 character line width
- TypeScript strict mode
- Private class fields use `#` prefix

## Common Modification Patterns

### Adding a new method

1. Add method to `src/rbac.ts` class with JSDoc (`@param`, `@returns`, `@example`)
2. Explicit return type (no inference for public API)
3. Add tests to `tests/rbac.test.ts`
4. Update `API.md`, `README.md` (if public), and this file's tables

### Adding a new exported type

1. Add to `src/rbac.ts` with `export`
2. Add JSDoc
3. Auto-exported via `src/mod.ts`
4. Document in `API.md` § Types and in the Exported Types block above

### Changing serialization format

Serialization is additive. New fields on `RbacDump` should be optional so old
dumps still restore cleanly. New required fields on exported `Internal`
interfaces are a BC break — document prominently.

## Related Documentation

- [README.md](./README.md) - User documentation
- [API.md](./API.md) - Complete API reference
- [CLAUDE.md](./CLAUDE.md) - Quick context for Claude Code
- [LICENSE](./LICENSE) - MIT license
