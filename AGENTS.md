# AGENTS.md

Machine-readable context for AI agents working with this codebase.

## Package Identity

```yaml
name: "@marianmeres/rbac"
version: "2.0.2"
license: MIT
author: Marian Meres
repository: https://github.com/marianmeres/rbac
```

## Purpose

Role-Based Access Control (RBAC) library with optional Attribute-Based Access Control (ABAC) support. Manages permissions through roles and groups.

## Technology Stack

- Language: TypeScript
- Runtime: Deno (primary), Node.js, Browser
- Build: deno task npm:build (uses @marianmeres/npmbuild)
- Test: deno test
- No external runtime dependencies

## Project Structure

```
src/
  mod.ts          # Entry point, re-exports rbac.ts
  rbac.ts         # Core implementation (~600 lines)
tests/
  rbac.test.ts    # Test suite (36 tests)
scripts/
  build-npm.ts    # NPM build script
.npm-dist/        # Generated NPM distribution
```

## Entry Points

- JSR/Deno: `./src/mod.ts`
- NPM: `.npm-dist/dist/mod.js`

## Exported Types

```typescript
// Main class
class Rbac

// Types
type RbacRuleFunction = (subject: Record<string, any>, resource?: Record<string, any>, context?: Record<string, any>) => boolean
interface RbacDump { roles: Record<string, ...>; groups: Record<string, ...> }
interface RbacRoleInternal { permissions: Set<string>; memberOf: Set<string> }
interface RbacGroupInternal { permissions: Set<string> }
```

## Public API Summary

### Rbac Class Methods

| Method | Signature | Returns |
|--------|-----------|---------|
| addRole | `(name: string, permissions?: string[], groupNames?: string[])` | `Rbac` |
| removeRole | `(name: string)` | `Rbac` |
| removeRolePermissions | `(name: string, permissions?: string[])` | `Rbac` |
| hasRole | `(name: string)` | `boolean` |
| getRoles | `()` | `string[]` |
| addGroup | `(name: string, permissions?: string[])` | `Rbac` |
| removeGroup | `(name: string)` | `Rbac` |
| removeGroupPermissions | `(name: string, permissions?: string[])` | `Rbac` |
| hasGroup | `(name: string)` | `boolean` |
| getGroups | `()` | `string[]` |
| addRoleToGroup | `(roleName: string, groupName: string)` | `Rbac` |
| removeRoleFromGroup | `(roleName: string, groupName: string)` | `Rbac` |
| getPermissions | `(roleName: string)` | `Set<string>` |
| hasPermission | `(roleName: string, permission: string)` | `boolean` |
| hasSomePermission | `(roleName: string, permissions: string[])` | `boolean` |
| can | `(subject: {role: string, ...}, permission: string, resource?, context?)` | `boolean` |
| addRule | `(permission: string, rule: RbacRuleFunction)` | `Rbac` |
| removeRule | `(permission: string)` | `Rbac` |
| hasRule | `(permission: string)` | `boolean` |
| getRules | `()` | `string[]` |
| toJSON | `()` | `RbacDump` |
| dump | `()` | `string` |
| restore (static) | `(dump: string \| Partial<RbacDump>)` | `Rbac` |

## Internal Data Structures

```typescript
// Private fields in Rbac class
#roles: Map<string, RbacRoleInternal>
#groups: Map<string, RbacGroupInternal>
#rules: Map<string, RbacRuleFunction>
```

## Key Behaviors

1. **Method chaining**: All mutating methods return `this`
2. **Permission inheritance**: Roles inherit permissions from their groups
3. **Group prerequisite**: Groups must exist before roles can reference them
4. **Cascading removal**: Removing a group removes references from all roles
5. **Permission deduplication**: Uses Set internally
6. **Exact matching**: No wildcard expansion for permissions
7. **ABAC evaluation order**: RBAC check first, then rule evaluation
8. **Serialization limitation**: Rules (functions) are not serialized

## Error Conditions

- `addRole()` throws if referenced group doesn't exist
- `addRoleToGroup()` throws if group doesn't exist
- `restore()` throws on invalid/unparseable dump

## Test Commands

```sh
deno test              # Run all tests
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

- Tabs for indentation
- 90 character line width
- 4 space indent width
- TypeScript strict mode

## Common Modification Patterns

### Adding a new method to Rbac class

1. Add method to `src/rbac.ts` class
2. Add JSDoc with @param, @returns, @example
3. Add explicit return type
4. Add tests to `tests/rbac.test.ts`
5. Update API.md and README.md if public API

### Adding new exported type

1. Add to `src/rbac.ts` with `export`
2. Add JSDoc documentation
3. Type is auto-exported via `src/mod.ts`

## Related Documentation

- [README.md](./README.md) - User documentation
- [API.md](./API.md) - Complete API reference
- [LICENSE](./LICENSE) - MIT license
