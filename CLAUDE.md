# CLAUDE.md

Quick context for Claude Code.

## What This Is

`@marianmeres/rbac` - TypeScript RBAC library with optional ABAC support. Zero dependencies. Works in Deno, Node.js, and browsers.

## File Layout

- `src/mod.ts` - Entry point (re-exports rbac.ts)
- `src/rbac.ts` - Single-file implementation (~600 LOC)
- `tests/rbac.test.ts` - 36 tests
- `deno.json` - Config and tasks

## Core Concepts

1. **Permissions** - Strings like `"article:read"` (exact match, no wildcards)
2. **Roles** - Have direct permissions + inherit from groups
3. **Groups** - Reusable permission sets that roles can join
4. **Rules** - Optional ABAC functions for fine-grained checks

## Key Commands

```sh
deno test           # Run tests
deno task npm:build # Build for NPM
deno task publish   # Publish to JSR + NPM
```

## Quick API Reference

```typescript
const rbac = new Rbac();

// Groups first, then roles
rbac.addGroup("admins", ["*:*"]);
rbac.addRole("admin", [], ["admins"]);

// Check permissions
rbac.hasPermission("admin", "*:*");           // boolean
rbac.hasSomePermission("admin", ["a", "b"]);  // boolean (OR)
rbac.getPermissions("admin");                 // Set<string>

// ABAC (optional)
rbac.addRule("article:update", (subject, resource, context) => {
  return resource?.authorId === subject.id;
});
rbac.can({ role: "author", id: "x" }, "article:update", { authorId: "x" });

// Serialize (rules NOT included)
const dump = rbac.dump();
const restored = Rbac.restore(dump);
```

## Important Constraints

- Groups must exist before roles reference them
- Permission matching is exact (no wildcard expansion)
- Rules are functions - not serialized by dump()
- All mutating methods return `this` for chaining

## Code Style

Tabs, 90 char lines, 4-space indent width. See `deno.json` fmt config.
