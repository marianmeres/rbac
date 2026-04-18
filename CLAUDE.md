# CLAUDE.md

Quick context for Claude Code.

## What This Is

`@marianmeres/rbac` - TypeScript RBAC library with optional ABAC support. Zero dependencies. Works in Deno, Node.js, and browsers.

## File Layout

- `src/mod.ts` - Entry point (re-exports rbac.ts)
- `src/rbac.ts` - Single-file implementation (~650 LOC)
- `tests/rbac.test.ts` - 65 tests
- `deno.json` - Config and tasks

## Core Concepts

1. **Permissions** - Strings like `"article:read"` (exact match, no wildcards)
2. **Roles** - Direct permissions + inherit from groups
3. **Groups** - Reusable permission sets; can inherit from other groups
4. **Rules** - Optional ABAC rule **chains** (AND semantics) per permission

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
rbac.addGroup("admins", ["system:admin"]);
rbac.addRole("admin", [], ["admins"]);

// Group hierarchy
rbac.addGroup("viewers", ["article:read"]);
rbac.addGroup("editors", ["article:update"]);
rbac.addGroupToGroup("editors", "viewers");

// Check permissions
rbac.hasPermission("admin", "system:admin");       // boolean
rbac.hasSomePermission("admin", ["a", "b"]);       // OR
rbac.hasEveryPermission("admin", ["a", "b"]);      // AND
rbac.getPermissions("admin");                      // Set<string>
rbac.explainPermission("admin", "system:admin");   // trace source

// ABAC (optional) — rule chains are AND
rbac.addRule("article:update", (subject, resource) => {
    return resource?.authorId === subject.id;
});
rbac.appendRule("article:update", duringBusinessHours);

// Multi-role subject supported
rbac.can({ role: ["author"], id: "x" }, "article:update", { authorId: "x" });

// Serialize (rule functions NOT included; permission names ARE)
const dump = rbac.dump();
const restored = Rbac.restore(dump);      // or: new Rbac(dump)
restored.getMissingRules();               // permissions whose rules need re-adding
```

## Important Constraints

- Groups must exist before roles or other groups reference them
- Permission matching is exact (no wildcard expansion)
- Rule functions are not serialized by `dump()` — their permission names are
- Rule chains use AND semantics — every rule must return `true`
- Group-to-group cycles are tolerated at query time (skipped, not error)
- All mutating methods return `this` for chaining

## Code Style

Tabs, 90 char lines, 4-space indent width. See `deno.json` fmt config.
