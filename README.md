# @marianmeres/rbac

Basic Role-Based-Access-Control manager.

## Installation

deno

```sh
deno add jsr:@marianmeres/rbac
```

nodejs

```sh
npx jsr add @marianmeres/rbac
```

## Usage

```ts
import { Rbac } from "@marianmeres/rbac";
```

## Basic example

```ts
const rbac = new Rbac();

// let's say we're modeling the actual permission value as an "entity:action"...
rbac
    // define group permissions
    .addGroup("admins", ["*:*"])
    .addGroup("editors", ["article:read", "article:update"])
    // define roles with permissions and group memberships
    .addRole("admin", [], ["admins"])
    .addRole("editor", [], ["editors"])
    .addRole("user", ["article:read"], []);

// check permissions
assert(rbac.hasPermission("admin", "*:*"));
assert(!rbac.hasPermission("editor", "article:*"));
assert(rbac.hasPermission("editor", "article:update"));
assert(!rbac.hasPermission("user", "article:update"));

// configuration can be serialized (and restored)
const dump = rbac.dump();
assert(typeof dump === "string");
const rbac2 = Rbac.restore(dump);
assert(rbac2.hasPermission("editor", "article:update"));

// example helper using `hasSomePermission` api
const canReadArticle = (role: string) =>
    rbac.hasSomePermission(role, ["*:*", "article:*", "article:read"]);

assert(canReadArticle("user"));
```