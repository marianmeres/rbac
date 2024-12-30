# @marianmeres/rbac

Basic Role-Based-Access-Credentials manager.

## Instalation

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
rbac
    // define group permissions
    .addGroup("admins", ["create:*", "read:*", "update:*", "delete:*"])
    .addGroup("editors", ["read:articles", "update:articles"])
    // define roles with permissions and group memberships
    .addRole("admin", [], ["admins"])
    .addRole("editor", [], ["editors"])
    .addRole("user", ["read:articles"]);

// check permissions
assert(rbac.hasPermission("admin", "update:*"));
assert(!rbac.hasPermission("editor", "update:*"));
assert(rbac.hasPermission("editor", "update:articles"));
assert(!rbac.hasPermission("user", "update:articles"));

// configuration can be serialized (and restored)
const dump = rbac.dump();
assert(typeof dump === "string");

const rbac2 = Rbac.restore(dump);
assert(rbac2.hasPermission("editor", "update:articles"));
```