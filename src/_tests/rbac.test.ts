import { assert, assertThrows } from "@std/assert";
import { Rbac } from "../rbac.ts";

const doTest = (rbac: Rbac) => {
	// true
	assert(rbac.hasPermission("role1", "action1"));
	assert(rbac.hasPermission("role1", "action2"));
	assert(rbac.hasPermission("role1", "action3"));

	assert(rbac.hasPermission("role2", "action1"));
	assert(rbac.hasPermission("role2", "action4"));

	// false
	assert(!rbac.hasPermission("role1", "action4"));
	assert(!rbac.hasPermission("role2", "action3"));

	assert(!rbac.hasPermission("role1", "unknown"));
	assert(!rbac.hasPermission("unknown", "action1"));
	assert(!rbac.hasPermission("unknown", "unknown"));
};

Deno.test("roles", () => {
	const rbac = new Rbac();

	rbac
		.addRole("role1", ["action1", "action2"])
		.addRole("role1", ["action3"])
		.addRole("role2", ["action1", "action4"]);

	doTest(rbac);
	doTest(Rbac.restore(rbac.dump()));

	// now remove role perm
	rbac.removeRolePermissions("role1", ["action1"]);
	assert(!rbac.hasPermission("role1", "action1"));
});

Deno.test("groups", () => {
	const rbac = new Rbac();

	rbac
		.addGroup("group1", ["action1", "action2"])
		.addGroup("group1", ["action3"])
		.addGroup("group2", ["action1", "action4"])
		.addRole("role1", [], ["group1"])
		.addRole("role2", [], ["group2"]);

	doTest(rbac);
	doTest(Rbac.restore(rbac.dump()));

	// now remove group perm
	rbac.removeGroupPermissions("group1", ["action1"]);
	assert(!rbac.hasPermission("role1", "action1"));
});

Deno.test("roles and groups", () => {
	const rbac = new Rbac();

	rbac
		.addGroup("group1", ["action1", "action2"])
		.addGroup("group2", ["action4"])
		.addRole("role1", ["action3"], ["group1"])
		.addRole("role2", ["action1"], ["group2"]);

	doTest(rbac);
	doTest(Rbac.restore(rbac.dump()));
});

Deno.test("partial manual restore", () => {
	// just for the sake of visual explicitness...
	const rbac = Rbac.restore({
		groups: {
			group1: { permissions: ["action1", "action2"] },
			group2: {}, // partial
		},
		roles: {
			role1: { permissions: ["action3"], memberOf: ["group1"] },
			role2: { permissions: ["action1", "action4"] }, // partial
			role3: { memberOf: ["group1"] }, // partial
			role4: {}, // partial
		},
	});
	doTest(rbac);

	assert(!rbac.hasPermission("role4", "action1"));
});

Deno.test("group must exist before being added to role", () => {
	const rbac = new Rbac();
	assertThrows(() => rbac.addRole("role", [], ["some"]));
});

Deno.test("readme example", () => {
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

	// example helper using some
	const canReadArticle = (role: string) =>
		rbac.hasSomePermission(role, ["*:*", "article:*", "article:read"]);

	assert(canReadArticle("user"));
});
