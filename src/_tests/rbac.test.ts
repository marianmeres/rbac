import { Rbac } from "../rbac.ts";
import { assert, assertEquals, assertThrows } from "@std/assert";

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

	// console.log(rbac.toJSON());
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

Deno.test("group must exist before being added to role", () => {
	const rbac = new Rbac();
	assertThrows(() => rbac.addRole("role", [], ["some"]));
});

Deno.test("readme example", () => {
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
});
