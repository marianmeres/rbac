import { assert, assertThrows } from "@std/assert";
import { Rbac } from "../src/rbac.ts";

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

Deno.test("removeRole removes role entirely", () => {
	const rbac = new Rbac();
	rbac.addRole("temp", ["action1", "action2"]);

	assert(rbac.hasRole("temp"));
	assert(rbac.hasPermission("temp", "action1"));

	rbac.removeRole("temp");

	assert(!rbac.hasRole("temp"));
	assert(!rbac.hasPermission("temp", "action1"));
});

Deno.test("removeGroup removes group and cleans up role references", () => {
	const rbac = new Rbac();
	rbac
		.addGroup("temp-group", ["action1", "action2"])
		.addRole("role1", [], ["temp-group"]);

	assert(rbac.hasGroup("temp-group"));
	assert(rbac.hasPermission("role1", "action1"));

	rbac.removeGroup("temp-group");

	assert(!rbac.hasGroup("temp-group"));
	assert(!rbac.hasPermission("role1", "action1"));
	assert(rbac.hasRole("role1")); // role still exists
});

Deno.test("getRoles returns all role names", () => {
	const rbac = new Rbac();
	rbac
		.addRole("admin")
		.addRole("editor")
		.addRole("user");

	const roles = rbac.getRoles();
	assert(roles.length === 3);
	assert(roles.includes("admin"));
	assert(roles.includes("editor"));
	assert(roles.includes("user"));
});

Deno.test("getGroups returns all group names", () => {
	const rbac = new Rbac();
	rbac
		.addGroup("admins")
		.addGroup("editors")
		.addGroup("users");

	const groups = rbac.getGroups();
	assert(groups.length === 3);
	assert(groups.includes("admins"));
	assert(groups.includes("editors"));
	assert(groups.includes("users"));
});

Deno.test("hasRole checks role existence", () => {
	const rbac = new Rbac();
	rbac.addRole("admin");

	assert(rbac.hasRole("admin"));
	assert(!rbac.hasRole("unknown"));
});

Deno.test("hasGroup checks group existence", () => {
	const rbac = new Rbac();
	rbac.addGroup("admins");

	assert(rbac.hasGroup("admins"));
	assert(!rbac.hasGroup("unknown"));
});

Deno.test("addRoleToGroup adds role to existing group", () => {
	const rbac = new Rbac();
	rbac
		.addGroup("managers", ["manage:team"])
		.addRole("supervisor");

	assert(!rbac.hasPermission("supervisor", "manage:team"));

	rbac.addRoleToGroup("supervisor", "managers");

	assert(rbac.hasPermission("supervisor", "manage:team"));
});

Deno.test("addRoleToGroup creates role if it doesn't exist", () => {
	const rbac = new Rbac();
	rbac.addGroup("managers", ["manage:team"]);

	assert(!rbac.hasRole("new-role"));

	rbac.addRoleToGroup("new-role", "managers");

	assert(rbac.hasRole("new-role"));
	assert(rbac.hasPermission("new-role", "manage:team"));
});

Deno.test("addRoleToGroup throws if group doesn't exist", () => {
	const rbac = new Rbac();
	assertThrows(
		() => rbac.addRoleToGroup("role", "nonexistent"),
		Error,
		"Group 'nonexistent' does not exist"
	);
});

Deno.test("removeRoleFromGroup removes role from group", () => {
	const rbac = new Rbac();
	rbac
		.addGroup("editors", ["article:update"])
		.addRole("writer", [], ["editors"]);

	assert(rbac.hasPermission("writer", "article:update"));

	rbac.removeRoleFromGroup("writer", "editors");

	assert(!rbac.hasPermission("writer", "article:update"));
	assert(rbac.hasRole("writer")); // role still exists
});

Deno.test("removeRoleFromGroup handles non-existent role gracefully", () => {
	const rbac = new Rbac();
	rbac.addGroup("editors");

	// Should not throw
	rbac.removeRoleFromGroup("nonexistent", "editors");
});

Deno.test("hasSomePermission returns false when no permissions match", () => {
	const rbac = new Rbac();
	rbac.addRole("user", ["article:read"]);

	assert(!rbac.hasSomePermission("user", [
		"article:update",
		"article:delete",
		"admin:*"
	]));
});

Deno.test("edge case: empty role and group names", () => {
	const rbac = new Rbac();
	rbac
		.addGroup("", ["action1"])
		.addRole("", ["action2"], [""]);

	assert(rbac.hasRole(""));
	assert(rbac.hasGroup(""));
	assert(rbac.hasPermission("", "action1"));
	assert(rbac.hasPermission("", "action2"));
});

Deno.test("edge case: empty permission strings", () => {
	const rbac = new Rbac();
	rbac
		.addGroup("group", [""])
		.addRole("role", [""], ["group"]);

	assert(rbac.hasPermission("role", ""));
	const perms = rbac.getPermissions("role");
	assert(perms.has(""));
});

Deno.test("edge case: very long permission lists", () => {
	const rbac = new Rbac();
	const manyPerms = Array.from({ length: 1000 }, (_, i) => `perm${i}`);

	rbac.addRole("power-user", manyPerms);

	assert(rbac.hasPermission("power-user", "perm0"));
	assert(rbac.hasPermission("power-user", "perm500"));
	assert(rbac.hasPermission("power-user", "perm999"));
	assert(!rbac.hasPermission("power-user", "perm1000"));

	const perms = rbac.getPermissions("power-user");
	assert(perms.size === 1000);
});

Deno.test("edge case: special characters in names", () => {
	const rbac = new Rbac();
	const specialNames = [
		"role:with:colons",
		"role-with-dashes",
		"role_with_underscores",
		"role.with.dots",
		"role with spaces",
		"role@email.com",
		"роль",  // Cyrillic
		"角色",  // Chinese
	];

	specialNames.forEach(name => {
		rbac.addRole(name, [`${name}:action`]);
		assert(rbac.hasRole(name));
		assert(rbac.hasPermission(name, `${name}:action`));
	});
});

Deno.test("edge case: role in multiple groups", () => {
	const rbac = new Rbac();
	rbac
		.addGroup("group1", ["action1"])
		.addGroup("group2", ["action2"])
		.addGroup("group3", ["action3"])
		.addRole("multi", ["action0"], ["group1", "group2", "group3"]);

	assert(rbac.hasPermission("multi", "action0"));
	assert(rbac.hasPermission("multi", "action1"));
	assert(rbac.hasPermission("multi", "action2"));
	assert(rbac.hasPermission("multi", "action3"));

	const perms = rbac.getPermissions("multi");
	assert(perms.size === 4);
});

Deno.test("edge case: removing group affects multiple roles", () => {
	const rbac = new Rbac();
	rbac
		.addGroup("shared", ["shared:action"])
		.addRole("role1", [], ["shared"])
		.addRole("role2", [], ["shared"])
		.addRole("role3", [], ["shared"]);

	assert(rbac.hasPermission("role1", "shared:action"));
	assert(rbac.hasPermission("role2", "shared:action"));
	assert(rbac.hasPermission("role3", "shared:action"));

	rbac.removeGroup("shared");

	assert(!rbac.hasPermission("role1", "shared:action"));
	assert(!rbac.hasPermission("role2", "shared:action"));
	assert(!rbac.hasPermission("role3", "shared:action"));
});

Deno.test("edge case: duplicate permissions are deduplicated", () => {
	const rbac = new Rbac();
	rbac
		.addRole("role", ["action1", "action2"])
		.addRole("role", ["action1", "action3"]); // action1 added again

	const perms = rbac.getPermissions("role");
	assert(perms.size === 3); // Not 4
	assert(perms.has("action1"));
	assert(perms.has("action2"));
	assert(perms.has("action3"));
});

Deno.test("serialization preserves all data after new API usage", () => {
	const rbac = new Rbac();
	rbac
		.addGroup("g1", ["p1"])
		.addGroup("g2", ["p2"])
		.addRole("r1", ["p3"], ["g1"])
		.addRole("r2", ["p4"])
		.addRoleToGroup("r2", "g2")
		.removeRolePermissions("r1", ["p3"]);

	const dump = rbac.dump();
	const rbac2 = Rbac.restore(dump);

	// Verify structure
	assert(rbac2.hasRole("r1"));
	assert(rbac2.hasRole("r2"));
	assert(rbac2.hasGroup("g1"));
	assert(rbac2.hasGroup("g2"));

	// Verify permissions
	assert(!rbac2.hasPermission("r1", "p3")); // was removed
	assert(rbac2.hasPermission("r1", "p1")); // inherited from g1
	assert(rbac2.hasPermission("r2", "p4"));
	assert(rbac2.hasPermission("r2", "p2")); // inherited from g2
});

// ABAC (Attribute-Based Access Control) Tests

Deno.test("ABAC: can() works without rules (RBAC only)", () => {
	const rbac = new Rbac();
	rbac.addRole("admin", ["article:delete"]);

	// Should work just like hasPermission
	assert(rbac.can({ role: "admin" }, "article:delete"));
	assert(!rbac.can({ role: "admin" }, "article:publish"));
});

Deno.test("ABAC: addRule and hasRule", () => {
	const rbac = new Rbac();
	rbac.addRole("author", ["article:update"]);

	assert(!rbac.hasRule("article:update"));

	rbac.addRule("article:update", (subject, resource) => {
		return resource?.authorId === subject.id;
	});

	assert(rbac.hasRule("article:update"));
});

Deno.test("ABAC: can() enforces ownership rule", () => {
	const rbac = new Rbac();
	rbac
		.addRole("author", ["article:update", "article:delete"])
		.addRule("article:update", (subject, resource) => {
			return resource?.authorId === subject.id;
		})
		.addRule("article:delete", (subject, resource) => {
			return resource?.authorId === subject.id && resource?.status === "draft";
		});

	const user1 = { role: "author", id: "user1" };
	const user2 = { role: "author", id: "user2" };
	const article1 = { authorId: "user1", status: "draft" };
	const article2 = { authorId: "user2", status: "published" };

	// User1 can update their own article
	assert(rbac.can(user1, "article:update", article1));

	// User1 cannot update user2's article
	assert(!rbac.can(user1, "article:update", article2));

	// User1 can delete their own draft
	assert(rbac.can(user1, "article:delete", article1));

	// User1 cannot delete published article (even if theirs)
	const publishedByUser1 = { authorId: "user1", status: "published" };
	assert(!rbac.can(user1, "article:delete", publishedByUser1));
});

Deno.test("ABAC: rule fails if RBAC permission missing", () => {
	const rbac = new Rbac();
	rbac
		.addRole("viewer", ["article:read"])
		.addRule("article:update", () => true); // Rule always allows

	// Even though rule returns true, RBAC check fails first
	assert(!rbac.can({ role: "viewer" }, "article:update"));
});

Deno.test("ABAC: multiple roles with different rules", () => {
	const rbac = new Rbac();
	rbac
		.addRole("author", ["article:update"])
		.addRole("editor", ["article:update"])
		.addRole("admin", ["article:update"])
		.addRule("article:update", (subject, resource) => {
			// Authors can only edit their own drafts
			if (subject.role === "author") {
				return resource?.authorId === subject.id && resource?.status === "draft";
			}
			// Editors can edit reviewed articles
			if (subject.role === "editor") {
				return resource?.status === "reviewed";
			}
			// Admins can edit anything
			return true;
		});

	const author = { role: "author", id: "user1" };
	const editor = { role: "editor", id: "user2" };
	const admin = { role: "admin", id: "user3" };

	const draftByAuthor = { authorId: "user1", status: "draft" };
	const reviewedArticle = { authorId: "user1", status: "reviewed" };
	const publishedArticle = { authorId: "user1", status: "published" };

	// Author can edit own draft
	assert(rbac.can(author, "article:update", draftByAuthor));
	// Author cannot edit reviewed article
	assert(!rbac.can(author, "article:update", reviewedArticle));

	// Editor cannot edit draft
	assert(!rbac.can(editor, "article:update", draftByAuthor));
	// Editor can edit reviewed article
	assert(rbac.can(editor, "article:update", reviewedArticle));

	// Admin can edit anything
	assert(rbac.can(admin, "article:update", draftByAuthor));
	assert(rbac.can(admin, "article:update", reviewedArticle));
	assert(rbac.can(admin, "article:update", publishedArticle));
});

Deno.test("ABAC: rules with context parameter", () => {
	const rbac = new Rbac();
	rbac
		.addRole("user", ["article:read"])
		.addRule("article:read", (subject, resource, context) => {
			// Allow reading only during business hours
			const hour = context?.currentHour ?? 12;
			return hour >= 9 && hour < 17;
		});

	const user = { role: "user", id: "user1" };

	// During business hours
	assert(rbac.can(user, "article:read", {}, { currentHour: 10 }));
	assert(rbac.can(user, "article:read", {}, { currentHour: 16 }));

	// Outside business hours
	assert(!rbac.can(user, "article:read", {}, { currentHour: 8 }));
	assert(!rbac.can(user, "article:read", {}, { currentHour: 18 }));
	assert(!rbac.can(user, "article:read", {}, { currentHour: 23 }));
});

Deno.test("ABAC: removeRule removes the rule", () => {
	const rbac = new Rbac();
	rbac
		.addRole("author", ["article:update"])
		.addRule("article:update", (subject, resource) => {
			return resource?.authorId === subject.id;
		});

	const user = { role: "author", id: "user1" };
	const article = { authorId: "user2" };

	// Rule blocks access
	assert(!rbac.can(user, "article:update", article));

	// Remove rule
	rbac.removeRule("article:update");

	// Now only RBAC check applies (no rule)
	assert(rbac.can(user, "article:update", article));
	assert(!rbac.hasRule("article:update"));
});

Deno.test("ABAC: getRules returns all rule permissions", () => {
	const rbac = new Rbac();
	rbac
		.addRule("article:update", () => true)
		.addRule("article:delete", () => true)
		.addRule("comment:moderate", () => true);

	const rules = rbac.getRules();
	assert(rules.length === 3);
	assert(rules.includes("article:update"));
	assert(rules.includes("article:delete"));
	assert(rules.includes("comment:moderate"));
});

Deno.test("ABAC: can() without resource when rule expects it", () => {
	const rbac = new Rbac();
	rbac
		.addRole("author", ["article:update"])
		.addRule("article:update", (subject, resource) => {
			// If no resource provided, deny
			if (!resource) return false;
			return resource.authorId === subject.id;
		});

	const user = { role: "author", id: "user1" };

	// No resource provided - rule denies
	assert(!rbac.can(user, "article:update"));

	// Resource provided - rule allows
	assert(rbac.can(user, "article:update", { authorId: "user1" }));
});

Deno.test("ABAC: complex real-world scenario", () => {
	const rbac = new Rbac();

	// Setup roles
	rbac
		.addGroup("content-creators", ["article:create", "article:read", "article:update"])
		.addGroup("moderators", ["comment:moderate", "article:publish"])
		.addRole("author", [], ["content-creators"])
		.addRole("editor", ["article:publish"], ["content-creators"])
		.addRole("admin", ["article:update", "article:publish", "article:create"], []);

	// Authors can only update their own drafts
	rbac.addRule("article:update", (subject, resource) => {
		if (subject.role === "author") {
			return resource?.authorId === subject.id && resource?.status === "draft";
		}
		return true; // Editors and admins can update anything
	});

	// Only editors can publish reviewed articles
	rbac.addRule("article:publish", (subject, resource) => {
		if (subject.role === "editor") {
			return resource?.status === "reviewed";
		}
		return true; // Admins can publish anything
	});

	const author = { role: "author", id: "alice" };
	const editor = { role: "editor", id: "bob" };
	const admin = { role: "admin", id: "charlie" };

	const aliceDraft = { authorId: "alice", status: "draft" };
	const bobDraft = { authorId: "bob", status: "draft" };
	const reviewedArticle = { authorId: "alice", status: "reviewed" };

	// Author scenarios
	assert(rbac.can(author, "article:create")); // No rule, just RBAC
	assert(rbac.can(author, "article:update", aliceDraft)); // Own draft
	assert(!rbac.can(author, "article:update", bobDraft)); // Not their draft
	assert(!rbac.can(author, "article:update", reviewedArticle)); // Not draft
	assert(!rbac.can(author, "article:publish")); // No permission

	// Editor scenarios
	assert(rbac.can(editor, "article:update", aliceDraft)); // Can update any
	assert(rbac.can(editor, "article:publish", reviewedArticle)); // Can publish reviewed
	assert(!rbac.can(editor, "article:publish", aliceDraft)); // Cannot publish draft

	// Admin scenarios (god mode)
	assert(rbac.can(admin, "article:update", aliceDraft));
	assert(rbac.can(admin, "article:publish", aliceDraft)); // Can publish anything
	assert(rbac.can(admin, "article:publish", reviewedArticle));
});
