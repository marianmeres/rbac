// deno-lint-ignore-file no-explicit-any

/** Internal roles data structure */
export interface RbacRoleInternal {
	permissions: Set<string>;
	memberOf: Set<string>;
}

/**
 * Internal groups data structure.
 *
 * Groups can themselves be members of other groups (group-to-group inheritance).
 * Traversal handles cycles gracefully, so a circular membership is a no-op rather
 * than an error.
 */
export interface RbacGroupInternal {
	permissions: Set<string>;
	memberOf: Set<string>;
}

/**
 * Serializable representation of the RBAC configuration.
 * Used for exporting and restoring RBAC state.
 */
export interface RbacDump {
	/** Map of role names to their permissions and group memberships */
	roles: Record<string, Partial<Record<"permissions" | "memberOf", string[]>>>;
	/** Map of group names to their permissions and (parent) group memberships */
	groups: Record<string, Partial<Record<"permissions" | "memberOf", string[]>>>;
	/**
	 * Permissions that had ABAC rules attached at dump time. Rule functions are
	 * not serialized; this list lets consumers detect missing rules after
	 * `Rbac.restore()` via `getMissingRules()`.
	 */
	rules?: string[];
}

/**
 * Default subject shape accepted by `can()` and rule functions.
 *
 * `role` may be a single string or an array of strings for multi-role subjects.
 */
export interface RbacSubject {
	role: string | string[];
	[key: string]: any;
}

/**
 * Rule function for attribute-based access control (ABAC).
 * Returns true if access should be granted based on subject, resource, and context attributes.
 *
 * The type is generic so callers can narrow `subject`, `resource`, and `context`
 * shapes per rule. All parameters default to permissive `Record<string, any>` /
 * `RbacSubject` to stay compatible with un-typed usage.
 *
 * @param subject - Object containing user/role information and attributes
 * @param resource - Optional resource object with attributes to check against
 * @param context - Optional context object (e.g., time, IP address, request metadata)
 * @returns True if the rule allows access, false otherwise
 */
export type RbacRuleFunction<
	Subject extends RbacSubject = RbacSubject,
	Resource extends Record<string, any> = Record<string, any>,
	Context extends Record<string, any> = Record<string, any>,
> = (subject: Subject, resource?: Resource, context?: Context) => boolean;

/**
 * Detailed result of an `explainPermission()` lookup. Useful for auditing.
 *
 * `path` traces how the permission was derived:
 * - `[]` if not granted
 * - `[roleName]` for a direct role permission
 * - `[roleName, groupName, ...]` for an inherited permission, listing the
 *   group chain (closest ancestor first)
 */
export interface RbacPermissionExplanation {
	granted: boolean;
	source: "role" | "group" | null;
	path: string[];
}

/**
 * Basic Role-Based-Access-Control manager.
 *
 * @example
 * ```ts
 * const rbac = new Rbac();
 *
 * rbac
 *     // group permissions
 *     .addGroup("system-admin", ["system:admin"])
 *     .addGroup("editors", ["article:read", "article:update"])
 *     // roles with permissions and group memberships
 *     .addRole("admin", [], ["system-admin"])
 *     .addRole("editor", [], ["editors"])
 *     .addRole("user", ["article:read"], []);
 *
 * assert(rbac.hasPermission("admin", "system:admin"));
 * assert(rbac.hasPermission("editor", "article:update"));
 * assert(!rbac.hasPermission("user", "article:update"));
 *
 * // configuration can be serialized (and restored)
 * const dump = rbac.dump();
 * const rbac2 = Rbac.restore(dump);
 * assert(rbac2.hasPermission("editor", "article:update"));
 *
 * // OR-style helper
 * const canRead = (role: string) =>
 *     rbac.hasSomePermission(role, ["system:admin", "article:read"]);
 *
 * assert(canRead("user"));
 * ```
 */
export class Rbac {
	#roles = new Map<string, RbacRoleInternal>();
	#groups = new Map<string, RbacGroupInternal>();
	#rules = new Map<string, RbacRuleFunction[]>();
	#expectedRules = new Set<string>();

	/**
	 * Creates a new Rbac instance.
	 *
	 * Optionally accepts an initial configuration (same shape as `Rbac.restore()`
	 * argument). Rules are never included in dumps and must be registered separately.
	 *
	 * @param dump - Optional initial configuration as JSON string or `RbacDump` object
	 * @throws Error if the dump cannot be parsed or references missing groups
	 *
	 * @example
	 * ```ts
	 * const rbac = new Rbac();
	 *
	 * // or from a dump
	 * const restored = new Rbac(previousDump);
	 * ```
	 */
	constructor(dump?: string | Partial<RbacDump>) {
		if (dump !== undefined && dump !== null) {
			this.#restoreFrom(dump);
		}
	}

	/** Creates an empty role if it doesn't exist */
	#initRole(name: string): RbacRoleInternal {
		if (!this.#roles.has(name)) {
			this.#roles.set(name, { permissions: new Set(), memberOf: new Set() });
		}
		return this.#roles.get(name)!;
	}

	/** Creates an empty group if it doesn't exist */
	#initGroup(name: string): RbacGroupInternal {
		if (!this.#groups.has(name)) {
			this.#groups.set(name, { permissions: new Set(), memberOf: new Set() });
		}
		return this.#groups.get(name)!;
	}

	/**
	 * Initializes a role, adds permissions, and assigns to groups.
	 * Can be called multiple times to add more permissions/groups to an existing role.
	 *
	 * @param name - The role name
	 * @param permissions - Array of permission strings to add to the role
	 * @param groupNames - Array of group names the role should be a member of
	 * @returns The Rbac instance for method chaining
	 * @throws Error if any of the specified groups don't exist
	 *
	 * @example
	 * ```ts
	 * rbac.addRole("editor", ["article:read", "article:update"], ["editors"]);
	 * ```
	 */
	addRole(
		name: string,
		permissions: string[] = [],
		groupNames: string[] = [],
	): Rbac {
		const role = this.#initRole(name);
		for (const p of permissions) role.permissions.add(p);
		for (const groupName of groupNames) {
			if (!this.#groups.has(groupName)) {
				throw new Error(`Group '${groupName}' does not exist`);
			}
			role.memberOf.add(groupName);
		}
		return this;
	}

	/**
	 * Removes specific permissions from a role.
	 * No-op if the role does not exist.
	 *
	 * @param name - The role name
	 * @param permissions - Array of permission strings to remove
	 * @returns The Rbac instance for method chaining
	 *
	 * @example
	 * ```ts
	 * rbac.removeRolePermissions("editor", ["article:delete"]);
	 * ```
	 */
	removeRolePermissions(name: string, permissions: string[] = []): Rbac {
		const role = this.#roles.get(name);
		if (role) {
			for (const p of permissions) role.permissions.delete(p);
		}
		return this;
	}

	/**
	 * Removes a role entirely from the RBAC system.
	 *
	 * @param name - The role name to remove
	 * @returns The Rbac instance for method chaining
	 *
	 * @example
	 * ```ts
	 * rbac.removeRole("guest");
	 * ```
	 */
	removeRole(name: string): Rbac {
		this.#roles.delete(name);
		return this;
	}

	/**
	 * Checks if a role exists in the RBAC system.
	 *
	 * @param name - The role name to check
	 * @returns True if the role exists, false otherwise
	 */
	hasRole(name: string): boolean {
		return this.#roles.has(name);
	}

	/**
	 * Returns an array of all role names.
	 */
	getRoles(): string[] {
		return [...this.#roles.keys()];
	}

	/**
	 * Initializes a group and adds permissions to it.
	 * Can be called multiple times to add more permissions to an existing group.
	 *
	 * @param name - The group name
	 * @param permissions - Array of permission strings to add to the group
	 * @returns The Rbac instance for method chaining
	 *
	 * @example
	 * ```ts
	 * rbac.addGroup("admins", ["system:admin"]);
	 * ```
	 */
	addGroup(name: string, permissions: string[] = []): Rbac {
		const group = this.#initGroup(name);
		for (const p of permissions) group.permissions.add(p);
		return this;
	}

	/**
	 * Removes specific permissions from a group.
	 * No-op if the group does not exist.
	 *
	 * @param name - The group name
	 * @param permissions - Array of permission strings to remove
	 * @returns The Rbac instance for method chaining
	 */
	removeGroupPermissions(name: string, permissions: string[] = []): Rbac {
		const group = this.#groups.get(name);
		if (group) {
			for (const p of permissions) group.permissions.delete(p);
		}
		return this;
	}

	/**
	 * Removes a group entirely from the RBAC system.
	 * Roles and other groups that were members of this group no longer inherit
	 * its permissions.
	 *
	 * @param name - The group name to remove
	 * @returns The Rbac instance for method chaining
	 */
	removeGroup(name: string): Rbac {
		this.#groups.delete(name);
		for (const role of this.#roles.values()) {
			role.memberOf.delete(name);
		}
		for (const group of this.#groups.values()) {
			group.memberOf.delete(name);
		}
		return this;
	}

	/**
	 * Checks if a group exists in the RBAC system.
	 */
	hasGroup(name: string): boolean {
		return this.#groups.has(name);
	}

	/**
	 * Returns an array of all group names.
	 */
	getGroups(): string[] {
		return [...this.#groups.keys()];
	}

	/**
	 * Adds a role to a group, allowing it to inherit the group's permissions.
	 * Creates the role if it doesn't exist.
	 *
	 * @param roleName - The role name
	 * @param groupName - The group name to add the role to
	 * @returns The Rbac instance for method chaining
	 * @throws Error if the group doesn't exist
	 */
	addRoleToGroup(roleName: string, groupName: string): Rbac {
		if (!this.#groups.has(groupName)) {
			throw new Error(`Group '${groupName}' does not exist`);
		}
		const role = this.#initRole(roleName);
		role.memberOf.add(groupName);
		return this;
	}

	/**
	 * Removes a role from a group.
	 * No-op if the role does not exist.
	 *
	 * @param roleName - The role name
	 * @param groupName - The group name to remove the role from
	 * @returns The Rbac instance for method chaining
	 */
	removeRoleFromGroup(roleName: string, groupName: string): Rbac {
		const role = this.#roles.get(roleName);
		if (role) role.memberOf.delete(groupName);
		return this;
	}

	/**
	 * Makes a group a member of another (parent) group. The child group inherits
	 * the parent's permissions.
	 *
	 * Cycles are detected lazily during traversal (they become no-ops). Both
	 * groups must exist.
	 *
	 * @param childName - The child group name
	 * @param parentName - The parent group name to inherit from
	 * @returns The Rbac instance for method chaining
	 * @throws Error if either group doesn't exist
	 *
	 * @example
	 * ```ts
	 * rbac
	 *     .addGroup("viewers", ["article:read"])
	 *     .addGroup("editors")
	 *     .addGroupToGroup("editors", "viewers");
	 * // "editors" now inherits "article:read" from "viewers"
	 * ```
	 */
	addGroupToGroup(childName: string, parentName: string): Rbac {
		if (!this.#groups.has(parentName)) {
			throw new Error(`Group '${parentName}' does not exist`);
		}
		if (!this.#groups.has(childName)) {
			throw new Error(`Group '${childName}' does not exist`);
		}
		if (childName === parentName) {
			throw new Error(`Group '${childName}' cannot be a member of itself`);
		}
		this.#groups.get(childName)!.memberOf.add(parentName);
		return this;
	}

	/**
	 * Removes a group's membership in another group.
	 * No-op if either group (or the membership) doesn't exist.
	 */
	removeGroupFromGroup(childName: string, parentName: string): Rbac {
		const child = this.#groups.get(childName);
		if (child) child.memberOf.delete(parentName);
		return this;
	}

	/** Collect permissions from a group and its ancestors. */
	#collectGroupPermissions(
		groupName: string,
		out: Set<string>,
		visited: Set<string>,
	): void {
		if (visited.has(groupName)) return;
		visited.add(groupName);
		const group = this.#groups.get(groupName);
		if (!group) return;
		for (const p of group.permissions) out.add(p);
		for (const parent of group.memberOf) {
			this.#collectGroupPermissions(parent, out, visited);
		}
	}

	/** Short-circuit permission check within a group sub-tree. */
	#groupHasPermission(
		groupName: string,
		permission: string,
		visited: Set<string>,
	): boolean {
		if (visited.has(groupName)) return false;
		visited.add(groupName);
		const group = this.#groups.get(groupName);
		if (!group) return false;
		if (group.permissions.has(permission)) return true;
		for (const parent of group.memberOf) {
			if (this.#groupHasPermission(parent, permission, visited)) return true;
		}
		return false;
	}

	/**
	 * Returns the full set of permissions for a role, including permissions
	 * inherited from all (transitively) associated groups.
	 *
	 * @param roleName - The role name
	 * @returns Set of all permissions (direct and inherited)
	 */
	getPermissions(roleName: string): Set<string> {
		const out = new Set<string>();
		const role = this.#roles.get(roleName);
		if (!role) return out;

		for (const p of role.permissions) out.add(p);

		const visited = new Set<string>();
		for (const groupName of role.memberOf) {
			this.#collectGroupPermissions(groupName, out, visited);
		}

		return out;
	}

	/**
	 * Checks if a role has a specific permission (direct or inherited through
	 * groups, including nested groups).
	 *
	 * Short-circuits on first match — does not materialize the full permission
	 * set.
	 */
	hasPermission(roleName: string, permission: string): boolean {
		const role = this.#roles.get(roleName);
		if (!role) return false;
		if (role.permissions.has(permission)) return true;
		const visited = new Set<string>();
		for (const groupName of role.memberOf) {
			if (this.#groupHasPermission(groupName, permission, visited)) return true;
		}
		return false;
	}

	/**
	 * Checks if a role has at least one of the given permissions (OR semantics).
	 */
	hasSomePermission(roleName: string, permissions: string[]): boolean {
		for (const p of permissions) {
			if (this.hasPermission(roleName, p)) return true;
		}
		return false;
	}

	/**
	 * Checks if a role has all of the given permissions (AND semantics).
	 *
	 * An empty `permissions` array returns `true` (vacuous truth).
	 *
	 * @example
	 * ```ts
	 * if (rbac.hasEveryPermission("editor", ["article:read", "article:update"])) {
	 *     // allow batch edit
	 * }
	 * ```
	 */
	hasEveryPermission(roleName: string, permissions: string[]): boolean {
		for (const p of permissions) {
			if (!this.hasPermission(roleName, p)) return false;
		}
		return true;
	}

	/** Walks the group graph looking for a permission; returns the path if found. */
	#findGroupPath(
		groupName: string,
		permission: string,
		visited: Set<string>,
	): string[] | null {
		if (visited.has(groupName)) return null;
		visited.add(groupName);
		const group = this.#groups.get(groupName);
		if (!group) return null;
		if (group.permissions.has(permission)) return [groupName];
		for (const parent of group.memberOf) {
			const sub = this.#findGroupPath(parent, permission, visited);
			if (sub) return [groupName, ...sub];
		}
		return null;
	}

	/**
	 * Returns a detailed explanation of how (or whether) a role derives a given
	 * permission. Useful for auditing and debugging access control decisions.
	 *
	 * @returns An object with `granted`, `source`, and `path` fields.
	 *   - `granted: false` → `source: null`, `path: []`
	 *   - direct role permission → `source: "role"`, `path: [roleName]`
	 *   - inherited → `source: "group"`, `path: [roleName, groupName, ...]`
	 *
	 * @example
	 * ```ts
	 * rbac
	 *     .addGroup("viewers", ["article:read"])
	 *     .addRole("user", [], ["viewers"]);
	 *
	 * rbac.explainPermission("user", "article:read");
	 * // { granted: true, source: "group", path: ["user", "viewers"] }
	 * ```
	 */
	explainPermission(
		roleName: string,
		permission: string,
	): RbacPermissionExplanation {
		const role = this.#roles.get(roleName);
		if (!role) return { granted: false, source: null, path: [] };
		if (role.permissions.has(permission)) {
			return { granted: true, source: "role", path: [roleName] };
		}
		const visited = new Set<string>();
		for (const groupName of role.memberOf) {
			const sub = this.#findGroupPath(groupName, permission, visited);
			if (sub) {
				return { granted: true, source: "group", path: [roleName, ...sub] };
			}
		}
		return { granted: false, source: null, path: [] };
	}

	/**
	 * Returns the full set of permissions for a group, optionally including
	 * permissions inherited from parent groups.
	 *
	 * @param groupName - The group name
	 * @param transitive - If true (default), includes inherited permissions.
	 *   If false, returns only the group's direct permissions.
	 */
	getGroupPermissions(groupName: string, transitive: boolean = true): Set<string> {
		const out = new Set<string>();
		const group = this.#groups.get(groupName);
		if (!group) return out;
		if (!transitive) {
			for (const p of group.permissions) out.add(p);
			return out;
		}
		this.#collectGroupPermissions(groupName, out, new Set());
		return out;
	}

	/**
	 * Returns the names of groups a role belongs to.
	 *
	 * @param roleName - The role name
	 * @param transitive - If true, also includes groups inherited through
	 *   group-to-group membership. Defaults to `false` (direct memberships only).
	 */
	getRoleGroups(roleName: string, transitive: boolean = false): string[] {
		const role = this.#roles.get(roleName);
		if (!role) return [];
		if (!transitive) return [...role.memberOf];
		const visited = new Set<string>();
		for (const g of role.memberOf) this.#collectGroupAncestors(g, visited);
		return [...visited];
	}

	#collectGroupAncestors(groupName: string, visited: Set<string>): void {
		if (visited.has(groupName)) return;
		visited.add(groupName);
		const g = this.#groups.get(groupName);
		if (!g) return;
		for (const parent of g.memberOf) this.#collectGroupAncestors(parent, visited);
	}

	/**
	 * Returns the names of roles that directly list `groupName` in their
	 * `memberOf`. Does not include roles that inherit the group transitively.
	 */
	getGroupRoles(groupName: string): string[] {
		const out: string[] = [];
		for (const [roleName, role] of this.#roles) {
			if (role.memberOf.has(groupName)) out.push(roleName);
		}
		return out;
	}

	/**
	 * Returns the direct parent groups of a group (groups this group is a member of).
	 */
	getGroupParents(groupName: string): string[] {
		const g = this.#groups.get(groupName);
		return g ? [...g.memberOf] : [];
	}

	/**
	 * Returns the direct child groups of a group (groups that are members of this group).
	 */
	getGroupChildren(groupName: string): string[] {
		const out: string[] = [];
		for (const [name, g] of this.#groups) {
			if (g.memberOf.has(groupName)) out.push(name);
		}
		return out;
	}

	/**
	 * Replaces any existing rule chain for `permission` with a single-rule chain
	 * containing `rule`. Use `appendRule()` to compose multiple rules.
	 *
	 * @example
	 * ```ts
	 * rbac.addRule("article:update", (subject, resource) => {
	 *     return resource?.authorId === subject.id;
	 * });
	 * ```
	 */
	addRule(permission: string, rule: RbacRuleFunction): Rbac {
		this.#rules.set(permission, [rule]);
		this.#expectedRules.delete(permission);
		return this;
	}

	/**
	 * Appends a rule to the chain for `permission`. All rules in the chain must
	 * return `true` for `can()` to grant access (AND semantics).
	 *
	 * If no chain exists yet, this acts like `addRule()`.
	 *
	 * @example
	 * ```ts
	 * rbac
	 *     .appendRule("article:update", isOwner)
	 *     .appendRule("article:update", isDuringBusinessHours);
	 * // Both rules must pass.
	 * ```
	 */
	appendRule(permission: string, rule: RbacRuleFunction): Rbac {
		const existing = this.#rules.get(permission);
		if (existing) existing.push(rule);
		else this.#rules.set(permission, [rule]);
		this.#expectedRules.delete(permission);
		return this;
	}

	/**
	 * Removes the entire rule chain for a specific permission.
	 */
	removeRule(permission: string): Rbac {
		this.#rules.delete(permission);
		this.#expectedRules.delete(permission);
		return this;
	}

	/**
	 * Checks if at least one rule is registered for a permission.
	 */
	hasRule(permission: string): boolean {
		const chain = this.#rules.get(permission);
		return chain !== undefined && chain.length > 0;
	}

	/**
	 * Returns all permissions that have rules attached.
	 */
	getRules(): string[] {
		return [...this.#rules.keys()];
	}

	/**
	 * Returns the names of permissions that had rules registered at dump time
	 * but have no rule registered on this instance. Returns `[]` for instances
	 * created without a dump or when all expected rules have been re-added.
	 *
	 * Useful right after `Rbac.restore()` / `new Rbac(dump)` to assert that all
	 * ABAC rules have been re-registered:
	 *
	 * @example
	 * ```ts
	 * const rbac = new Rbac(previousDump);
	 * rbac.addRule("article:update", ownershipRule);
	 * const missing = rbac.getMissingRules();
	 * if (missing.length > 0) {
	 *     throw new Error(`Missing rules: ${missing.join(", ")}`);
	 * }
	 * ```
	 */
	getMissingRules(): string[] {
		return [...this.#expectedRules];
	}

	/**
	 * Checks if a subject can perform an action, with optional ABAC rule evaluation.
	 *
	 * 1. Checks basic RBAC: at least one of the subject's roles must have the
	 *    permission (direct or inherited).
	 * 2. If a rule chain exists for the permission, evaluates all rules; all
	 *    must return `true` (AND semantics).
	 *
	 * @param subject - Object with a `role` property (string or array of strings)
	 *                  plus any additional attributes
	 * @param permission - The permission to check
	 * @param resource - Optional resource object with attributes
	 * @param context - Optional context object (time, IP, metadata, etc.)
	 *
	 * @example
	 * ```ts
	 * rbac.can({ role: "admin" }, "article:delete");
	 *
	 * // multi-role subject
	 * rbac.can({ role: ["author", "reviewer"], id: "u1" }, "article:update", article);
	 *
	 * rbac.can(
	 *     { role: "editor" },
	 *     "article:publish",
	 *     { status: "reviewed" },
	 *     { currentTime: new Date() }
	 * );
	 * ```
	 */
	can(
		subject: RbacSubject,
		permission: string,
		resource?: Record<string, any>,
		context?: Record<string, any>,
	): boolean {
		const roles = Array.isArray(subject.role) ? subject.role : [subject.role];

		let allowed = false;
		for (const r of roles) {
			if (this.hasPermission(r, permission)) {
				allowed = true;
				break;
			}
		}
		if (!allowed) return false;

		const chain = this.#rules.get(permission);
		if (!chain || chain.length === 0) return true;

		for (const rule of chain) {
			if (!rule(subject, resource, context)) return false;
		}
		return true;
	}

	/**
	 * Returns the internal data structure as a plain object.
	 *
	 * The `rules` field (if present) lists permissions that currently have
	 * rules attached — it does NOT contain the rule functions themselves.
	 */
	toJSON(): RbacDump {
		const groups: RbacDump["groups"] = {};
		for (const [name, g] of this.#groups) {
			groups[name] = {
				permissions: [...g.permissions],
				memberOf: [...g.memberOf],
			};
		}
		const roles: RbacDump["roles"] = {};
		for (const [name, r] of this.#roles) {
			roles[name] = {
				permissions: [...r.permissions],
				memberOf: [...r.memberOf],
			};
		}
		const dump: RbacDump = { roles, groups };
		if (this.#rules.size > 0) {
			dump.rules = [...this.#rules.keys()];
		}
		return dump;
	}

	/**
	 * Returns the internal data structure as a JSON string.
	 * Use with `Rbac.restore()` (or `new Rbac(dump)`) to recreate configuration.
	 *
	 * Rule functions are NOT serialized. Their permission names are included as
	 * `rules: string[]` in the dump so that callers can detect missing rules
	 * after restore via `getMissingRules()`.
	 */
	dump(): string {
		return JSON.stringify(this);
	}

	/**
	 * Returns a deep clone of this RBAC instance (including rule chains, which
	 * are not serialized by `dump()`).
	 */
	clone(): Rbac {
		const cloned = new Rbac();
		cloned.#restoreFrom(this.toJSON());
		for (const [perm, chain] of this.#rules) {
			cloned.#rules.set(perm, [...chain]);
			cloned.#expectedRules.delete(perm);
		}
		return cloned;
	}

	#restoreFrom(dump: string | Partial<RbacDump>): void {
		let data: Partial<RbacDump>;
		try {
			data = typeof dump === "string" ? JSON.parse(dump) : dump;
		} catch (e) {
			throw new Error(`Unable to restore dump: invalid JSON`, { cause: e });
		}

		try {
			// Pass 1: create groups (so both role.memberOf and group.memberOf
			// references can be resolved regardless of declaration order).
			for (const [name, g] of Object.entries(data.groups || {})) {
				this.addGroup(name, g.permissions);
			}
			// Pass 2: wire up group-to-group membership.
			for (const [name, g] of Object.entries(data.groups || {})) {
				if (g.memberOf?.length) {
					for (const parent of g.memberOf) {
						this.addGroupToGroup(name, parent);
					}
				}
			}
			// Pass 3: roles (may reference groups created in pass 1).
			for (const [name, r] of Object.entries(data.roles || {})) {
				this.addRole(name, r.permissions, r.memberOf);
			}
			// Track which permissions had rules originally so callers can detect
			// missing rule re-registrations.
			if (Array.isArray(data.rules)) {
				for (const perm of data.rules) this.#expectedRules.add(perm);
			}
		} catch (e) {
			throw new Error(`Unable to restore dump`, { cause: e });
		}
	}

	/**
	 * Creates a new Rbac instance from a dump (JSON string or object).
	 *
	 * Equivalent to `new Rbac(dump)`.
	 *
	 * @throws Error if dump is invalid or references missing groups
	 */
	static restore(dump: string | Partial<RbacDump>): Rbac {
		return new Rbac(dump);
	}
}
