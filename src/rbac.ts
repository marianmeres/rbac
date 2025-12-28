// deno-lint-ignore-file no-explicit-any

/** Internal roles data structure */
export interface RbacRoleInternal {
	permissions: Set<string>;
	memberOf: Set<string>;
}

/** Internal groups data structure */
export interface RbacGroupInternal {
	permissions: Set<string>;
}

/**
 * Serializable representation of the RBAC configuration.
 * Used for exporting and restoring RBAC state.
 */
export interface RbacDump {
	/** Map of role names to their permissions and group memberships */
	roles: Record<string, Partial<Record<"permissions" | "memberOf", string[]>>>;
	/** Map of group names to their permissions */
	groups: Record<string, Partial<Record<"permissions", string[]>>>;
}

/**
 * Rule function for attribute-based access control (ABAC).
 * Returns true if access should be granted based on subject, resource, and context attributes.
 *
 * @param subject - Object containing user/role information and attributes
 * @param resource - Optional resource object with attributes to check against
 * @param context - Optional context object (e.g., time, IP address, request metadata)
 * @returns True if the rule allows access, false otherwise
 */
export type RbacRuleFunction = (
	subject: Record<string, any>,
	resource?: Record<string, any>,
	context?: Record<string, any>
) => boolean;

/**
 * Basic Role-Based-Access-Control manager.
 *
 * @example
 * ```ts
 * const rbac = new Rbac();
 *
 * // let's say we're modeling the actual permission value as an "entity:action"...
 * rbac
 *     // define group permissions
 *     .addGroup("admins", ["*:*"])
 *     .addGroup("editors", ["article:read", "article:update"])
 *     // define roles with permissions and group memberships
 *     .addRole("admin", [], ["admins"])
 *     .addRole("editor", [], ["editors"])
 *     .addRole("user", ["article:read"], []);
 *
 * // check permissions
 * assert(rbac.hasPermission("admin", "*:*"));
 * assert(!rbac.hasPermission("editor", "article:*"));
 * assert(rbac.hasPermission("editor", "article:update"));
 * assert(!rbac.hasPermission("user", "article:update"));
 *
 * // configuration can be serialized (and restored)
 * const dump = rbac.dump();
 * assert(typeof dump === "string");
 * const rbac2 = Rbac.restore(dump);
 * assert(rbac2.hasPermission("editor", "article:update"));
 *
 * // example helper using `hasSomePermission` api
 * const canReadArticle = (role: string) =>
 *     rbac.hasSomePermission(role, ["*:*", "article:*", "article:read"]);
 *
 * assert(canReadArticle("user"));
 * ```
 */
export class Rbac {
	#roles = new Map<string, RbacRoleInternal>();
	#groups = new Map<string, RbacGroupInternal>();
	#rules = new Map<string, RbacRuleFunction>();

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
			this.#groups.set(name, { permissions: new Set() });
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
		groupNames: string[] = []
	): Rbac {
		const role = this.#initRole(name);
		permissions.forEach((permName) => role.permissions.add(permName));
		groupNames.forEach((groupName) => {
			if (!this.#groups.has(groupName)) {
				throw new Error(`Group '${groupName}' does not exist`);
			}
			role.memberOf.add(groupName);
		});
		return this;
	}

	/**
	 * Removes specific permissions from a role.
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
		if (this.#roles.has(name)) {
			const role = this.#roles.get(name);
			permissions.forEach((permName) => role!.permissions.delete(permName));
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
	 *
	 * @example
	 * ```ts
	 * if (rbac.hasRole("admin")) { ... }
	 * ```
	 */
	hasRole(name: string): boolean {
		return this.#roles.has(name);
	}

	/**
	 * Returns an array of all role names.
	 *
	 * @returns Array of role names
	 *
	 * @example
	 * ```ts
	 * const roles = rbac.getRoles(); // ["admin", "editor", "user"]
	 * ```
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
	 * rbac.addGroup("admins", ["*:*"]);
	 * ```
	 */
	addGroup(name: string, permissions: string[] = []): Rbac {
		const group = this.#initGroup(name);
		permissions.forEach((permName) => group.permissions.add(permName));
		return this;
	}

	/**
	 * Removes specific permissions from a group.
	 *
	 * @param name - The group name
	 * @param permissions - Array of permission strings to remove
	 * @returns The Rbac instance for method chaining
	 *
	 * @example
	 * ```ts
	 * rbac.removeGroupPermissions("editors", ["article:delete"]);
	 * ```
	 */
	removeGroupPermissions(name: string, permissions: string[] = []): Rbac {
		if (this.#groups.has(name)) {
			const group = this.#groups.get(name);
			permissions.forEach((permName) => group!.permissions.delete(permName));
		}
		return this;
	}

	/**
	 * Removes a group entirely from the RBAC system.
	 * Note: Roles that are members of this group will no longer inherit its permissions.
	 *
	 * @param name - The group name to remove
	 * @returns The Rbac instance for method chaining
	 *
	 * @example
	 * ```ts
	 * rbac.removeGroup("guests");
	 * ```
	 */
	removeGroup(name: string): Rbac {
		this.#groups.delete(name);
		// Clean up group references from roles
		for (const role of this.#roles.values()) {
			role.memberOf.delete(name);
		}
		return this;
	}

	/**
	 * Checks if a group exists in the RBAC system.
	 *
	 * @param name - The group name to check
	 * @returns True if the group exists, false otherwise
	 *
	 * @example
	 * ```ts
	 * if (rbac.hasGroup("admins")) { ... }
	 * ```
	 */
	hasGroup(name: string): boolean {
		return this.#groups.has(name);
	}

	/**
	 * Returns an array of all group names.
	 *
	 * @returns Array of group names
	 *
	 * @example
	 * ```ts
	 * const groups = rbac.getGroups(); // ["admins", "editors"]
	 * ```
	 */
	getGroups(): string[] {
		return [...this.#groups.keys()];
	}

	/**
	 * Adds a role to a group, allowing it to inherit the group's permissions.
	 *
	 * @param roleName - The role name
	 * @param groupName - The group name to add the role to
	 * @returns The Rbac instance for method chaining
	 * @throws Error if the group doesn't exist
	 *
	 * @example
	 * ```ts
	 * rbac.addRoleToGroup("editor", "content-managers");
	 * ```
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
	 * Removes a role from a group, stopping it from inheriting the group's permissions.
	 *
	 * @param roleName - The role name
	 * @param groupName - The group name to remove the role from
	 * @returns The Rbac instance for method chaining
	 *
	 * @example
	 * ```ts
	 * rbac.removeRoleFromGroup("editor", "content-managers");
	 * ```
	 */
	removeRoleFromGroup(roleName: string, groupName: string): Rbac {
		if (this.#roles.has(roleName)) {
			const role = this.#roles.get(roleName)!;
			role.memberOf.delete(groupName);
		}
		return this;
	}

	/**
	 * Returns the full set of permissions for a role, including inherited group permissions.
	 *
	 * @param roleName - The role name
	 * @returns Set of all permissions (direct and inherited)
	 *
	 * @example
	 * ```ts
	 * const perms = rbac.getPermissions("editor");
	 * // Set { "article:read", "article:update", ... }
	 * ```
	 */
	getPermissions(roleName: string): Set<string> {
		let out = new Set<string>();

		const role = this.#roles.get(roleName);
		if (!role) return out;

		// 1. collect group permissions the given role is a member of
		for (const groupName of role.memberOf) {
			const group = this.#groups.get(groupName);
			if (group) {
				out = out.union(group.permissions);
			}
		}

		// 2. union with its own permissions
		return out.union(role.permissions);
	}

	/**
	 * Checks if a role has a specific permission (direct or inherited).
	 *
	 * @param roleName - The role name
	 * @param permission - The permission to check
	 * @returns True if the role has the permission, false otherwise
	 *
	 * @example
	 * ```ts
	 * if (rbac.hasPermission("editor", "article:update")) {
	 *   // Allow update
	 * }
	 * ```
	 */
	hasPermission(roleName: string, permission: string): boolean {
		return this.getPermissions(roleName).has(permission);
	}

	/**
	 * Checks if a role has at least one of the given permissions.
	 * Useful for implementing OR-based permission checks.
	 *
	 * @param roleName - The role name
	 * @param permissions - Array of permissions to check
	 * @returns True if the role has at least one of the permissions, false otherwise
	 *
	 * @example
	 * ```ts
	 * // Check if user can read articles (via any permission)
	 * const canRead = rbac.hasSomePermission("user", [
	 *   "*:*",
	 *   "article:*",
	 *   "article:read"
	 * ]);
	 * ```
	 */
	hasSomePermission(roleName: string, permissions: string[]): boolean {
		const all = this.getPermissions(roleName);
		for (const perm of permissions) {
			if (all.has(perm)) return true;
		}
		return false;
	}

	/**
	 * Adds a conditional rule for attribute-based access control (ABAC).
	 * Rules are evaluated after basic RBAC permission checks pass.
	 *
	 * @param permission - The permission string to attach this rule to
	 * @param rule - Function that evaluates subject, resource, and context attributes
	 * @returns The Rbac instance for method chaining
	 *
	 * @example
	 * ```ts
	 * // Authors can only edit their own draft articles
	 * rbac.addRule("article:update", (subject, resource) => {
	 *   if (subject.role === "author") {
	 *     return resource.authorId === subject.id && resource.status === "draft";
	 *   }
	 *   return true; // Admins can edit anything
	 * });
	 * ```
	 */
	addRule(permission: string, rule: RbacRuleFunction): Rbac {
		this.#rules.set(permission, rule);
		return this;
	}

	/**
	 * Removes a rule for a specific permission.
	 *
	 * @param permission - The permission to remove the rule from
	 * @returns The Rbac instance for method chaining
	 *
	 * @example
	 * ```ts
	 * rbac.removeRule("article:update");
	 * ```
	 */
	removeRule(permission: string): Rbac {
		this.#rules.delete(permission);
		return this;
	}

	/**
	 * Checks if a rule exists for a specific permission.
	 *
	 * @param permission - The permission to check
	 * @returns True if a rule exists, false otherwise
	 *
	 * @example
	 * ```ts
	 * if (rbac.hasRule("article:update")) { ... }
	 * ```
	 */
	hasRule(permission: string): boolean {
		return this.#rules.has(permission);
	}

	/**
	 * Returns all permissions that have rules attached.
	 *
	 * @returns Array of permission names with rules
	 *
	 * @example
	 * ```ts
	 * const ruledPerms = rbac.getRules(); // ["article:update", "article:delete"]
	 * ```
	 */
	getRules(): string[] {
		return [...this.#rules.keys()];
	}

	/**
	 * Checks if a subject can perform an action, with optional ABAC rule evaluation.
	 * This method first checks basic RBAC permissions, then evaluates any attached rules.
	 *
	 * @param subject - Object with at least a 'role' property, plus any other attributes
	 * @param permission - The permission to check
	 * @param resource - Optional resource object with attributes to check against
	 * @param context - Optional context object (time, IP, metadata, etc.)
	 * @returns True if access is granted (RBAC + rules), false otherwise
	 *
	 * @example
	 * ```ts
	 * // Basic RBAC check
	 * rbac.can({ role: "admin" }, "article:delete");
	 *
	 * // ABAC check with resource
	 * rbac.can(
	 *   { role: "author", id: "user123" },
	 *   "article:update",
	 *   { authorId: "user123", status: "draft" }
	 * );
	 *
	 * // ABAC check with context
	 * rbac.can(
	 *   { role: "editor" },
	 *   "article:publish",
	 *   { status: "reviewed" },
	 *   { currentTime: new Date() }
	 * );
	 * ```
	 */
	can(
		subject: { role: string; [key: string]: any },
		permission: string,
		resource?: Record<string, any>,
		context?: Record<string, any>
	): boolean {
		// 1. First check basic RBAC permission
		if (!this.hasPermission(subject.role, permission)) {
			return false;
		}

		// 2. If no rule exists, RBAC check is sufficient
		if (!this.#rules.has(permission)) {
			return true;
		}

		// 3. Evaluate the rule
		const rule = this.#rules.get(permission)!;
		return rule(subject, resource, context);
	}

	/**
	 * Returns the internal data structure as a plain object.
	 * Useful for serialization and inspection.
	 *
	 * @returns Plain object representation of roles and groups
	 *
	 * @example
	 * ```ts
	 * const data = rbac.toJSON();
	 * console.log(data.roles);
	 * console.log(data.groups);
	 * ```
	 */
	toJSON(): RbacDump {
		const serialize = (
			map: Map<string, RbacRoleInternal | RbacGroupInternal>
		) => {
			return [...map].reduce((m, [k, v]) => {
				m[k] = Object.entries(v).reduce((m2, [k2, v2]) => {
					m2[k2] = [...v2];
					return m2;
				}, {} as Record<string, string[]>);
				return m;
			}, {} as Record<string, Record<string, string[]>>);
		};

		return {
			roles: serialize(this.#roles),
			groups: serialize(this.#groups),
		};
	}

	/**
	 * Returns the internal data structure as a JSON string.
	 * Use with `Rbac.restore()` to recreate the RBAC configuration.
	 *
	 * @returns JSON string representation
	 *
	 * @example
	 * ```ts
	 * const dump = rbac.dump();
	 * localStorage.setItem("rbac", dump);
	 * // Later...
	 * const rbac2 = Rbac.restore(localStorage.getItem("rbac"));
	 * ```
	 */
	dump(): string {
		return JSON.stringify(this);
	}

	/**
	 * Creates a new Rbac instance from a dump (JSON string or object).
	 * Groups must be defined before roles that reference them.
	 *
	 * @param dump - JSON string or RbacDump object
	 * @returns New Rbac instance with restored configuration
	 * @throws Error if dump is invalid or cannot be parsed
	 *
	 * @example
	 * ```ts
	 * const dump = rbac.dump();
	 * const rbac2 = Rbac.restore(dump);
	 * ```
	 */
	static restore(dump: string | Partial<RbacDump>): Rbac {
		const rbac = new Rbac();
		try {
			const data: Partial<RbacDump> =
				typeof dump === "string" ? JSON.parse(dump) : dump;

			Object.entries(data.groups || {}).forEach(([name, o]) => {
				rbac.addGroup(name, o.permissions);
			});

			Object.entries(data.roles || {}).forEach(([name, o]) => {
				rbac.addRole(name, o.permissions, o.memberOf);
			});
		} catch (_e: any) {
			throw new Error(`Unable to restore dump: ${_e}`);
		}

		return rbac;
	}
}
