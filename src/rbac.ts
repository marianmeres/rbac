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

interface RbacDump {
	roles: Record<string, Record<"permissions" | "memberOf", string[]>>;
	groups: Record<string, Record<"permissions", string[]>>;
}

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

	/** Will create empty role */
	#initRole(name: string): RbacRoleInternal {
		if (!this.#roles.has(name)) {
			this.#roles.set(name, { permissions: new Set(), memberOf: new Set() });
		}
		return this.#roles.get(name)!;
	}

	/** Will create empty group */
	#initGroup(name: string): RbacGroupInternal {
		if (!this.#groups.has(name)) {
			this.#groups.set(name, { permissions: new Set() });
		}
		return this.#groups.get(name)!;
	}

	/** Will initialize role, add permissions, and assing to group. */
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

	/** Will remove permission from role (if exists). */
	removeRolePermissions(name: string, permissions: string[] = []): Rbac {
		if (this.#roles.has(name)) {
			const role = this.#roles.get(name);
			permissions.forEach((permName) => role!.permissions.delete(permName));
		}
		return this;
	}

	/** Will initialize group and add permissions to it. */
	addGroup(name: string, permissions: string[] = []): Rbac {
		const group = this.#initGroup(name);
		permissions.forEach((permName) => group.permissions.add(permName));
		return this;
	}

	/** Will remove permission from group (if exists). */
	removeGroupPermissions(name: string, permissions: string[] = []): Rbac {
		if (this.#groups.has(name)) {
			const group = this.#groups.get(name);
			permissions.forEach((permName) => group!.permissions.delete(permName));
		}
		return this;
	}

	/** Will return the full set of permissions for the given roleName. */
	getPermissions(roleName: string): Set<string> {
		let out = new Set<string>();

		const role = this.#roles.get(roleName);
		if (!role) return out;

		// 1. collect groups permission the given role is a member of
		for (const groupName of role.memberOf) {
			const group = this.#groups.get(groupName);
			if (group) {
				out = out.union(group.permissions);
			}
		}

		// 2. union with its own
		return out.union(role.permissions);
	}

	/** Will check if the given roleName has the given permission. */
	hasPermission(roleName: string, permission: string): boolean {
		return this.getPermissions(roleName).has(permission);
	}

	/** Will check if the given roleName has _some_ (at least one) of the given permissions. */
	hasSomePermission(roleName: string, permissions: string[]): boolean {
		const all = this.getPermissions(roleName);
		for (const perm of permissions) {
			if (all.has(perm)) return true;
		}
		return false;
	}

	/** Returns internal data structure as a plain object. */
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

	/** Returns internal data structure as a json string. */
	dump(): string {
		return JSON.stringify(this);
	}

	/** Will create a new instance from dump. */
	static restore(dump: string | RbacDump): Rbac {
		const rbac = new Rbac();
		try {
			const data: RbacDump = typeof dump === "string" ? JSON.parse(dump) : dump;

			Object.entries(data.groups).forEach(([name, o]) => {
				rbac.addGroup(name, o.permissions);
			});

			Object.entries(data.roles).forEach(([name, o]) => {
				rbac.addRole(name, o.permissions, o.memberOf);
			});
		} catch (_e: any) {
			throw new Error(`Unable to restore dump: ${_e.toString()}`);
		}

		return rbac;
	}
}
