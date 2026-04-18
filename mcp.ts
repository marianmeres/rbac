import { z } from "npm:zod";
import type { McpToolDefinition } from "jsr:@marianmeres/mcp-server/types";
import { Rbac } from "./src/rbac.ts";

const CONFIG_DESC =
	"RBAC configuration as JSON string (RbacDump format with roles and groups; groups may have memberOf for group-to-group inheritance)";

export const tools: McpToolDefinition[] = [
	{
		name: "rbac-check-permission",
		description:
			"Check if a role has a specific permission in an RBAC config, resolving role→group and group→group inheritance. Returns whether access is granted and the full path (role + any groups) through which the permission is derived.",
		params: {
			config: z.string().describe(CONFIG_DESC),
			roleName: z.string().describe("The role name to check"),
			permission: z
				.string()
				.describe("The permission string to check (e.g. 'article:read')"),
		},
		handler: async ({ config, roleName, permission }) => {
			const rbac = Rbac.restore(config as string);
			const explanation = rbac.explainPermission(
				roleName as string,
				permission as string,
			);
			return JSON.stringify({
				granted: explanation.granted,
				source: explanation.source,
				path: explanation.path,
			});
		},
	},
	{
		name: "rbac-list-permissions",
		description:
			"List all effective permissions for a role in an RBAC config, broken down by source (direct permissions vs. inherited from each directly-associated group). Group permissions include transitively inherited ones.",
		params: {
			config: z.string().describe(CONFIG_DESC),
			roleName: z
				.string()
				.describe("The role name to list permissions for"),
		},
		handler: async ({ config, roleName }) => {
			const rbac = Rbac.restore(config as string);
			const all = [...rbac.getPermissions(roleName as string)];

			const direct: string[] = [];
			const fromGroups: Record<string, string[]> = {};

			if (rbac.hasRole(roleName as string)) {
				const dump = rbac.toJSON();
				direct.push(
					...(dump.roles[roleName as string]?.permissions ?? []),
				);
				for (const groupName of rbac.getRoleGroups(roleName as string)) {
					const perms = [...rbac.getGroupPermissions(groupName)];
					if (perms.length > 0) fromGroups[groupName] = perms;
				}
			}

			return JSON.stringify({ permissions: all, direct, fromGroups });
		},
	},
	{
		name: "rbac-validate-config",
		description:
			"Validate an RBAC configuration dump and return diagnostics including errors (invalid references, cycles) and warnings (unused groups, empty roles).",
		params: {
			config: z.string().describe(CONFIG_DESC),
		},
		handler: async ({ config }) => {
			const errors: string[] = [];
			const warnings: string[] = [];

			let dump;
			try {
				dump = typeof config === "string" ? JSON.parse(config as string) : config;
			} catch (e) {
				return JSON.stringify({
					valid: false,
					errors: [`Invalid JSON: ${e}`],
					warnings: [],
				});
			}

			const groupNames = new Set(Object.keys(dump.groups || {}));
			const referencedGroups = new Set<string>();

			// Check roles → group references
			for (
				const [roleName, role] of Object.entries(
					(dump.roles || {}) as Record<string, any>,
				)
			) {
				if (!role.permissions?.length && !role.memberOf?.length) {
					warnings.push(
						`Role '${roleName}' has no permissions and no group memberships`,
					);
				}
				for (const groupName of role.memberOf || []) {
					referencedGroups.add(groupName);
					if (!groupNames.has(groupName)) {
						errors.push(
							`Role '${roleName}' references non-existent group '${groupName}'`,
						);
					}
				}
			}

			// Check group → group references
			for (
				const [groupName, group] of Object.entries(
					(dump.groups || {}) as Record<string, any>,
				)
			) {
				for (const parent of group.memberOf || []) {
					referencedGroups.add(parent);
					if (!groupNames.has(parent)) {
						errors.push(
							`Group '${groupName}' references non-existent parent group '${parent}'`,
						);
					}
					if (parent === groupName) {
						errors.push(
							`Group '${groupName}' is listed as a member of itself`,
						);
					}
				}
			}

			// Unused groups (not referenced by any role or other group)
			for (const groupName of groupNames) {
				if (!referencedGroups.has(groupName)) {
					warnings.push(
						`Group '${groupName}' is not referenced by any role or group`,
					);
				}
			}

			// Verify restore works
			if (errors.length === 0) {
				try {
					Rbac.restore(dump);
				} catch (e) {
					errors.push(`Restore failed: ${e}`);
				}
			}

			return JSON.stringify({
				valid: errors.length === 0,
				errors,
				warnings,
			});
		},
	},
];
