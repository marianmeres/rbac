import { z } from "npm:zod";
import type { McpToolDefinition } from "jsr:@marianmeres/mcp-server/types";
import { Rbac } from "./src/rbac.ts";

const CONFIG_DESC =
	"RBAC configuration as JSON string (RbacDump format with roles and groups)";

export const tools: McpToolDefinition[] = [
	{
		name: "rbac-check-permission",
		description:
			"Check if a role has a specific permission in an RBAC config, resolving group inheritance. Returns whether access is granted and how (direct or via which group).",
		params: {
			config: z.string().describe(CONFIG_DESC),
			roleName: z.string().describe("The role name to check"),
			permission: z
				.string()
				.describe(
					"The permission string to check (e.g. 'article:read')"
				),
		},
		handler: async ({ config, roleName, permission }) => {
			const rbac = Rbac.restore(config as string);
			const granted = rbac.hasPermission(
				roleName as string,
				permission as string
			);

			// Trace where the permission comes from
			let via: string | null = null;
			if (granted) {
				const dump =
					typeof config === "string"
						? JSON.parse(config)
						: config;
				const role = dump.roles?.[roleName as string];
				if (role?.permissions?.includes(permission as string)) {
					via = "direct";
				} else if (role?.memberOf) {
					for (const groupName of role.memberOf) {
						const group = dump.groups?.[groupName];
						if (
							group?.permissions?.includes(permission)
						) {
							via = `group:${groupName}`;
							break;
						}
					}
				}
			}

			return JSON.stringify({ granted, via });
		},
	},
	{
		name: "rbac-list-permissions",
		description:
			"List all effective permissions for a role in an RBAC config, broken down by source (direct permissions vs. inherited from each group).",
		params: {
			config: z.string().describe(CONFIG_DESC),
			roleName: z
				.string()
				.describe("The role name to list permissions for"),
		},
		handler: async ({ config, roleName }) => {
			const rbac = Rbac.restore(config as string);
			const all = [...rbac.getPermissions(roleName as string)];

			const dump =
				typeof config === "string"
					? JSON.parse(config as string)
					: config;
			const role = dump.roles?.[roleName as string];
			const direct: string[] = role?.permissions ?? [];
			const fromGroups: Record<string, string[]> = {};

			if (role?.memberOf) {
				for (const groupName of role.memberOf) {
					const group = dump.groups?.[groupName];
					if (group?.permissions?.length) {
						fromGroups[groupName] = group.permissions;
					}
				}
			}

			return JSON.stringify({ permissions: all, direct, fromGroups });
		},
	},
	{
		name: "rbac-validate-config",
		description:
			"Validate an RBAC configuration dump and return diagnostics including errors (invalid references) and warnings (unused groups, empty roles).",
		params: {
			config: z.string().describe(CONFIG_DESC),
		},
		handler: async ({ config }) => {
			const errors: string[] = [];
			const warnings: string[] = [];

			let dump;
			try {
				dump =
					typeof config === "string"
						? JSON.parse(config)
						: config;
			} catch (e) {
				return JSON.stringify({
					valid: false,
					errors: [`Invalid JSON: ${e}`],
					warnings: [],
				});
			}

			const groupNames = new Set(
				Object.keys(dump.groups || {})
			);
			const referencedGroups = new Set<string>();

			// Check roles
			for (const [roleName, role] of Object.entries(
				(dump.roles || {}) as Record<string, any>
			)) {
				if (
					!role.permissions?.length &&
					!role.memberOf?.length
				) {
					warnings.push(
						`Role '${roleName}' has no permissions and no group memberships`
					);
				}
				for (const groupName of role.memberOf || []) {
					referencedGroups.add(groupName);
					if (!groupNames.has(groupName)) {
						errors.push(
							`Role '${roleName}' references non-existent group '${groupName}'`
						);
					}
				}
			}

			// Check for unused groups
			for (const groupName of groupNames) {
				if (!referencedGroups.has(groupName)) {
					warnings.push(
						`Group '${groupName}' is not referenced by any role`
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
