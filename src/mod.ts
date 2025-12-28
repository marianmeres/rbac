/**
 * @module
 *
 * Lightweight, type-safe Role-Based Access Control (RBAC) library for managing
 * permissions through roles and groups. Includes optional Attribute-Based Access
 * Control (ABAC) for fine-grained resource and context-based permissions.
 *
 * @example Basic RBAC usage
 * ```ts
 * import { Rbac } from "@marianmeres/rbac";
 *
 * const rbac = new Rbac();
 *
 * // Define groups and roles
 * rbac
 *   .addGroup("admins", ["*:*"])
 *   .addGroup("editors", ["article:read", "article:update"])
 *   .addRole("admin", [], ["admins"])
 *   .addRole("editor", [], ["editors"]);
 *
 * // Check permissions
 * rbac.hasPermission("admin", "*:*"); // true
 * rbac.hasPermission("editor", "article:update"); // true
 * ```
 *
 * @example ABAC with ownership rules
 * ```ts
 * import { Rbac } from "@marianmeres/rbac";
 *
 * const rbac = new Rbac();
 * rbac
 *   .addRole("author", ["article:update"])
 *   .addRule("article:update", (subject, resource) => {
 *     return resource?.authorId === subject.id;
 *   });
 *
 * rbac.can({ role: "author", id: "user1" }, "article:update", { authorId: "user1" }); // true
 * rbac.can({ role: "author", id: "user1" }, "article:update", { authorId: "user2" }); // false
 * ```
 */
export * from "./rbac.ts";
