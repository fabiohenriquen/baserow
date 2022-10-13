import { Registerable } from '@baserow/modules/core/registry'

/**
 */
export class PermissionManagerType extends Registerable {
  hasPermission(permissions, operation, context) {}

  /**
   * The order value used to sort admin types in the sidebar menu.
   */
  getOrder() {
    return 0
  }
}

export class CorePermissionManagerType extends PermissionManagerType {
  static getType() {
    return 'core'
  }

  hasPermission(permissions, operation, context) {
    if (permissions.includes(operation)) {
      return true
    }
  }
}

export class StaffPermissionManagerType extends PermissionManagerType {
  static getType() {
    return 'staff'
  }

  hasPermission(permissions, operation, context) {
    if (permissions.staff_only_operations.includes(operation)) {
      return permissions.is_staff
    }
  }
}

export class GroupMemberPermissionManagerType extends PermissionManagerType {
  static getType() {
    return 'member'
  }

  hasPermission(permissions, operation, context) {
    return permissions
  }
}

export class BasicPermissionManagerType extends PermissionManagerType {
  static getType() {
    return 'basic'
  }

  hasPermission(permissions, operation, context) {
    // Is it an admin only operation?
    if (permissions.admin_only_operation.includes(operation)) {
      // yes, so it should be an admin of the group
      if (permissions.is_admin) {
        // It is!
        return true
      }
    } else {
      // It's a member and it's a non admin only operation.
      return true
    }
    // None of the above applied
    return false
  }
}