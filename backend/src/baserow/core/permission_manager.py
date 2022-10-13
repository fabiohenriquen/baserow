from rest_framework.exceptions import NotAuthenticated

from baserow.core.models import GroupUser

from .exceptions import (
    IsNotAdminError,
    UserInvalidGroupPermissionsError,
    UserNotInGroup,
)
from .registries import PermissionManagerType


class CorePermissionManagerType(PermissionManagerType):
    type = "core"

    ALWAYS_ALLOWED_OPERATIONS = ["create_group", "list_groups"]

    def check_permissions(
        self, actor, operation, group=None, context=None, include_trash=False
    ):

        if operation in self.ALWAYS_ALLOWED_OPERATIONS:
            return True

    def get_permissions_object(self, actor, group=None):
        return self.ALWAYS_ALLOWED_OPERATIONS


class StaffOnlyPermissionManagerType(PermissionManagerType):
    type = "staff"
    STAFF_ONLY_OPERATIONS = ["settings.update"]

    def check_permissions(
        self, actor, operation, group=None, context=None, include_trash=False
    ):

        if hasattr(actor, "is_authenticated"):
            user = actor
            if not user.is_authenticated:
                raise NotAuthenticated()

            if operation in self.STAFF_ONLY_OPERATIONS:
                if actor.is_staff:
                    return True
                else:
                    raise IsNotAdminError(user)

    def get_permissions_object(self, actor, group=None):
        return {
            "staff_only_operations": self.STAFF_ONLY_OPERATIONS,
            "is_staff": actor.is_staff,
        }


class GroupMemberOnlyPermissionManagerType(PermissionManagerType):
    type = "member"

    def check_permissions(
        self, actor, operation, group=None, context=None, include_trash=False
    ):
        if group is None:
            return None

        if hasattr(actor, "is_authenticated"):
            user = actor
            if not user.is_authenticated:
                raise NotAuthenticated()

            if include_trash:
                queryset = GroupUser.objects_and_trash
            else:
                queryset = GroupUser.objects

            # Check if the user is a member of this group
            if not queryset.filter(user_id=user.id, group_id=group.id).exists():
                raise UserNotInGroup(user, group)

    def get_permissions_object(self, actor, group=None):
        # Check if the user is a member of this group
        return GroupUser.objects.filter(user_id=actor.id, group_id=group.id).exists()


class BasicPermissionManagerType(PermissionManagerType):
    type = "basic"

    ADMIN_ONLY_OPERATIONS = set(
        [
            "group.list_invitations",
            "group.create_invitation",
            "invitation.read",
            "invitation.update",
            "invitation.delete",
            "group.list_group_users",
            "group.update",
            "group.delete",
            "group_user.update",
            "group_user.delete",
        ]
    )

    def check_permissions(
        self, actor, operation, group=None, context=None, include_trash=False
    ):

        if group is None:
            return None

        if hasattr(actor, "is_authenticated"):
            user = actor
            if not user.is_authenticated:
                raise NotAuthenticated()

            if operation in self.ADMIN_ONLY_OPERATIONS:

                if include_trash:
                    manager = GroupUser.objects_and_trash
                else:
                    manager = GroupUser.objects

                queryset = manager.filter(user_id=user.id, group_id=group.id)

                # Check if the user is a member of this group
                group_user = queryset.get()

                if "ADMIN" not in group_user.permissions:
                    raise UserInvalidGroupPermissionsError(user, group, operation)

            return True

    def get_permissions_object(self, actor, group=None, include_trash=False):
        if group is None:
            return None

        if include_trash:
            manager = GroupUser.objects_and_trash
        else:
            manager = GroupUser.objects

        queryset = manager.filter(user_id=actor.id, group_id=group.id)

        try:
            # Check if the user is a member of this group
            group_user = queryset.get()
        except GroupUser.DoesNotExist:
            return None

        return {
            "admin_only_operations": self.ADMIN_ONLY_OPERATIONS,
            "is_admin": "ADMIN" in group_user.permissions,
        }