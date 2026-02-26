from rest_framework import permissions

from .constants import Roles


class VaultPermission(permissions.BasePermission):
    """
    Custom permission class for vault operations based on Django groups
    """
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        # Superusers have all permissions
        if request.user.is_superuser:
            return True
        
        user_groups = request.user.groups.values_list('name', flat=True)
        
        # Check if user has any vault-related group
        has_vault_access = any(group in Roles.ALL for group in user_groups)

        if not has_vault_access:
            return False

        # Permission checks based on action
        if view.action in ['list', 'retrieve']:
            # All vault users can view
            return True
        elif view.action in ['create', 'update', 'partial_update']:
            # Vault Admin and Editor can create/update
            return Roles.ADMIN in user_groups or Roles.EDITOR in user_groups
        elif view.action == 'destroy':
            # Only Vault Admin can delete
            return Roles.ADMIN in user_groups
        
        return False
    
    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False
        
        # Superusers have all permissions
        if request.user.is_superuser:
            return True
        
        user_groups = request.user.groups.values_list('name', flat=True)
        
        # Vault Admin has access to all entries
        if Roles.ADMIN in user_groups:
            return True

        # Vault Editor can view/edit all entries but only delete their own
        if Roles.EDITOR in user_groups:
            if view.action == 'destroy':
                return obj.owner == request.user
            return True

        # Vault Viewer can only view entries they own
        if Roles.VIEWER in user_groups:
            if view.action in ['update', 'partial_update', 'destroy']:
                return False
            return obj.owner == request.user

        return False


class CredentialTypePermission(permissions.BasePermission):
    """
    Custom permission class for credential type operations
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        # Superusers have all permissions
        if request.user.is_superuser:
            return True

        user_groups = request.user.groups.values_list('name', flat=True)

        # Check if user has any vault-related group
        has_vault_access = any(group in Roles.ALL for group in user_groups)

        if not has_vault_access:
            return False

        # Permission checks based on action
        if view.action in ['list', 'retrieve']:
            # All vault users can view credential types
            return True
        elif view.action in ['create', 'update', 'partial_update', 'destroy']:
            # Only Vault Admin can modify credential types
            return Roles.ADMIN in user_groups

        return False


class IsOwnerOrVaultAdmin(permissions.BasePermission):
    """
    Permission that allows vault admins or owners to access objects
    """

    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False

        # Superusers have all permissions
        if request.user.is_superuser:
            return True

        # Vault Admin has access to all entries
        user_groups = request.user.groups.values_list('name', flat=True)
        if Roles.ADMIN in user_groups:
            return True

        # Check if user is the owner
        return obj.owner == request.user


class VaultViewerReadOnly(permissions.BasePermission):
    """
    Permission that allows read-only access for vault viewers
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        # Superusers have all permissions
        if request.user.is_superuser:
            return True

        user_groups = request.user.groups.values_list('name', flat=True)

        # Check if user has vault viewer access
        if Roles.VIEWER in user_groups:
            return request.method in permissions.SAFE_METHODS

        # Other vault groups have full permissions
        return Roles.ADMIN in user_groups or Roles.EDITOR in user_groups