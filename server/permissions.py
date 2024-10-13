from rest_framework.permissions import BasePermission
from .models import PageMaster, CustomUser  # Adjust based on your app structure


class IsAuthenticatedUser(BasePermission):
    """
    Allows access only to authenticated users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsPageMaster(BasePermission):
    """
    Allows access only to PageMaster users.
    """
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            # Check if the user is an instance of PageMaster
            return any(group.name == 'PageMaster' for group in request.user.groups.all()) or request.user.has_perm('server.add_post')
        return False


class IsCustomUser(BasePermission):
    """
    Allows access only to CustomUser users.
    """
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            # Deny access to users in the PageMaster group
            if any(group.name == 'PageMaster' for group in request.user.groups.all()):
                return False
            
            # Allow access if the user is an instance of CustomUser
            if isinstance(request.user, CustomUser):
                return any(group.name == 'CustomUser' for group in request.user.groups.all())
        
        return False