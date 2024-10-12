from rest_framework.permissions import BasePermission
from .models import PageMaster, CustomUser  # Adjust based on your app structure
from django.contrib.auth.models import Permission


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
        return request.user and request.user.is_authenticated and request.user.has_perm('server.add_post')


class IsCustomUser(BasePermission):
    """
    Allows access only to CustomUser users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and isinstance(request.user, CustomUser)
