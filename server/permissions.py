from rest_framework.permissions import BasePermission
from .models import PageMaster, CustomUser  # Adjust the import based on your app structure


class IsPageMaster(BasePermission):
    """
    Allows access only to PageMaster users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and isinstance(request.user, PageMaster)

class IsCustomUser(BasePermission):
    """
    Allows access only to CustomUser users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and isinstance(request.user, CustomUser)
